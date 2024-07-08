# cython:boundscheck=False
cimport cython
import zlib
import sys
import lzo
from struct import pack, unpack
import re
from io import BytesIO

from ..ripemd128 import ripemd128
from ..pureSalsa20 import Salsa20

def _fast_decrypt(data, key):
    b = bytearray(data)
    key = bytearray(key)
    previous = 0x36
    for i in range(len(b)):
        t = (b[i] >> 4 | b[i] << 4) & 0xff
        t = t ^ previous ^ (i & 0xff) ^ key[i % len(key)]
        previous = b[i]
        b[i] = t
    return bytes(b)

def _unescape_entities(text):
    """Unescape offending tags < > " &."""
    text = text.replace(b'&lt;', b'<')
    text = text.replace(b'&gt;', b'>')
    text = text.replace(b'&quot;', b'"')
    text = text.replace(b'&amp;', b'&')
    return text

def _mdx_decrypt(comp_block):
    key = ripemd128(comp_block[4:8] + pack(b'<L', 0x3695))
    return comp_block[0:8] + _fast_decrypt(comp_block[8:], key)

def _salsa_decrypt(ciphertext, encrypt_key):
    s20 = Salsa20(key=encrypt_key, IV=b"\x00"*8, rounds=8)
    return s20.encryptBytes(ciphertext)


def _decrypt_regcode_by_deviceid(reg_code, deviceid):
    deviceid_digest = ripemd128(deviceid)
    s20 = Salsa20(key=deviceid_digest, IV=b"\x00"*8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key


def _decrypt_regcode_by_email(reg_code, email):
    email_digest = ripemd128(email.decode().encode('utf-16-le'))
    s20 = Salsa20(key=email_digest, IV=b"\x00"*8, rounds=8)
    encrypt_key = s20.encryptBytes(reg_code)
    return encrypt_key

cdef class MDict(object):
    """
    Base class which reads in header and key block.

    It has no public methods and serves only as code sharing base class.
    """
    cdef size_t _number_width
    cdef str _encoding
    def __init__(self, fname, encoding='', passcode=None):
        """Init."""
        self._fname = fname
        self._encoding = encoding.upper()
        self._passcode = passcode

        self.header = self._read_header()
        try:
            self._key_list = self._read_keys()
        except Exception:
            print("Try Brutal Force on Encrypted Key Blocks")
            self._key_list = self._read_keys_brutal()

    def __len__(self):
        return self._num_entries

    def __iter__(self):
        return self.keys()

    def keys(self):
        """Return an iterator over dictionary keys."""
        return (key_value for key_id, key_value in self._key_list)

    def _read_number(self, f):
        return unpack(self._number_format, f.read(self._number_width))[0]

    def _parse_header(self, header):
        """Extract attributes from <Dict attr="value" ... >."""
        taglist = re.findall(b'(\w+)="(.*?)"', header, re.DOTALL)
        tagdict = {}
        for key, value in taglist:
            tagdict[key] = _unescape_entities(value)
        return tagdict

    def _decode_key_block_info(self, key_block_info_compressed):
        if self._version >= 2:
            # zlib compression
            assert(key_block_info_compressed[:4] == b'\x02\x00\x00\x00')
            # decrypt if needed
            if self._encrypt & 0x02:
                key_block_info_compressed = _mdx_decrypt(key_block_info_compressed)
            # decompress
            key_block_info = zlib.decompress(key_block_info_compressed[8:])
            # adler checksum
            adler32 = unpack('>I', key_block_info_compressed[4:8])[0]
            assert(adler32 == zlib.adler32(key_block_info) & 0xffffffff)
        else:
            # no compression
            key_block_info = key_block_info_compressed
        # decode
        key_block_info_list = []
        num_entries = 0
        i = 0
        if self._version >= 2:
            byte_format = '>H'
            byte_width = 2
            text_term = 1
        else:
            byte_format = '>B'
            byte_width = 1
            text_term = 0

        while i < len(key_block_info):
            # number of entries in current key block
            num_entries += unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            # text head size
            text_head_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            # text head
            if self._encoding != 'UTF-16':
                i += text_head_size + text_term
            else:
                i += (text_head_size + text_term) * 2
            # text tail size
            text_tail_size = unpack(byte_format, key_block_info[i:i+byte_width])[0]
            i += byte_width
            # text tail
            if self._encoding != 'UTF-16':
                i += text_tail_size + text_term
            else:
                i += (text_tail_size + text_term) * 2
            # key block compressed size
            key_block_compressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            # key block decompressed size
            key_block_decompressed_size = unpack(self._number_format, key_block_info[i:i+self._number_width])[0]
            i += self._number_width
            key_block_info_list += [(key_block_compressed_size, key_block_decompressed_size)]

        #assert(num_entries == self._num_entries)

        return key_block_info_list

    cdef list _decode_key_block(self, bytes key_block_compressed, list[int] key_block_info_list):
        cdef int i = 0
        cdef list key_list = []
        cdef size_t start, end
        cdef size_t compressed_size, decompressed_size
        cdef bytes key_block_type
        cdef bytes key_block
        cdef bytes header
        cdef size_t header_len

        for compressed_size, decompressed_size in key_block_info_list:
            start = i
            end = i + compressed_size
            # 4 bytes : compression type
            key_block_type = key_block_compressed[start:start+4]
            # 4 bytes : adler checksum of decompressed key block
            # adler32 = unpack('>I', key_block_compressed[start+4:start+8])[0]
            if key_block_type == b'\x00\x00\x00\x00':
                key_block = key_block_compressed[start+8:end]
            elif key_block_type == b'\x01\x00\x00\x00':
                # decompress key block
                header = b'\xf0' + pack('>I', decompressed_size)
                key_block = lzo.decompress(header + key_block_compressed[start+8:end])
            elif key_block_type == b'\x02\x00\x00\x00':
                # decompress key block
                key_block = zlib.decompress(key_block_compressed[start+8:end])
            # extract one single key block into a key list
            key_list += self._split_key_block(key_block)
            # notice that adler32 returns signed value
            # assert(adler32 == zlib.adler32(key_block) & 0xffffffff)

            i += compressed_size
        return key_list


    cdef list _split_key_block(self, bytes key_block):
        cdef list[tuple[size_t, bytes]] key_list = []
        cdef size_t key_start_index = 0, width, i, key_id, key_end_index, key_block_len = len(key_block)
        cdef bytes key_text, delimiter
        # key text ends with '\x00'
        if self._encoding == 'UTF-16':
            delimiter = b'\x00\x00'
            width = 2
        else:
            delimiter = b'\x00'
            width = 1
        while key_start_index < key_block_len:
            # the corresponding record's offset in record block
            key_id = unpack(self._number_format, key_block[key_start_index:key_start_index+self._number_width])[0]

            i = key_start_index + self._number_width
            while i < key_block_len:
                if key_block[i:i+width] == delimiter:
                    key_end_index = i
                    break
                i += width

            key_text = key_block[key_start_index+self._number_width:key_end_index]\
                .decode(self._encoding, errors='ignore').encode('utf-8').strip()
            key_start_index = key_end_index + width
            key_list += [(key_id, key_text)]
        return key_list

    def _read_header(self):
        f = open(self._fname, 'rb')
        # number of bytes of header text
        header_bytes_size = unpack('>I', f.read(4))[0]
        header_bytes = f.read(header_bytes_size)
        # 4 bytes: adler32 checksum of header, in little endian
        adler32 = unpack('<I', f.read(4))[0]
        assert(adler32 == zlib.adler32(header_bytes) & 0xffffffff)
        # mark down key block offset
        self._key_block_offset = f.tell()
        f.close()

        # header text in utf-16 encoding ending with '\x00\x00'
        header_text = header_bytes[:-2].decode('utf-16').encode('utf-8')
        header_tag = self._parse_header(header_text)
        if not self._encoding:
            encoding = header_tag[b'Encoding']
            if sys.hexversion >= 0x03000000:
                encoding = encoding.decode('utf-8')
            # GB18030 > GBK > GB2312
            if encoding in ['GBK', 'GB2312']:
                encoding = 'GB18030'
            self._encoding = encoding
        # encryption flag
        #   0x00 - no encryption
        #   0x01 - encrypt record block
        #   0x02 - encrypt key info block
        if b'Encrypted' not in header_tag or header_tag[b'Encrypted'] == b'No':
            self._encrypt = 0
        elif header_tag[b'Encrypted'] == b'Yes':
            self._encrypt = 1
        else:
            self._encrypt = int(header_tag[b'Encrypted'])

        # stylesheet attribute if present takes form of:
        #   style_number # 1-255
        #   style_begin  # or ''
        #   style_end    # or ''
        # store stylesheet in dict in the form of
        # {'number' : ('style_begin', 'style_end')}
        self._stylesheet = {}
        if header_tag.get('StyleSheet'):
            lines = header_tag['StyleSheet'].splitlines()
            for i in range(0, len(lines), 3):
                self._stylesheet[lines[i]] = (lines[i+1], lines[i+2])

        # before version 2.0, number is 4 bytes integer
        # version 2.0 and above uses 8 bytes
        self._version = float(header_tag[b'GeneratedByEngineVersion'])
        if self._version < 2.0:
            self._number_width = 4
            self._number_format = '>I'
        else:
            self._number_width = 8
            self._number_format = '>Q'

        return header_tag

    def _read_keys(self):
        f = open(self._fname, 'rb')
        f.seek(self._key_block_offset)

        # the following numbers could be encrypted
        if self._version >= 2.0:
            num_bytes = 8 * 5
        else:
            num_bytes = 4 * 4
        block = f.read(num_bytes)

        if self._encrypt & 1:
            if self._passcode is None:
                raise RuntimeError('user identification is needed to read encrypted file')
            regcode, userid = self._passcode
            if isinstance(userid, unicode):
                userid = userid.encode('utf8')
            if self.header[b'RegisterBy'] == b'EMail':
                encrypted_key = _decrypt_regcode_by_email(regcode, userid)
            else:
                encrypted_key = _decrypt_regcode_by_deviceid(regcode, userid)
            block = _salsa_decrypt(block, encrypted_key)

        # decode this block
        sf = BytesIO(block)
        # number of key blocks
        num_key_blocks = self._read_number(sf)
        # number of entries
        self._num_entries = self._read_number(sf)
        # number of bytes of key block info after decompression
        if self._version >= 2.0:
            key_block_info_decomp_size = self._read_number(sf)
        # number of bytes of key block info
        key_block_info_size = self._read_number(sf)
        # number of bytes of key block
        key_block_size = self._read_number(sf)

        # 4 bytes: adler checksum of previous 5 numbers
        if self._version >= 2.0:
            adler32 = unpack('>I', f.read(4))[0]
            assert adler32 == (zlib.adler32(block) & 0xffffffff)

        # read key block info, which indicates key block's compressed and decompressed size
        key_block_info = f.read(key_block_info_size)
        key_block_info_list = self._decode_key_block_info(key_block_info)
        assert(num_key_blocks == len(key_block_info_list))

        # read key block
        key_block_compressed = f.read(key_block_size)
        # extract key block
        key_list = self._decode_key_block(key_block_compressed, key_block_info_list)

        self._record_block_offset = f.tell()
        f.close()

        return key_list

    def _read_keys_brutal(self):
        f = open(self._fname, 'rb')
        f.seek(self._key_block_offset)

        # the following numbers could be encrypted, disregard them!
        if self._version >= 2.0:
            num_bytes = 8 * 5 + 4
            key_block_type = b'\x02\x00\x00\x00'
        else:
            num_bytes = 4 * 4
            key_block_type = b'\x01\x00\x00\x00'
        block = f.read(num_bytes)

        # key block info
        # 4 bytes '\x02\x00\x00\x00'
        # 4 bytes adler32 checksum
        # unknown number of bytes follows until '\x02\x00\x00\x00' which marks the beginning of key block
        key_block_info = f.read(8)
        if self._version >= 2.0:
            assert key_block_info[:4] == b'\x02\x00\x00\x00'
        while True:
            fpos = f.tell()
            t = f.read(1024)
            index = t.find(key_block_type)
            if index != -1:
                key_block_info += t[:index]
                f.seek(fpos + index)
                break
            else:
                key_block_info += t

        key_block_info_list = self._decode_key_block_info(key_block_info)
        key_block_size = sum(list(zip(*key_block_info_list))[0])

        # read key block
        key_block_compressed = f.read(key_block_size)
        # extract key block
        key_list = self._decode_key_block(key_block_compressed, key_block_info_list)

        self._record_block_offset = f.tell()
        f.close()

        self._num_entries = len(key_list)
        return key_list