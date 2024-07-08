"""Repack readmdict."""
#!/usr/bin/env python
# -*- coding: utf-8 -*-
# readmdict.py
# Octopus MDict Dictionary File (.mdx) and Resource File (.mdd) Analyser
#
# Copyright (C) 2012, 2013, 2015 Xiaoqiang Wang <xiaoqiangwang AT gmail DOT com>
#
# This program is a free software; you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, version 3 of the License.
#
# You can get a copy of GNU General Public License along this program
# But you can always get it from http://www.gnu.org/licenses/gpl.txt
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE. See the
# GNU General Public License for more details.

from struct import pack, unpack
from io import BytesIO
import re
import sys

from .ripemd128 import ripemd128
from .pureSalsa20 import Salsa20

# zlib compression is used for engine version >=2.0
import zlib
# LZO compression is used for engine version < 2.0
try:
    import lzo
except ImportError:
    lzo = None
    print("LZO compression support is not available")

# 2x3 compatible
if sys.hexversion >= 0x03000000:
    unicode = str

# Cython
from .CY_MDict.MDict import MDict

class MDD(MDict):
    """
    MDict resource file format (*.MDD) reader.

    >>> mdd = MDD('example.mdd')
    >>> len(mdd)
    208
    >>> for filename,content in mdd.items():
    ... print filename, content[:10]
    """

    def __init__(self, fname, passcode=None):
        MDict.__init__(self, fname, encoding='UTF-16', passcode=passcode)

    def items(self):
        """Return a generator which in turn produce tuples in the form of (filename, content)."""
        return self._decode_record_block()

    def _decode_record_block(self):
        f = open(self._fname, 'rb')
        f.seek(self._record_block_offset)

        num_record_blocks = self._read_number(f)
        num_entries = self._read_number(f)
        assert(num_entries == self._num_entries)
        record_block_info_size = self._read_number(f)
        record_block_size = self._read_number(f)

        # record block info section
        record_block_info_list = []
        size_counter = 0
        for i in range(num_record_blocks):
            compressed_size = self._read_number(f)
            decompressed_size = self._read_number(f)
            record_block_info_list += [(compressed_size, decompressed_size)]
            size_counter += self._number_width * 2
        assert(size_counter == record_block_info_size)

        # actual record block
        offset = 0
        i = 0
        size_counter = 0
        for compressed_size, decompressed_size in record_block_info_list:
            record_block_compressed = f.read(compressed_size)
            # 4 bytes: compression type
            record_block_type = record_block_compressed[:4]
            # 4 bytes: adler32 checksum of decompressed record block
            adler32 = unpack('>I', record_block_compressed[4:8])[0]
            if record_block_type == b'\x00\x00\x00\x00':
                record_block = record_block_compressed[8:]
            elif record_block_type == b'\x01\x00\x00\x00':
                if lzo is None:
                    print("LZO compression is not supported")
                    break
                # decompress
                header = b'\xf0' + pack('>I', decompressed_size)
                record_block = lzo.decompress(header + record_block_compressed[8:])
            elif record_block_type == b'\x02\x00\x00\x00':
                # decompress
                record_block = zlib.decompress(record_block_compressed[8:])

            # notice that adler32 return signed value
            assert(adler32 == zlib.adler32(record_block) & 0xffffffff)

            assert(len(record_block) == decompressed_size)
            # split record block according to the offset info from key block
            while i < len(self._key_list):
                record_start, key_text = self._key_list[i]
                # reach the end of current record block
                if record_start - offset >= len(record_block):
                    break
                # record end index
                if i < len(self._key_list)-1:
                    record_end = self._key_list[i+1][0]
                else:
                    record_end = len(record_block) + offset
                i += 1
                data = record_block[record_start-offset:record_end-offset]
                yield key_text, data
            offset += len(record_block)
            size_counter += compressed_size
        assert(size_counter == record_block_size)

        f.close()


class MDX(MDict):
    """
    Return MDict dictionary file format (*.MDD) reader.

    >>> mdx = MDX('example.mdx')
    >>> len(mdx)
    42481
    >>> for key,value in mdx.items():
    ... print key, value[:10]
    """

    def __init__(self, fname, encoding='', substyle=False, passcode=None):
        MDict.__init__(self, fname, encoding, passcode)
        self._substyle = substyle

    def items(self):
        """Return a generator which in turn produce tuples in the form of (key, value)."""
        return self._decode_record_block()

    def _substitute_stylesheet(self, txt):
        # substitute stylesheet definition
        txt_list = re.split('`\d+`', txt)
        txt_tag = re.findall('`\d+`', txt)
        txt_styled = txt_list[0]
        for j, p in enumerate(txt_list[1:]):
            style = self._stylesheet[txt_tag[j][1:-1]]
            if p and p[-1] == '\n':
                txt_styled = txt_styled + style[0] + p.rstrip() + style[1] + '\r\n'
            else:
                txt_styled = txt_styled + style[0] + p + style[1]
        return txt_styled

    def _decode_record_block(self):
        f = open(self._fname, 'rb')
        f.seek(self._record_block_offset)

        num_record_blocks = self._read_number(f)
        num_entries = self._read_number(f)
        assert(num_entries == self._num_entries)
        record_block_info_size = self._read_number(f)
        record_block_size = self._read_number(f)

        # record block info section
        record_block_info_list = []
        size_counter = 0
        for i in range(num_record_blocks):
            compressed_size = self._read_number(f)
            decompressed_size = self._read_number(f)
            record_block_info_list += [(compressed_size, decompressed_size)]
            size_counter += self._number_width * 2
        assert(size_counter == record_block_info_size)

        # actual record block data
        offset = 0
        i = 0
        size_counter = 0
        for compressed_size, decompressed_size in record_block_info_list:
            record_block_compressed = f.read(compressed_size)
            # 4 bytes indicates block compression type
            record_block_type = record_block_compressed[:4]
            # 4 bytes adler checksum of uncompressed content
            adler32 = unpack('>I', record_block_compressed[4:8])[0]
            # no compression
            if record_block_type == b'\x00\x00\x00\x00':
                record_block = record_block_compressed[8:]
            # lzo compression
            elif record_block_type == b'\x01\x00\x00\x00':
                if lzo is None:
                    print("LZO compression is not supported")
                    break
                # decompress
                header = b'\xf0' + pack('>I', decompressed_size)
                record_block = lzo.decompress(header + record_block_compressed[8:])
            # zlib compression
            elif record_block_type == b'\x02\x00\x00\x00':
                # decompress
                record_block = zlib.decompress(record_block_compressed[8:])

            # notice that adler32 return signed value
            assert(adler32 == zlib.adler32(record_block) & 0xffffffff)

            assert(len(record_block) == decompressed_size)
            # split record block according to the offset info from key block
            while i < len(self._key_list):
                record_start, key_text = self._key_list[i]
                # reach the end of current record block
                if record_start - offset >= len(record_block):
                    break
                # record end index
                if i < len(self._key_list)-1:
                    record_end = self._key_list[i+1][0]
                else:
                    record_end = len(record_block) + offset
                i += 1
                record = record_block[record_start-offset:record_end-offset]
                # convert to utf-8
                record = record.decode(self._encoding, errors='ignore').strip(u'\x00').encode('utf-8')
                # substitute styles
                if self._substyle and self._stylesheet:
                    record = self._substitute_stylesheet(record)

                yield key_text, record
            offset += len(record_block)
            size_counter += compressed_size
        assert(size_counter == record_block_size)

        f.close()

