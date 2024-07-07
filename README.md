# Faster-readmdict

Use Cython to speed up `readmdict.py`

Original edition:
```
❯ time python -m readmdict ./concise-enhanced.mdx
======== b'./concise-enhanced.mdx' ========
  Number of Entries : 3402564
  GeneratedByEngineVersion : 2.0
  RequiredEngineVersion : 2.0
  Format : Html
  KeyCaseSensitive : No
  StripKey : Yes
  Encrypted : 2
  Description : <font size=5 color=red>简明英汉字典增强版：20170605<br>
(数据：http://github.com/skywind3000/ECDICT)<br>
 1. 开源英汉字典：MIT / CC 双协议<br>
 2. 标注牛津三千关键词：音标后 K字符<br>
 3. 柯林斯星级词汇标注：音标后 1-5的数字<br>
 4. 标注 COCA/BNC 的词频顺序<br>
 5. 标注考试大纲信息：中高研四六托雅 等<br>
</font>
  Title : 简明英汉字典增强版 - CSS
  Encoding : UTF-8
  CreationDate : 2017-6-4
  Compact : No
  Compat : No
  Left2Right : Yes
  DataSourceFormat : 107
  StyleSheet :
python -m readmdict ./concise-enhanced.mdx  4.99s user 0.28s system 99% cpu 5.275 total
```

Ours:
```
❯ time python ./readmdict/__main__.py ../ecdict-mdx-style-28/concise-enhanced.mdx
======== b'../ecdict-mdx-style-28/concise-enhanced.mdx' ========
  Number of Entries : 3402564
  GeneratedByEngineVersion : 2.0
  RequiredEngineVersion : 2.0
  Format : Html
  KeyCaseSensitive : No
  StripKey : Yes
  Encrypted : 2
  Description : <font size=5 color=red>简明英汉字典增强版：20170605<br>
(数据：http://github.com/skywind3000/ECDICT)<br>
 1. 开源英汉字典：MIT / CC 双协议<br>
 2. 标注牛津三千关键词：音标后 K字符<br>
 3. 柯林斯星级词汇标注：音标后 1-5的数字<br>
 4. 标注 COCA/BNC 的词频顺序<br>
 5. 标注考试大纲信息：中高研四六托雅 等<br>
</font>
  Title : 简明英汉字典增强版 - CSS
  Encoding : UTF-8
  CreationDate : 2017-6-4
  Compact : No
  Compat : No
  Left2Right : Yes
  DataSourceFormat : 107
  StyleSheet :
python ./readmdict/__main__.py ../ecdict-mdx-style-28/concise-enhanced.mdx  3.32s user 0.29s system 99% cpu 3.608 total
```