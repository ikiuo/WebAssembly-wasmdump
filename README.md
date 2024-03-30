# .wasm ファイル内容の詳細出力

[WebAssemblyのバイナリ形式(.wasmファイル)](https://webassembly.github.io/spec/core/binary/)の詳細を出力します。

[MDNにて説明されているテキスト形式の例](https://developer.mozilla.org/ja/docs/WebAssembly/Text_format_to_Wasm)から作った simple.wasm では以下のようになります。

```
$ python3 wasmdump.py simple.wasm
------------------------------------------------------------------------------
Path: simple.wasm
------------------------------------------------------------------------------
00: 00 61 73 6d             | magic = b'\x00asm'
04: 01 00 00 00             | version = 1
------------------------------------------------------------------------------
08: 01                      | Type Section (id=1)
09: 08                      | section size = 8
0a: 02                      | functype count = 2
                            | typeidx[0]
0b: 60                      |   functype
0c: 01                      |   param[1]
0d: 7f                      |     i32
0e: 00                      |   result[0]
                            | typeidx[1]
0f: 60                      |   functype
10: 00                      |   param[0]
11: 00                      |   result[0]
------------------------------------------------------------------------------
12: 02                      | Import Section (id=2)
13: 19                      | section size = 25
14: 01                      | import count = 1
                            | import[0]
15: 07 69 6d 70 6f 72 74 73 |   module = "imports"
1d: 0d 69 6d 70 6f 72 74 65 |   name = "imported_func"
25: 64 5f 66 75 6e 63       |
2b: 00                      |   func
2c: 00                      |     typeidx = 0
------------------------------------------------------------------------------
2d: 03                      | Function Section (id=3)
2e: 02                      | section size = 2
2f: 01                      | typeidx count = 1
30: 01                      |   typeidx[0] = 1
------------------------------------------------------------------------------
31: 07                      | Export Section (id=7)
32: 11                      | section size = 17
33: 01                      | export count = 1
                            | export[0]
34: 0d 65 78 70 6f 72 74 65 |   name = "exported_func"
3c: 64 5f 66 75 6e 63       |
42: 00                      |   func
43: 01                      |     funcidx = 1
------------------------------------------------------------------------------
44: 0a                      | Code Section (id=10)
45: 08                      | section size = 8
46: 01                      | code count = 1
                            | code[0]
47: 06                      |   code size = 6
48: 00                      |   local size = 0
49: 41                      |   i32.const
4a: 2a                      |     --> 42
4b: 10                      |   call
4c: 00                      |     --> 0
4d: 0b                      |   end
```
