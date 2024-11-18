---
title: HITCON 2023 Qual Crazy Arcade
date: 2024-01-21 23:11:48
tags:
---

這次超久才寫 WriteUp
學校有點多東西要忙

今年的 Hitcon 只有解這題 另一題 Rust 交換沒看很懂
這題是跟漢堡一起解的。
把他分析差不多以後我跟他說要全部變幽靈才 call 的到那個 Function 結果他說不用就會 call 到
浪費好多時間==

## 解題流程
首先打開遊戲可以看到他會載入他同資料夾中的驅動
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153694603271209103/image.png)


然後看到下面接 IO 的這個名稱，有沒有很熟悉
這個是 Msi AfterBurner 之前出問題的驅動阿
漏洞主要是任意讀寫記憶體
並且對照後面的 DeviceIoControl 也能夠猜到它是使用了讀寫功能

然後後面我就先動態分析，想說只要通關說不定會有些東西
因為他說有幾層，我以為只要成功過就可以了
因此我是先開始分析它是怎麼生成拉桿的
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153696329290227762/image.png)


這個位置會生成拉桿 然後確定他是否在牆裡面
至於下面的 73 41 則是玩家的 XY 值
因此只要控制它的 rand 的輸出值跟玩家位置就可以通關了
不過 很顯然的 通關並不是它的目的

在 7990 的函數位置可以發現一個有趣的東西
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153697154158821446/image.png)

它是 Win 欸
代表說應該就是上面的 DAT_140016238 的變數操作會有可能涉及 Flag 了
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153697584657993748/image.png)


透過找對這個變數讀寫的位置後可以發現這個有趣的東西
這不就是對 RTcore64 進行操作的 IOCTL 嗎
那當初我發現這個函數時是先下斷點在要執行 IO 那邊
通關試試看 那很明顯一點用也沒有

反正總之，上面不是檢查是不是 5 嗎
漢堡就寫了一個 CE 腳本
直接開改
```
{ Game   : CrazyArcade.exe
  Version: 
  Date   : 2023-09-09
  Author : 123

  This script does blah blah blah
}

[ENABLE]

aobscanmodule(INJECT,CrazyArcade.exe,83 3C 90 05 0F 85 A4 01 00 00) // should be unique
alloc(newmem,$1000,INJECT)

label(code)
label(return)

newmem:

code:
  push 5
  pop dword ptr [rax+rdx*4]
  cmp dword ptr [rax+rdx*4],05
  jne CrazyArcade.exe+328E
  jmp return

INJECT:
  jmp newmem
  nop 5
return:
registersymbol(INJECT)

[DISABLE]

INJECT:
  db 83 3C 90 05 0F 85 A4 01 00 00

unregistersymbol(INJECT)
dealloc(newmem)
```
反正我也不知道怎麼生成的 難怪大家都說楓之谷是練功場

阿 在執行之前記得在那個 call IO 的裡面下斷點

然後在那邊找到一個很可疑的 Address 看起來像是某個 Driver 的區塊

FFFFF805426C3000 這個位置

然後接下來就是要處理它該怎麼讓它一直 call 檢查那塊了
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153706531452375112/image.png)

然後我鎖定了 71B6 那塊 還有後面的一個 JNZ 都改成 NOP
不就會一直呼叫了嗎

接下來就是漫長的等待 等到它跑 0x1337 次後 Flag 就會出現在 FFFFF805426C3000 這個位置上了
![image](https://cdn.discordapp.com/attachments/464447402557046784/1153707389699227749/image.png)