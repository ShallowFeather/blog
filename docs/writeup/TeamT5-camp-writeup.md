---
title: TeamT5 camp writeup
date: 2024-01-21 23:08:19
tags: TeamT5 Reverse Kernel
---
## 類別三：遊戲外掛實作
### 基礎題 (40% ~ 50%)
#### 控制炸彈數
通過 Cheat Engine 去搜尋初始值
一開始炸彈數量一定是 1 那吃了道具後會加 1 死掉則變回 1 由此慢慢測試
![image](https://hackmd.io/_uploads/B1Yk4ycVT.png)


#### 控制火力
通過 Cheat Engine 去搜尋初始值
一開始炸彈數量一定是 1 那吃了道具後會加 1 死掉則變回 1 由此慢慢測試
哈哈跟上面一樣
![image](https://hackmd.io/_uploads/HkQL4J9V6.png)

#### 控制走路速度
走路速度一開始搜尋 1 時沒有找到 之後用尋找遞增的方式去尋找
發現他初始值是 2 原本才找不到
![image](https://hackmd.io/_uploads/ByhHUkq4a.png)


#### 永久盾牌
盾牌的話 會有一個 0 或 1 決定是否啟動
並且如果他計時為 0 時也會取消掉
![image](https://hackmd.io/_uploads/r1ZOOJ5Va.png)

#### extra 昏迷
跟盾牌一樣的道理 我在她 struct 發現的 就想說加在這邊
![image](https://hackmd.io/_uploads/SJ4EK15NT.png)


### 進階題 (50% ~ 60%)
#### 倒數時間暫停
這個我覺得比下面穿牆的還難一點
原本想說用 Cheat Engine 找到時間的總和但是發現他好像是 call SDL 的 tick 來確認時間 (?
所以我就從 ghidra 那邊看有 call tick 的
![image](https://hackmd.io/_uploads/SJuFsk94p.png)
最後發現這邊
![image](https://hackmd.io/_uploads/S1zCjk9Ea.png)
把 sub 的指令全部改成 nop 也就是 0x90 後就能夠讓他時間取消計時了
#### 穿牆
先利用 Cheat Engine 把腳色的 x y 找出來
我就直接猜說 他會在更動 x y 時 去檢查是否有超出邊界
![image](https://hackmd.io/_uploads/Hkfd2kqVT.png)
最後發現把上面CrazyArcade.exe+38A4 位置的指令改成 nop 就不會檢查了

#### 用游標移動角色
下面兩個則不能直接用 Cheat engine 去用了 必須要 inject dll 才行
然後我原本想法是利用 SDL2 的函數去抓滑鼠的位置 然後再改 x y
但後面發現要 getmodule 之類的好麻煩 乾脆用 windows.h 的內建函數解決
![image](https://hackmd.io/_uploads/B1bxCkc4T.png)
減掉 rect.left 跟 rect.top 是因為他不是全螢幕 所以視窗會跟著它移動
-40 是為了讓他更接近滑鼠 不然 windows.h 是由視窗左上角去做定位的
#### 用滑鼠左鍵放炸彈
這個部份我逆向比較久
基本把所有邏輯都拆光了吧 (?
原本想說 他一定是對應某個案件然後去call 放炸彈
所以把call的案件code修改就能成功了
沒想到她還有其他檢查就很頭痛 而且我也不知道滑鼠對應的數字 還要找就很麻煩
![image](https://hackmd.io/_uploads/Hyi7JgcNT.png)
所以最後就只能通過注入 然後去呼叫它裡面寫好的 function
param_2 就是他的遊戲腳色 struct
所以要做的只有 攔截滑鼠按鍵 + 呼叫 function
![image](https://hackmd.io/_uploads/B1WnklcNa.png)
然後 在 dll 中 我是去開兩個 thread 來處理所有操作


### Kernel 題 (10% ~ 20%)

題外話，都用 RTcore 這個 driver ㄟ 害我原本工具加載上去發現沒辦法在開啟遊戲 原來是這個在搞
建議使用 Windows 1909 就是為了能打這個 driver 對ㄅ
#### 破解遊戲保護
ObRegisterCallbacks 上網查一下發現是註冊某個 process 到註冊表中，並讓其他東西存取他時會讀取不到
那搜尋時我也發現有 ObUnRegisterCallbacks 這個 function 也就是用來將他從註冊表中移除
因此如果要破解遊戲保護的話 就只要找到 ObUnRegisterCallbacks 這個函數的相關參數就可以了
反正就是 他加入註冊表後會加入他的 linklist 也就是說 我從中抓取一個 並且遍歷他找到應該要解除了 或是直接把全部 linklist 上的都去 call ObUnRegisterCallbacks 不就解決了嗎
如果遍歷找他的話應該可以用她的 Altitude 的值去找
![image](https://hackmd.io/_uploads/HkqIMg9E6.png)
