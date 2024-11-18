---
title: TeamT5 釣魚遊戲 WriteUp
date: 2024-01-21 23:06:02
tags: TeamT5 Reverse Kernel
---
## Part 1

首先程式開啟後可以發現 Cheat Engine 是沒有辦法去讀取他的，連 OpenProcess 都不行。
我第一個想法是直接打 dbk.sys 就能夠直接做驅動讀寫了。而事實也是直接就可以讀了。

![](https://cdn.discordapp.com/attachments/464447402557046784/1144246294924230726/image.png)

不過我找了一段時間都沒辦法從記憶體找到 Flag 的痕跡，甚麼 Flag Magic 之類的都沒找到 我懷疑網頁在誤導(X

而後面在逆向 anti_cheat.dll 時就發現了
![](https://hackmd.io/_uploads/HyF63aV62.png)

而在 DB20 的位置有一個函數就是在對這個 Flag 去做操作
它的操作看起來像是 利用 GetModuleHandleW 獲取某個 hModule 結構
當中會利用兩個當中的參數 第一個參數會影響他是否輸出 Flag 而第二個參數不會 只有用在生成 Flag 得時候 但最後我都沒有搞懂第二個參數在幹嘛##

然後他對第一個操作基本上是
取值 然後對他進行 ltoa 轉成字串
然後再把他丟進
```cpp
int sub_10010C00(char *a1)

{

  int v2; // [esp+D4h] [ebp-14h]

  int i; // [esp+E0h] [ebp-8h]

  for ( i = 5381; ; i = v2 + 33 * i )

  {

    v2 = *a1++;

    if ( !v2 )

      break;

  }

  return i;

}
```
這樣的一個函數中去做處理 最後跟 1174378711 去做 compare
不過當初我卡了型別的問題 加上應該可以用 z3 解 但我寫爛了 總之就直接爆搜了 具體的 code 如下
```cpp
#include <bits/stdc++.h>

using namespace std;

int sub_10010C00(char *a1)
{
    int v2; // [esp+D4h] [ebp-14h]
    int i; // [esp+E0h] [ebp-8h]
    for ( i = 5381; ; i = v2 + 33 * i )
    {
        v2 = *a1++;
        if ( !v2 )
            break;
    }
    return i;
}

signed main() {
    long i = 1;
    char src[sizeof(long)*8+1];
    while(i++) {
        memset(src, 0, 10);
        ltoa(i, src, 10);
        printf ("%s\n",src);
        int v4 = sub_10010C00(src);
        if(v4 == 1174378711) {
            cout << '\n';
            cout << i << '\n';
            cout << v4 << '\n';
            break;
        }
    }
}
```
最後會輸出 1836925 這個值
因此如果要他彈出 Flag 就要修改他的第一個參數為 1836925 這個數字
而在使用 Cheat Engine 時，因為他有記憶體保護 所以最一開始我是使用 DBVM 來進行 Debug

我最一開始先透過搜尋字串 找 encrypt_flag 的特徵 就是最一開始其實是 `[g8`
這樣的一個字串
因為他是一個 while 迴圈會一直去做 Check 所以那個字串一定可以被搜尋到
並且透過 find access 找到 DB20 該函數位置

![](https://hackmd.io/_uploads/B1rRnTVa2.png)

然後去下斷點並且修改 register 的值
![](https://hackmd.io/_uploads/Hk6R2aNan.png)
按下 Run 以後 Flag 就彈出來了
![](https://hackmd.io/_uploads/BkGyTTVTh.png)

### Bonus
不過 之後我也知道了記憶體保護原來是叫做 PPL 
因此我在 Github 上找到了一個可以利用的專案就是
[itm4n/PPLcontrol: Controlling Windows PP(L)s (github.com)](https://github.com/itm4n/PPLcontrol)
利用這個就可以不用去利用 DBVM 了

## Part 2

Part 2 我原本不知道要怎麼修改 Driver 的 asm 因此解這題也算是學會一個新東西吧 xD
我原本的想法比較複雜 就是利用
[9176324/Shark: Turn off PatchGuard in real time for win7 (7600) ~ later (github.com)](https://github.com/9176324/Shark)
然後去做 SSDT Hook 修改掉 PsSetCreateProcessNotifyRoutine 
不過後面發現只要找出 Driver 的 base address 然後寫 driver 去修改即可
我修改的地方就是在他利用 PsSetCreateProcessNotifyRoutine 會調用的 Function 
讓他最一開始的指令是 0x3C 也就是 ret 這樣就不會執行執行到他檢查關閉的 Pid 是否為 Catfishing.exe 的了
基本上就這樣
還有就是有打了一個過期簽章把 Driver 弄上去 不然就要關閉 DSE
詳細 Code 如下 (為甚麼明明研究比較久卻 WP 寫比較短
```c
#include <ntifs.h>
#include <ntddk.h>

NTKERNELAPI
NTSTATUS
MmCopyVirtualMemory(
    _In_ PEPROCESS srcProcess,
    _In_ PVOID srcAddr,
    _In_ PEPROCESS dstProcess,
    _In_ PVOID dstAddr,
    _In_ SIZE_T DataSize,
    _In_    KPROCESSOR_MODE PreviousMode,
    _Out_    PSIZE_T RetureSize
);

NTSTATUS kReadProcessMemory(PEPROCESS Process, PVOID lpBaseAddress, PVOID lpBuffer, size_t nSize)
{
    PSIZE_T rSize;
    return MmCopyVirtualMemory(Process, lpBaseAddress, PsGetCurrentProcess(), lpBuffer, nSize, KernelMode, &rSize);
}


NTSTATUS kWriteProcessMemory(PEPROCESS Process, PVOID lpBaseAddress, PVOID lpBuffer, size_t nSize)
{
    PSIZE_T rSize;
    return MmCopyVirtualMemory(PsGetCurrentProcess(), lpBuffer, Process, lpBaseAddress, nSize, KernelMode, &rSize);
}

NTSTATUS DriverUnload(PDRIVER_OBJECT pDriverObject)
{
    return STATUS_SUCCESS;
}

NTSTATUS DriverEntry(PDRIVER_OBJECT pDriverObject, PUNICODE_STRING pRegister)
{
    pDriverObject->DriverUnload = DriverUnload;

    PEPROCESS Process;
    size_t pid = 4;
    PsLookupProcessByProcessId((HANDLE)pid, &Process);
    PVOID addr = 0xFFFFF80542501C60; // 這邊應該可以自動化找的 但是最近沒什麼時間弄這ㄍ

    int newValue = 195;
    kWriteProcessMemory(Process, addr, &newValue, sizeof(int));

    int readValue = 0;
    kReadProcessMemory(Process, addr, &readValue, sizeof(int));

    DbgPrintEx(0, 0, "change value: %d\n", readValue);
    return  STATUS_SUCCESS;
}

```



