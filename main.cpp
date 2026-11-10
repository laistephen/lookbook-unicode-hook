#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <vector>

// 定義原始 API 函數指標
typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef INT(WINAPI* FnMultiByteToWideChar)(UINT, DWORD, LPCSTR, int, LPWSTR, int);
typedef INT(WINAPI* FnWideCharToMultiByte)(UINT, DWORD, LPCWSTR, int, LPSTR, int, LPCSTR, LPBOOL);

FnCreateFileA fpCreateFileA = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;
FnMultiByteToWideChar fpMultiByteToWideChar = NULL;
FnWideCharToMultiByte fpWideCharToMultiByte = NULL;

// 攔截 MultiByteToWideChar：當 Lookbook 內部轉碼時，即時攔截並修正缺字或方塊 □
INT WINAPI HookedMultiByteToWideChar(
    UINT CodePage, DWORD dwFlags, LPCSTR lpMultiByteStr, int cbMultiByte, LPWSTR lpWideCharStr, int cchWideChar) 
{
    int ret = fpMultiByteToWideChar(CodePage, dwFlags, lpMultiByteStr, cbMultiByte, lpWideCharStr, cchWideChar);
    
    // 如果成功轉換出寬字元，對內容進行動態掃描與修正
    if (ret > 0 && lpWideCharStr != NULL && cchWideChar > 0) {
        int count = (cchWideChar < ret) ? cchWideChar : ret;
        for (int i = 0; i < count; ++i) {
            // 範例：將「犟」字代碼 (0x729F) 或因缺字產生的不支援代碼進行即時對應修正
            if (lpWideCharStr[i] == 0x729F) {
                lpWideCharStr[i] = 0x5F3A; // 自動替換為繁體中文可顯示的「強」
            }
            // 也可以針對寬字元為 0x25A1 (即方塊 □) 的狀況進行額外條件捕捉與修復
        }
    }
    return ret;
}

// 攔截 WideCharToMultiByte
INT WINAPI HookedWideCharToMultiByte(
    UINT CodePage, DWORD dwFlags, LPCWSTR lpWideCharStr, int cchWideChar, LPSTR lpMultiByteStr, int cbMultiByte, LPCSTR lpDefaultChar, LPBOOL lpUsedDefaultChar) 
{
    return fpWideCharToMultiByte(CodePage, dwFlags, lpWideCharStr, cchWideChar, lpMultiByteStr, cbMultiByte, lpDefaultChar, lpUsedDefaultChar);
}

// 基礎檔案讀寫攔截
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    return fpCreateFileA ? fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile) : INVALID_HANDLE_VALUE;
}

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    return fpReadFile ? fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) : FALSE;
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    return fpWriteFile ? fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) : FALSE;
}

// DLL 入口點
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() == MH_OK) {
            MH_CreateHook(&CreateFileA, &HookedCreateFileA, reinterpret_cast<LPVOID*>(&fpCreateFileA));
            MH_CreateHook(&ReadFile, &HookedReadFile, reinterpret_cast<LPVOID*>(&fpReadFile));
            MH_CreateHook(&WriteFile, &HookedWriteFile, reinterpret_cast<LPVOID*>(&fpWriteFile));

            // 直接掛載攔截 kernel32 的 MultiByteToWideChar，從根本解決內建轉碼缺字問題
            HMODULE hKernel32 = GetModuleHandleA("kernel32.dll");
            if (hKernel32) {
                LPVOID pMultiByteToWideChar = (LPVOID)GetProcAddress(hKernel32, "MultiByteToWideChar");
                LPVOID pWideCharToMultiByte = (LPVOID)GetProcAddress(hKernel32, "WideCharToMultiByte");
                if (pMultiByteToWideChar) MH_CreateHook(pMultiByteToWideChar, &HookedMultiByteToWideChar, reinterpret_cast<LPVOID*>(&fpMultiByteToWideChar));
                if (pWideCharToMultiByte) MH_CreateHook(pWideCharToMultiByte, &HookedWideCharToMultiByte, reinterpret_cast<LPVOID*>(&fpWideCharToMultiByte));
            }

            MH_EnableHook(MH_ALL_HOOKS);
        }
        break;
    case DLL_PROCESS_DETACH:
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
