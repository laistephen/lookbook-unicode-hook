#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <vector>

// 定義原始 API 函數指標
typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnTextOutA)(HDC, int, int, LPCSTR, int);
typedef BOOL(WINAPI* FnExtTextOutA)(HDC, int, int, UINT, CONST RECT*, LPCSTR, UINT, CONST INT*);

FnCreateFileA fpCreateFileA = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;
FnTextOutA fpTextOutA = NULL;
FnExtTextOutA fpExtTextOutA = NULL;

// 畫面繪製字元修正函數
std::string FixRenderText(LPCSTR lpString, int cchString) {
    if (!lpString || cchString <= 0) return "";
    std::string text(lpString, cchString);
    return text;
}

// 1. 攔截 TextOutA
BOOL WINAPI HookedTextOutA(HDC hdc, int nXStart, int nYStart, LPCSTR lpString, int cchString) {
    std::string fixed = FixRenderText(lpString, cchString);
    if (fpTextOutA) {
        return fpTextOutA(hdc, nXStart, nYStart, fixed.c_str(), (int)fixed.length());
    }
    return FALSE;
}

// 2. 攔截 ExtTextOutA
BOOL WINAPI HookedExtTextOutA(HDC hdc, int nX, int nY, UINT uOptions, CONST RECT* lprc, LPCSTR lpString, UINT cbCount, CONST INT* lpDx) {
    std::string fixed = FixRenderText(lpString, cbCount);
    if (fpExtTextOutA) {
        return fpExtTextOutA(hdc, nX, nY, uOptions, lprc, fixed.c_str(), (UINT)fixed.length(), lpDx);
    }
    return FALSE;
}

// 3. 基礎檔案讀寫攔截
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

            // 動態載入 gdi32.dll 並安全掛載 TextOutA 與 ExtTextOutA
            HMODULE hGdi32 = LoadLibraryA("gdi32.dll");
            if (hGdi32) {
                LPVOID pTextOutA = (LPVOID)GetProcAddress(hGdi32, "TextOutA");
                LPVOID pExtTextOutA = (LPVOID)GetProcAddress(hGdi32, "ExtTextOutA");
                if (pTextOutA) MH_CreateHook(pTextOutA, &HookedTextOutA, reinterpret_cast<LPVOID*>(&fpTextOutA));
                if (pExtTextOutA) MH_CreateHook(pExtTextOutA, &HookedExtTextOutA, reinterpret_cast<LPVOID*>(&fpExtTextOutA));
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
