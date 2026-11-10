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

// 畫面繪製字元修正函數：將 Lookbook 內部產生的方塊 □ 動態還原為正確字元
std::string FixRenderText(LPCSTR lpString, int cchString) {
    if (!lpString || cchString <= 0) return "";
    std::string text(lpString, cchString);
    
    // 如果字串中包含 Lookbook 因查不到對應碼而產生的「□」，可在此進行對應修正
    // 範例：將特定的 □ 替換回原本的字元（例如「犟」，其 Big5/GB 顯示對應）
    size_t pos = 0;
    while ((pos = text.find("□", pos)) != std::string::npos) {
        // 如果你知道該位置原本是哪個字，可在此置換；
        // 或者是針對整段文字進行關鍵字修正
        pos += 2; // UTF-8 或 Big5 的 □ 位元組長度
    }
    
    // 另外一種做法：如果該行包含特定的上下文，直接進行字串替換測試
    // 例如將「倔□的」修正為「倔強的」
    if (text.find("倔") != std::string::npos && text.find("的") != std::string::npos) {
        size_t idx = text.find("倔");
        // 簡單將周邊的方塊補正
        // 實務上也可以直接建立對照表
    }

    return text;
}

// 1. 攔截 TextOutA：當軟體嘗試在畫面上繪製文字時進行攔截與修正
BOOL WINAPI HookedTextOutA(HDC hdc, int nXStart, int nYStart, LPCSTR lpString, int cchString) {
    std::string fixed = FixRenderText(lpString, cchString);
    return fpTextOutA(hdc, nXStart, nYStart, fixed.c_str(), (int)fixed.length());
}

// 2. 攔截 ExtTextOutA：另一種常見的文字繪製 API
BOOL WINAPI HookedExtTextOutA(HDC hdc, int nX, int nY, UINT uOptions, CONST RECT* lprc, LPCSTR lpString, UINT cbCount, CONST INT* lpDx) {
    std::string fixed = FixRenderText(lpString, cbCount);
    return fpExtTextOutA(hdc, nX, nY, uOptions, lprc, fixed.c_str(), (UINT)fixed.length(), lpDx);
}

// 3. 基礎檔案讀寫攔截
HANDLE WINAPI HookedCreateFileA(LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode, LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition, DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) {
    return fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    return fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
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
            MH_CreateHook(&TextOutA, &HookedTextOutA, reinterpret_cast<LPVOID*>(&fpTextOutA));
            MH_CreateHook(&ExtTextOutA, &HookedExtTextOutA, reinterpret_cast<LPVOID*>(&fpExtTextOutA));
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
