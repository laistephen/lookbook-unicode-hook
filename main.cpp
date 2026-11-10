#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <vector>

// 定義原始 API 函數指標
typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

FnCreateFileA fpCreateFileA = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;

// 輔助函數：檢查是否為有效的 UTF-8 格式
bool IsUtf8(const char* data, size_t size) {
    size_t i = 0;
    bool has_utf8 = false;
    while (i < size) {
        unsigned char c = data[i];
        if (c < 0x80) { i++; continue; }
        has_utf8 = true;
        size_t expected = 0;
        if ((c & 0xE0) == 0xC0) expected = 1;
        else if ((c & 0xF0) == 0xE0) expected = 2;
        else if ((c & 0xF8) == 0xF0) expected = 3;
        else return false;
        
        if (i + expected >= size) return false;
        for (size_t j = 1; j <= expected; ++j) {
            if ((data[i + j] & 0xC0) != 0x80) return false;
        }
        i += expected + 1;
    }
    return has_utf8;
}

// 核心轉碼函數：將 GBK 或 UTF-8 轉為系統預設 ANSI (Big5) 供舊軟體正確顯示
std::vector<char> TranslateTextBuffer(const char* data, size_t size) {
    if (size == 0) return {};

    UINT sourceCP = CP_ACP; // 預設
    if (IsUtf8(data, size)) {
        sourceCP = CP_UTF8;
    } else {
        // 簡單判定是否為 GBK 範圍，若不是純 ASCII 則嘗試以 GBK (CP936) 解讀
        sourceCP = 936; 
    }

    // 1. 先轉為寬字元 (UTF-16)
    int wlen = MultiByteToWideChar(sourceCP, 0, data, (int)size, NULL, 0);
    if (wlen <= 0) return std::vector<char>(data, data + size);

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(sourceCP, 0, data, (int)size, &wstr[0], wlen);

    // 2. 再從寬字元轉回系統當前 ANSI (繁體中文 Big5 / CP950)
    int alen = WideCharToMultiByte(950, 0, wstr.c_str(), wlen, NULL, 0, NULL, NULL);
    if (alen <= 0) return std::vector<char>(data, data + size);

    std::vector<char> outBuffer(alen);
    WideCharToMultiByte(950, 0, wstr.c_str(), wlen, outBuffer.data(), alen, NULL, NULL);
    return outBuffer;
}

// 1. 攔截 CreateFileA
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    return fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// 2. 攔截 ReadFile：自動攔截並將 GBK/UTF-8 轉譯為 Big5
BOOL WINAPI HookedReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) 
{
    BOOL result = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        // 讀取原始檔案資料
        std::vector<char> rawData((char*)lpBuffer, (char*)lpBuffer + *lpNumberOfBytesRead);
        
        // 進行編碼智慧轉換
        std::vector<char> converted = TranslateTextBuffer(rawData.data(), rawData.size());

        // 如果轉換後的長度小於等於緩衝區容量，則複寫進去
        if (converted.size() <= nNumberOfBytesToRead) {
            memcpy(lpBuffer, converted.data(), converted.size());
            *lpNumberOfBytesRead = (DWORD)converted.size();
        }
    }
    return result;
}

// 3. 攔截 WriteFile
BOOL WINAPI HookedWriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) 
{
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
