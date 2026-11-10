#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <vector>
#include <algorithm>
#include <map>

typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* FnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnCloseHandle)(HANDLE);

FnCreateFileA fpCreateFileA = NULL;
FnCreateFileW fpCreateFileW = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;
FnCloseHandle fpCloseHandle = NULL;

// 儲存被攔截檔案的記憶體轉譯資料與目前讀取指標
struct HookedFileContext {
    std::vector<char> data;
    DWORD position;
};

std::map<HANDLE, HookedFileContext> g_hookedFiles;
CRITICAL_SECTION g_cs;

// 核心轉碼引擎：自動編碼辨識 + 簡轉繁 + 姓氏保護 + Big5 轉譯
std::vector<char> TranslateTextBuffer(const char* data, size_t size) {
    if (size == 0) return {};

    UINT sourceCP = 936; // 預設 GBK (CP936)
    const char* parseData = data;
    size_t parseSize = size;

    // 1. 自動偵測 UTF-8 帶 BOM 或標準 UTF-8
    if (size >= 3 && (unsigned char)data[0] == 0xEF && (unsigned char)data[1] == 0xBB && (unsigned char)data[2] == 0xBF) {
        sourceCP = CP_UTF8;
        parseData = data + 3;
        parseSize = size - 3;
    } 
    else if (MultiByteToWideChar(CP_UTF8, MB_ERR_INVALID_CHARS, data, (int)size, NULL, 0) > 0) {
        sourceCP = CP_UTF8;
    }

    // 2. 轉為寬字元 (UTF-16)
    int wlen = MultiByteToWideChar(sourceCP, 0, parseData, (int)parseSize, NULL, 0);
    if (wlen <= 0) return std::vector<char>(data, data + size);

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(sourceCP, 0, parseData, (int)parseSize, &wstr[0], wlen);

    // 3. 簡體轉繁體
    LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_TRADITIONAL_CHINESE, &wstr[0], wlen, &wstr[0], wlen);

    // 4. 【智慧防呆與保護清單】
    for (size_t i = 0; i < wstr.length(); ++i) {
        wchar_t& ch = wstr[i];
        
        // 保護姓氏：將被誤轉成繁體「範」的字還原為「范」
        if (ch == L'範') {
            ch = L'范';
        }

        // 缺字防呆（例如 0x729F 這種 Big5 缺字轉為強）
        if (ch == 0x729F) {
            ch = L'強';
        }
    }

    // 5. 轉回 Lookbook 專用的 Big5 (CP950)
    int alen = WideCharToMultiByte(950, 0, wstr.c_str(), (int)wstr.length(), NULL, 0, NULL, NULL);
    if (alen <= 0) return std::vector<char>(data, data + size);

    std::vector<char> outBuffer(alen);
    WideCharToMultiByte(950, 0, wstr.c_str(), (int)wstr.length(), outBuffer.data(), alen, NULL, NULL);
    return outBuffer;
}

bool IsTxtFile(LPCSTR filename) {
    if (!filename) return false;
    std::string name(filename);
    if (name.length() < 4) return false;
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
    return name.substr(name.length() - 4) == ".txt";
}

HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    HANDLE hReal = fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    
    if (lpFileName && IsTxtFile(lpFileName) && hReal != INVALID_HANDLE_VALUE && (dwDesiredAccess & GENERIC_READ)) {
        DWORD fileSize = GetFileSize(hReal, NULL);
        if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
            std::vector<char> fileBuffer(fileSize);
            DWORD bytesRead = 0;
            if (fpReadFile(hReal, fileBuffer.data(), fileSize, &bytesRead, NULL) && bytesRead > 0) {
                std::vector<char> translated = TranslateTextBuffer(fileBuffer.data(), bytesRead);
                
                EnterCriticalSection(&g_cs);
                g_hookedFiles[hReal] = { translated, 0 };
                LeaveCriticalSection(&g_cs);
            }
        }
    }
    return hReal;
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    HANDLE hReal = fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
    
    if (lpFileName && hReal != INVALID_HANDLE_VALUE && (dwDesiredAccess & GENERIC_READ)) {
        int len = WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, NULL, 0, NULL, NULL);
        if (len > 0) {
            std::string ansiName(len - 1, 0);
            WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, &ansiName[0], len, NULL, NULL);
            if (IsTxtFile(ansiName.c_str())) {
                DWORD fileSize = GetFileSize(hReal, NULL);
                if (fileSize != INVALID_FILE_SIZE && fileSize > 0) {
                    std::vector<char> fileBuffer(fileSize);
                    DWORD bytesRead = 0;
                    if (fpReadFile(hReal, fileBuffer.data(), fileSize, &bytesRead, NULL) && bytesRead > 0) {
                        std::vector<char> translated = TranslateTextBuffer(fileBuffer.data(), bytesRead);
                        
                        EnterCriticalSection(&g_cs);
                        g_hookedFiles[hReal] = { translated, 0 };
                        LeaveCriticalSection(&g_cs);
                    }
                }
            }
        }
    }
    return hReal;
}

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    EnterCriticalSection(&g_cs);
    auto it = g_hookedFiles.find(hFile);
    if (it != g_hookedFiles.end()) {
        auto& ctx = it->second;
        if (ctx.position >= ctx.data.size()) {
            if (lpNumberOfBytesRead) *lpNumberOfBytesRead = 0;
            LeaveCriticalSection(&g_cs);
            return TRUE;
        }
        DWORD bytesToCopy = min(nNumberOfBytesToRead, (DWORD)(ctx.data.size() - ctx.position));
        memcpy(lpBuffer, ctx.data.data() + ctx.position, bytesToCopy);
        ctx.position += bytesToCopy;
        if (lpNumberOfBytesRead) *lpNumberOfBytesRead = bytesToCopy;
        LeaveCriticalSection(&g_cs);
        return TRUE;
    }
    LeaveCriticalSection(&g_cs);

    return fpReadFile ? fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) : FALSE;
}

BOOL WINAPI HookedCloseHandle(HANDLE hObject) {
    EnterCriticalSection(&g_cs);
    if (g_hookedFiles.find(hObject) != g_hookedFiles.end()) {
        g_hookedFiles.erase(hObject);
    }
    LeaveCriticalSection(&g_cs);

    return fpCloseHandle ? fpCloseHandle(hObject) : FALSE;
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    return fpWriteFile ? fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        InitializeCriticalSection(&g_cs);
        if (MH_Initialize() == MH_OK) {
            MH_CreateHook(&CreateFileA, &HookedCreateFileA, reinterpret_cast<LPVOID*>(&fpCreateFileA));
            MH_CreateHook(&CreateFileW, &HookedCreateFileW, reinterpret_cast<LPVOID*>(&fpCreateFileW));
            MH_CreateHook(&ReadFile, &HookedReadFile, reinterpret_cast<LPVOID*>(&fpReadFile));
            MH_CreateHook(&WriteFile, &HookedWriteFile, reinterpret_cast<LPVOID*>(&fpWriteFile));
            MH_CreateHook(&CloseHandle, &HookedCloseHandle, reinterpret_cast<LPVOID*>(&fpCloseHandle));
            MH_EnableHook(MH_ALL_HOOKS);
        }
        break;
    case DLL_PROCESS_DETACH:
        DeleteCriticalSection(&g_cs);
        MH_DisableHook(MH_ALL_HOOKS);
        MH_Uninitialize();
        break;
    }
    return TRUE;
}
