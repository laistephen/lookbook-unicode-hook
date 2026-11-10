#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <vector>
#include <algorithm>

typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef HANDLE(WINAPI* FnCreateFileW)(LPCWSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);

FnCreateFileA fpCreateFileA = NULL;
FnCreateFileW fpCreateFileW = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;

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

// 核心轉碼與智慧防呆：簡體轉繁體 + 自訂保護清單 + Big5 轉譯
std::vector<char> TranslateTextBuffer(const char* data, size_t size) {
    if (size == 0) return {};

    UINT sourceCP = CP_ACP;
    if (IsUtf8(data, size)) {
        sourceCP = CP_UTF8;
    } else {
        sourceCP = 936; // GBK / 簡體中文
    }

    // 1. 先將原始檔案轉為寬字元 (UTF-16)
    int wlen = MultiByteToWideChar(sourceCP, 0, data, (int)size, NULL, 0);
    if (wlen <= 0) return std::vector<char>(data, data + size);

    std::wstring wstr(wlen, 0);
    MultiByteToWideChar(sourceCP, 0, data, (int)size, &wstr[0], wlen);

    // 2. 使用 Windows API 將簡體中文直接轉為繁體中文
    LCMapStringW(LOCALE_USER_DEFAULT, LCMAP_TRADITIONAL_CHINESE, &wstr[0], wlen, &wstr[0], wlen);

    // 3. 【自訂保護清單與缺字防呆】
    for (size_t i = 0; i < wstr.length(); ++i) {
        wchar_t& ch = wstr[i];
        
        // 保護姓氏：將被誤轉成繁體「範」的字還原為簡體/常用字「范」
        if (ch == L'範') {
            ch = L'范';
        }

        // 缺字防呆（例如 0x729F 這種 Big5 缺字轉為強）
        if (ch == 0x729F) {
            ch = L'強';
        }
    }

    // 4. 轉回 Lookbook 看得懂的 Big5 (CP950)
    int alen = WideCharToMultiByte(950, 0, wstr.c_str(), wlen, NULL, 0, NULL, NULL);
    if (alen <= 0) return std::vector<char>(data, data + size);

    std::vector<char> outBuffer(alen);
    WideCharToMultiByte(950, 0, wstr.c_str(), wlen, outBuffer.data(), alen, NULL, NULL);
    return outBuffer;
}

bool IsTxtFile(LPCSTR filename) {
    if (!filename) return false;
    std::string name(filename);
    if (name.length() < 4) return false;
    std::transform(name.begin(), name.end(), name.begin(), ::tolower);
    return name.substr(name.length() - 4) == ".txt";
}

HANDLE OpenAndRedirectTxt(HANDLE hReal) {
    if (hReal == INVALID_HANDLE_VALUE) return INVALID_HANDLE_VALUE;
    DWORD fileSize = GetFileSize(hReal, NULL);
    if (fileSize == INVALID_FILE_SIZE || fileSize == 0) {
        CloseHandle(hReal);
        return INVALID_HANDLE_VALUE;
    }
    std::vector<char> fileBuffer(fileSize);
    DWORD bytesRead = 0;
    if (!ReadFile(hReal, fileBuffer.data(), fileSize, &bytesRead, NULL) || bytesRead == 0) {
        CloseHandle(hReal);
        return INVALID_HANDLE_VALUE;
    }
    CloseHandle(hReal);

    std::vector<char> converted = TranslateTextBuffer(fileBuffer.data(), bytesRead);

    char tempPath[MAX_PATH];
    char tempFile[MAX_PATH];
    GetTempPathA(MAX_PATH, tempPath);
    GetTempFileNameA(tempPath, "LBK", 0, tempFile);

    HANDLE hTemp = CreateFileA(tempFile, GENERIC_READ | GENERIC_WRITE, 0, NULL, CREATE_ALWAYS, FILE_ATTRIBUTE_TEMPORARY | FILE_FLAG_DELETE_ON_CLOSE, NULL);
    if (hTemp != INVALID_HANDLE_VALUE) {
        DWORD bytesWritten = 0;
        WriteFile(hTemp, converted.data(), (DWORD)converted.size(), &bytesWritten, NULL);
        SetFilePointer(hTemp, 0, NULL, FILE_BEGIN);
        return hTemp;
    }
    return INVALID_HANDLE_VALUE;
}

HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    if (lpFileName && IsTxtFile(lpFileName) && (dwDesiredAccess & GENERIC_READ) && !(dwDesiredAccess & GENERIC_WRITE)) {
        HANDLE hReal = fpCreateFileA(lpFileName, GENERIC_READ, FILE_SHARE_READ, lpSecurityAttributes, OPEN_EXISTING, dwFlagsAndAttributes, hTemplateFile);
        HANDLE hRedirected = OpenAndRedirectTxt(hReal);
        if (hRedirected != INVALID_HANDLE_VALUE) return hRedirected;
    }
    return fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

HANDLE WINAPI HookedCreateFileW(
    LPCWSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    if (lpFileName && (dwDesiredAccess & GENERIC_READ) && !(dwDesiredAccess & GENERIC_WRITE)) {
        int len = WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, NULL, 0, NULL, NULL);
        if (len > 0) {
            std::string ansiName(len - 1, 0);
            WideCharToMultiByte(CP_ACP, 0, lpFileName, -1, &ansiName[0], len, NULL, NULL);
            if (IsTxtFile(ansiName.c_str())) {
                HANDLE hReal = fpCreateFileW(lpFileName, GENERIC_READ, FILE_SHARE_READ, lpSecurityAttributes, OPEN_EXISTING, dwFlagsAndAttributes, hTemplateFile);
                HANDLE hRedirected = OpenAndRedirectTxt(hReal);
                if (hRedirected != INVALID_HANDLE_VALUE) return hRedirected;
            }
        }
    }
    return fpCreateFileW(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

BOOL WINAPI HookedReadFile(HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead, LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) {
    return fpReadFile ? fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped) : FALSE;
}

BOOL WINAPI HookedWriteFile(HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite, LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) {
    return fpWriteFile ? fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped) : FALSE;
}

BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() == MH_OK) {
            MH_CreateHook(&CreateFileA, &HookedCreateFileA, reinterpret_cast<LPVOID*>(&fpCreateFileA));
            MH_CreateHook(&CreateFileW, &HookedCreateFileW, reinterpret_cast<LPVOID*>(&fpCreateFileW));
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
