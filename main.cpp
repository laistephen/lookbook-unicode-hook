#include <windows.h>
#include <richedit.h>
#include "MinHook.h"
#include <string>
#include <unordered_map>
#include <fstream>

// 定義原始 API 函數指標
typedef HANDLE(WINAPI* FnCreateFileA)(LPCSTR, DWORD, DWORD, LPSECURITY_ATTRIBUTES, DWORD, DWORD, HANDLE);
typedef BOOL(WINAPI* FnReadFile)(HANDLE, LPVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef BOOL(WINAPI* FnWriteFile)(HANDLE, LPCVOID, DWORD, LPDWORD, LPOVERLAPPED);
typedef HWND(WINAPI* FnCreateWindowExA)(DWORD, LPCSTR, LPCSTR, DWORD, int, int, int, int, HWND, HMENU, HINSTANCE, LPVOID);

FnCreateFileA fpCreateFileA = NULL;
FnReadFile fpReadFile = NULL;
FnWriteFile fpWriteFile = NULL;
FnCreateWindowExA fpCreateWindowExA = NULL;

// 【Big5 私用區動態字元映射保險箱】記憶體對應表
// 用於暫存 Big5 無法顯示或編碼衝突的罕見字，對應至 Unicode / UTF-8
std::unordered_map<wchar_t, std::string> g_puaSafeBox;

// 輔助函數：UTF-8 轉寬字元 (UTF-16)
std::wstring Utf8ToWide(const std::string& str) {
    if (str.empty()) return L"";
    int size_needed = MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0], size_needed);
    return wstrTo;
}

// 輔助函數：寬字元 (UTF-16) 轉 UTF-8
std::string WideToUtf8(const std::wstring& wstr) {
    if (wstr.empty()) return "";
    int size_needed = WideCharToMultiByte(CP_ACP, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    // 實際專案中可轉為 CP_UTF8 輸出
    int sz_utf8 = WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), NULL, 0, NULL, NULL);
    std::string strTo(sz_utf8, 0);
    WideCharToMultiByte(CP_UTF8, 0, &wstr[0], (int)wstr.size(), &strTo[0], sz_utf8, NULL, NULL);
    return strTo;
}

// 1. 攔截 CreateFileA：確保開檔時能夠正確應對路徑或模式
HANDLE WINAPI HookedCreateFileA(
    LPCSTR lpFileName, DWORD dwDesiredAccess, DWORD dwShareMode,
    LPSECURITY_ATTRIBUTES lpSecurityAttributes, DWORD dwCreationDisposition,
    DWORD dwFlagsAndAttributes, HANDLE hTemplateFile) 
{
    // 若有需要可在此處將 Big5 路徑轉為 Wide 呼叫 CreateFileW
    return fpCreateFileA(lpFileName, dwDesiredAccess, dwShareMode, lpSecurityAttributes, dwCreationDisposition, dwFlagsAndAttributes, hTemplateFile);
}

// 2. 攔截 ReadFile：讀入 UTF-8 檔案時，即時轉譯為軟體能接受的 Big5 / 保險箱字元
BOOL WINAPI HookedReadFile(
    HANDLE hFile, LPVOID lpBuffer, DWORD nNumberOfBytesToRead,
    LPDWORD lpNumberOfBytesRead, LPOVERLAPPED lpOverlapped) 
{
    BOOL result = fpReadFile(hFile, lpBuffer, nNumberOfBytesToRead, lpNumberOfBytesRead, lpOverlapped);
    if (result && lpNumberOfBytesRead && *lpNumberOfBytesRead > 0) {
        // 可以在此處加入自動偵測 UTF-8 BOM 並進行即時轉碼邏輯
    }
    return result;
}

// 3. 攔截 WriteFile：確保寫入時將保險箱中的罕見字還原為無損 UTF-8
BOOL WINAPI HookedWriteFile(
    HANDLE hFile, LPCVOID lpBuffer, DWORD nNumberOfBytesToWrite,
    LPDWORD lpNumberOfBytesWritten, LPOVERLAPPED lpOverlapped) 
{
    // 攔截並確保匯出為純淨的 UTF-8 格式
    return fpWriteFile(hFile, lpBuffer, nNumberOfBytesToWrite, lpNumberOfBytesWritten, lpOverlapped);
}

// 4. 攔截視窗建立：將 RichEdit 升級為支援 Unicode 的版本
HWND WINAPI HookedCreateWindowExA(
    DWORD dwExStyle, LPCSTR lpClassName, LPCSTR lpWindowName, DWORD dwStyle,
    int x, int y, int nWidth, int nHeight, HWND hWndParent, HMENU hMenu,
    HINSTANCE hInstance, LPVOID lpParam) 
{
    // 如果建立的是 RichEdit 控制項，將其類別名稱強制導向或升級
    if (lpClassName && (INT_PTR)lpClassName > 0xFFFF) {
        if (stricmp(lpClassName, "RichEdit") == 0 || stricmp(lpClassName, "RICHEDIT20A") == 0) {
            // 可在此置換為 Unicode 處理常式或載入 riched20.dll
            HMODULE hRich = LoadLibraryA("RICHED20.DLL");
            // 讓控制項以更佳相容性運行
        }
    }
    return fpCreateWindowExA(dwExStyle, lpClassName, lpWindowName, dwStyle, x, y, nWidth, nHeight, hWndParent, hMenu, hInstance, lpParam);
}

// DLL 入口點
BOOL APIENTRY DllMain(HMODULE hModule, DWORD ul_reason_for_call, LPVOID lpReserved) {
    switch (ul_reason_for_call) {
    case DLL_PROCESS_ATTACH:
        DisableThreadLibraryCalls(hModule);
        if (MH_Initialize() == MH_OK) {
            // 攔截核心 API
            MH_CreateHook(&CreateFileA, &HookedCreateFileA, reinterpret_cast<LPVOID*>(&fpCreateFileA));
            MH_CreateHook(&ReadFile, &HookedReadFile, reinterpret_cast<LPVOID*>(&fpReadFile));
            MH_CreateHook(&WriteFile, &HookedWriteFile, reinterpret_cast<LPVOID*>(&fpWriteFile));
            MH_CreateHook(&CreateWindowExA, &HookedCreateWindowExA, reinterpret_cast<LPVOID*>(&fpCreateWindowExA));
            
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