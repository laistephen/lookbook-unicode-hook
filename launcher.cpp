#include <windows.h>
#include <string>

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    char szPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, szPath);
    
    std::string exePath = std::string(szPath) + "\\LookBook.exe";
    std::string dllPath = std::string(szPath) + "\\LookbookHook.dll";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 正常啟動原本的 LookBook.exe（維持原檔名，確保相容性與 OLE 正常）
    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, 0, NULL, szPath, &si, &pi)) {
        MessageBoxA(NULL, "找不到 LookBook.exe！請確定載入器與 LookBook.exe 放在同一資料夾中。", "錯誤", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 等待 300 毫秒，讓主程式完成 OLE 初始化
    Sleep(300);

    // 注入 DLL
    LPVOID pLibRemote = VirtualAllocEx(pi.hProcess, NULL, dllPath.length() + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (pLibRemote) {
        WriteProcessMemory(pi.hProcess, pLibRemote, dllPath.c_str(), dllPath.length() + 1, NULL);
        
        LPTHREAD_START_ROUTINE pLoadLibrary = (LPTHREAD_START_ROUTINE)GetProcAddress(
            GetModuleHandleA("kernel32.dll"), "LoadLibraryA");

        if (pLoadLibrary) {
            HANDLE hThread = CreateRemoteThread(pi.hProcess, NULL, 0, pLoadLibrary, pLibRemote, 0, NULL);
            if (hThread) {
                WaitForSingleObject(hThread, INFINITE);
                CloseHandle(hThread);
            }
        }
    }

    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
