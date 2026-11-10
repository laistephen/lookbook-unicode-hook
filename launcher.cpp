#include <windows.h>
#include <string>

int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    char szPath[MAX_PATH];
    GetCurrentDirectoryA(MAX_PATH, szPath);
    
    std::string exePath = std::string(szPath) + "\\LookBook_orig.exe";
    std::string dllPath = std::string(szPath) + "\\LookbookHook.dll";

    STARTUPINFOA si = { sizeof(si) };
    PROCESS_INFORMATION pi = { 0 };

    // 以暫停狀態啟動原本的主程式
    if (!CreateProcessA(exePath.c_str(), NULL, NULL, NULL, FALSE, CREATE_SUSPENDED, NULL, szPath, &si, &pi)) {
        MessageBoxA(NULL, "找不到 LookBook_orig.exe！請確定是否已將原本的 LookBook.exe 改名為 LookBook_orig.exe。", "錯誤", MB_OK | MB_ICONERROR);
        return 1;
    }

    // 在目標進程中配置記憶體並寫入 DLL 路徑
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

    // 恢復主程式執行
    ResumeThread(pi.hThread);
    CloseHandle(pi.hProcess);
    CloseHandle(pi.hThread);
    return 0;
}
