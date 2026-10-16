#include <windows.h>
#include <tlhelp32.h>
#include <iostream>
#include <fstream>
#include <vector>

#ifdef _M_X64
#include "mmap_x64.h"
#else
#include "mmap_x86.h"
#endif

// Manual Map Result
enum class ManualMapResult : int {
    Pending = 0,
    Success = 1,
    FailedResolveImports,
    FailedRelocations,
    FailedEntryPoint,
};

// Manual Map Struct
struct MANUAL_MAP_PARAM {
    ULONG_PTR pLoadLibraryA;
    ULONG_PTR pGetProcAddress;
    ULONG_PTR dllBase;
    ULONG_PTR entryPoint;
    ManualMapResult result;
};

// Thread Struct
struct THREAD_INFO {
    DWORD threadId = 0;
    HANDLE hThread = NULL;
    CONTEXT ctx = { 0 };
};

ULONGLONG FileTimeToUInt64(const FILETIME& ft) {
    ULARGE_INTEGER uli;
    uli.LowPart = ft.dwLowDateTime;
    uli.HighPart = ft.dwHighDateTime;
    return uli.QuadPart;
}

struct EnumData {
    DWORD processId;
    DWORD threadId;
};

BOOL CALLBACK EnumWindowsProc(HWND hwnd, LPARAM lParam) {
    EnumData* data = (EnumData*)lParam;
    DWORD procId = 0;
    DWORD threadId = GetWindowThreadProcessId(hwnd, &procId);

    if (procId == data->processId && IsWindowVisible(hwnd)) {
        data->threadId = threadId;
        return FALSE;
    }
    return TRUE;
}

THREAD_INFO GetActiveThread(DWORD targetPid) {
    THREAD_INFO result = { 0 };

    EnumData data = { targetPid, 0 };
    EnumWindows(EnumWindowsProc, (LPARAM)&data);

    if (data.threadId != 0) {
        HANDLE hThread = OpenThread(THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, data.threadId);
        if (hThread) {
            SuspendThread(hThread);
            CONTEXT ctx = { 0 };
            ctx.ContextFlags = CONTEXT_CONTROL;

            if (GetThreadContext(hThread, &ctx)) {
                result.threadId = data.threadId;
                result.hThread = hThread;
                result.ctx = ctx;
                return result;
            }

            ResumeThread(hThread);
            CloseHandle(hThread);
        }
    }

    HANDLE hSnapThread = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
    if (hSnapThread == INVALID_HANDLE_VALUE) return result;

    THREADENTRY32 te;
    te.dwSize = sizeof(THREADENTRY32);
    std::vector<DWORD> threadIds;

    if (Thread32First(hSnapThread, &te)) {
        do {
            if (te.th32OwnerProcessID == targetPid) {
                threadIds.push_back(te.th32ThreadID);
            }
        } while (Thread32Next(hSnapThread, &te));
    }
    CloseHandle(hSnapThread);

    for (DWORD tid : threadIds) {
        HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION | THREAD_GET_CONTEXT | THREAD_SET_CONTEXT | THREAD_SUSPEND_RESUME, FALSE, tid);
        if (!hThread) continue;

        FILETIME creationTime, exitTime, kernelTime1, userTime1, kernelTime2, userTime2;

        if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime1, &userTime1)) {
            Sleep(20);

            if (GetThreadTimes(hThread, &creationTime, &exitTime, &kernelTime2, &userTime2)) {
                ULONGLONG k1 = FileTimeToUInt64(kernelTime1);
                ULONGLONG u1 = FileTimeToUInt64(userTime1);
                ULONGLONG k2 = FileTimeToUInt64(kernelTime2);
                ULONGLONG u2 = FileTimeToUInt64(userTime2);

                if ((k2 > k1) || (u2 > u1)) {
                    SuspendThread(hThread);
                    CONTEXT ctx = { 0 };
                    ctx.ContextFlags = CONTEXT_CONTROL;

                    if (GetThreadContext(hThread, &ctx)) {
                        result.threadId = tid;
                        result.hThread = hThread;
                        result.ctx = ctx;
                        return result;
                    }

                    ResumeThread(hThread);
                }
            }
        }
        CloseHandle(hThread);
    }

    return result;
}

int main(int argc, char* argv[]) {
    if (argc < 2) {
        std::cout << "Usage: DLL-Injector.exe <ProcessName.exe> <DllPath>\n";
        system("pause");
        return 1;
    }

    wchar_t wTargetName[MAX_PATH];
    mbstowcs_s(NULL, wTargetName, argv[1], MAX_PATH);

    DWORD targetPid = 0;
    HANDLE snapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 entry;
    entry.dwSize = sizeof(PROCESSENTRY32);

    if (Process32First(snapshot, &entry)) {
        do {
            if (_wcsicmp(entry.szExeFile, wTargetName) == 0) {
                targetPid = entry.th32ProcessID;
                break;
            }
        } while (Process32Next(snapshot, &entry));
    }
    CloseHandle(snapshot);

    if (targetPid == 0) {
        std::cout << "[!] Target process not found.\n";
        system("pause");
        return 1;
    }
	std::cout << "[+] Target found!\n";
    std::cout << "[+] Target PID: " << targetPid << "\n";

    char fullPath[MAX_PATH];
    if (GetFullPathNameA(argv[2], MAX_PATH, fullPath, NULL) == 0) {
        std::cout << "[!] Invalid DLL path.\n";
        system("pause");
        return 1;
    }

    // Open Target Process
    auto hProc = OpenProcess(PROCESS_ALL_ACCESS, FALSE, targetPid);
    if (!hProc) {
        std::cout << "[!] OpenProcess failed. Error: " << GetLastError() << "\n";
        system("pause");
        return 1;
    }
	std::cout << "[+] OpenProcess success!\n";

    // Map DLL
    std::ifstream file(fullPath, std::ios::binary | std::ios::ate);
    if (!file.is_open()) {
        std::cout << "[!] Failed to open DLL file.\n";
        system("pause");
        return 1;
    }
    std::cout << "[+] DLL file opened successfully!\n";
    std::streamsize fileSize = file.tellg();
    file.seekg(0, std::ios::beg);

    std::vector<BYTE> fileBuffer;
    fileBuffer.resize(fileSize);

    if (!file.read(reinterpret_cast<char*>(fileBuffer.data()), fileSize)) {
        std::cout << "[!] Failed to read DLL file into memory.\n";
        system("pause");
        return 1;
    }
    std::cout << "[+] DLL file read into memory successfully!\n";

    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(fileBuffer.data());
    if (pDosHeader->e_magic != 0x5A4D) {
        std::cout << "[!] Invalid MZ header.\n";
        system("pause");
        return 1;
    }

    auto* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(fileBuffer.data() + pDosHeader->e_lfanew);
    DWORD sizeOfImage = pNtHeader->OptionalHeader.SizeOfImage;

    BYTE* pTargetBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeOfImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pTargetBase) {
        std::cout << "[!] Target memory allocation failed. Error: " << GetLastError() << "\n";
        CloseHandle(hProc);
        system("pause");
        return 1;
    }

    std::vector<BYTE> localImage(sizeOfImage, 0);
    memcpy(localImage.data(), fileBuffer.data(), pNtHeader->OptionalHeader.SizeOfHeaders);

    auto* pSectionHeader = IMAGE_FIRST_SECTION(pNtHeader);
    for (WORD i = 0; i < pNtHeader->FileHeader.NumberOfSections; ++i, ++pSectionHeader) {
        if (pSectionHeader->SizeOfRawData > 0) {
            memcpy(
                localImage.data() + pSectionHeader->VirtualAddress,
                fileBuffer.data() + pSectionHeader->PointerToRawData,
                pSectionHeader->SizeOfRawData
            );
        }
    }

    if (!WriteProcessMemory(hProc, pTargetBase, localImage.data(), sizeOfImage, nullptr)) {
        std::cout << "[!] Failed to write mapped DLL to target. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        system("pause");
        return 1;
    }
    std::cout << "[+] Mapped DLL written to target successfully!\n";

    // Map MMap Loader
    auto* loaderDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(loader_dll_bytes.data());
    if (loaderDosHeader->e_magic != 0x5A4D) {
        std::cout << "[!] Invalid MZ header.\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        system("pause");
        return 1;
    }

    auto* loaderNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(loader_dll_bytes.data() + loaderDosHeader->e_lfanew);
    DWORD sizeOfLoaderImage = loaderNtHeader->OptionalHeader.SizeOfImage;

    BYTE* pLoaderBase = reinterpret_cast<BYTE*>(VirtualAllocEx(hProc, nullptr, sizeOfLoaderImage, MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE));
    if (!pLoaderBase) {
        std::cout << "[!] Target memory allocation failed. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        system("pause");
        return 1;
    }

    std::vector<BYTE> loaderImage(sizeOfLoaderImage, 0);
    memcpy(loaderImage.data(), loader_dll_bytes.data(), loaderNtHeader->OptionalHeader.SizeOfHeaders);

    auto* loaderSectionHeader = IMAGE_FIRST_SECTION(loaderNtHeader);
    for (WORD i = 0; i < loaderNtHeader->FileHeader.NumberOfSections; ++i, ++loaderSectionHeader) {
        if (loaderSectionHeader->SizeOfRawData > 0) {
            memcpy(
                loaderImage.data() + loaderSectionHeader->VirtualAddress,
                loader_dll_bytes.data() + loaderSectionHeader->PointerToRawData,
                loaderSectionHeader->SizeOfRawData
            );
        }
    }

    if (!WriteProcessMemory(hProc, pLoaderBase, loaderImage.data(), sizeOfLoaderImage, nullptr)) {
        std::cout << "[!] Failed to write loader to target. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pLoaderBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        system("pause");
        return 1;
    }

    // Map Reserved Param
    LPVOID pParam = VirtualAllocEx(hProc, nullptr, sizeof(MANUAL_MAP_PARAM), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
    if (!pParam) {
        std::cout << "[!] Failed to allocate memory for reserved param. Error: " << GetLastError() << "\n";
        VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
        VirtualFreeEx(hProc, pLoaderBase, 0, MEM_RELEASE);
        CloseHandle(hProc);
        system("pause");
        return 1;
    }

    // ShellCode Ptr
    LPVOID pRemoteShellcode = nullptr;

    // Thread Hijack
	std::cout << "[+] Attempting to hijack a thread in the target process...\n";

    THREAD_INFO info = GetActiveThread(targetPid);
    if (info.hThread) {
        std::cout << "[+] Successfully obtained thread handle!\n";
		std::cout << "[+] Thread ID: " << info.threadId << "\n";

        // ShellCode
        uintptr_t pLoadLibraryA = (uintptr_t)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "LoadLibraryA");
        uintptr_t pGetProcAddress = (uintptr_t)GetProcAddress(GetModuleHandleA("Kernel32.dll"), "GetProcAddress");
        uintptr_t dllBase = reinterpret_cast<uintptr_t>(pTargetBase);
        uintptr_t ploaderEntryPoint = reinterpret_cast<uintptr_t>(pLoaderBase + loaderNtHeader->OptionalHeader.AddressOfEntryPoint);

        MANUAL_MAP_PARAM localParam = { 0 };
        localParam.pLoadLibraryA = pLoadLibraryA;
        localParam.pGetProcAddress = pGetProcAddress;
        localParam.dllBase = dllBase;
        localParam.entryPoint = 0;

        if (!WriteProcessMemory(hProc, pParam, &localParam, sizeof(MANUAL_MAP_PARAM), nullptr)) {
            std::cout << "[!] Failed to write reserved param to target. Error: " << GetLastError() << "\n";
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pLoaderBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pParam, 0, MEM_RELEASE);
            CloseHandle(hProc);
            system("pause");
            return 1;
        }

#ifdef _WIN64
        uintptr_t o_ip = info.ctx.Rip;
#else
        uintptr_t o_ip = info.ctx.Eip;
#endif

        // ShellCode From asm
#ifdef _WIN64
        BYTE shellcode[] = {
            0x48, 0x83, 0xEC, 0x08,
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
            0xC7, 0x44, 0x24, 0x04, 0x00, 0x00, 0x00, 0x00,
            0x4C, 0x8D, 0x1C, 0x24,
            0x48, 0x81, 0xEC, 0xD0, 0x04, 0x00, 0x00,
            0x48, 0x83, 0xE4, 0xF0,
            0x48, 0x89, 0x44, 0x24, 0x78,
            0x48, 0x89, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,
            0x48, 0x89, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xAC, 0x24, 0xA0, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,
            0x48, 0x89, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,
            0x4C, 0x89, 0x9C, 0x24, 0x98, 0x00, 0x00, 0x00,
            0x8C, 0x4C, 0x24, 0x38,
            0x8C, 0x5C, 0x24, 0x3A,
            0x8C, 0x44, 0x24, 0x3C,
            0x8C, 0x64, 0x24, 0x3E,
            0x8C, 0x6C, 0x24, 0x40,
            0x8C, 0x54, 0x24, 0x42,
            0x0F, 0xAE, 0x84, 0x24, 0x00, 0x01, 0x00, 0x00,
            0x0F, 0xAE, 0x5C, 0x24, 0x34,
            0x9C,
            0x58,
            0x89, 0x44, 0x24, 0x44,
            0x48, 0x8B, 0x44, 0x24, 0x78,
            0xC7, 0x44, 0x24, 0x30, 0x0F, 0x00, 0x10, 0x00,
            0x48, 0x83, 0xEC, 0x20,
            0x48, 0x33, 0xC9,
            0x48, 0xC7, 0xC2, 0x01, 0x00, 0x00, 0x00,
            0x49, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0x48, 0xB8, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0,
            0x48, 0x83, 0xC4, 0x20,
            0x0F, 0xAE, 0x54, 0x24, 0x34,
            0x0F, 0xAE, 0x8C, 0x24, 0x00, 0x01, 0x00, 0x00,
            0x8B, 0x44, 0x24, 0x44,
            0x50,
            0x9D,
            0x48, 0x8B, 0x44, 0x24, 0x78,
            0x48, 0x8B, 0x8C, 0x24, 0x80, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x94, 0x24, 0x88, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0x9C, 0x24, 0x90, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xAC, 0x24, 0xA0, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xB4, 0x24, 0xA8, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xBC, 0x24, 0xB0, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x84, 0x24, 0xB8, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x8C, 0x24, 0xC0, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x94, 0x24, 0xC8, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0x9C, 0x24, 0xD0, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xA4, 0x24, 0xD8, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xAC, 0x24, 0xE0, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xB4, 0x24, 0xE8, 0x00, 0x00, 0x00,
            0x4C, 0x8B, 0xBC, 0x24, 0xF0, 0x00, 0x00, 0x00,
            0x48, 0x8B, 0xA4, 0x24, 0x98, 0x00, 0x00, 0x00,
            0xC3
        };

        memcpy(&shellcode[7], &o_ip, 4);
        memcpy(&shellcode[15], (uint8_t*)&o_ip + 4, 4);
        memcpy(&shellcode[231], &pParam, 8);
        memcpy(&shellcode[241], &ploaderEntryPoint, 8);
#else

        BYTE shellcode[] = {
            0x83, 0xEC, 0x04,
            0xC7, 0x04, 0x24, 0x00, 0x00, 0x00, 0x00,
            0x60,
            0x9C,
            0x55,
            0x8B, 0xEC,
            0x68, 0x00, 0x00, 0x00, 0x00,
            0x6A, 0x01,
            0x6A, 0x00,
            0xB8, 0x00, 0x00, 0x00, 0x00,
            0xFF, 0xD0,
            0x8B, 0xE5,
            0x5D,
            0x9D,
            0x61,
            0xC3,
        };

        memcpy(&shellcode[6], &o_ip, 4);
        memcpy(&shellcode[16], &pParam, 4);
        memcpy(&shellcode[25], &ploaderEntryPoint, 4);
#endif

        pRemoteShellcode = VirtualAllocEx(hProc, nullptr, sizeof(shellcode), MEM_COMMIT | MEM_RESERVE, PAGE_EXECUTE_READWRITE);
        if (!pRemoteShellcode) {
            std::cout << "[!] Failed to allocate memory for shellcode. Error: " << GetLastError() << "\n";
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pLoaderBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pParam, 0, MEM_RELEASE);
            CloseHandle(hProc);
            system("pause");
            return 1;
        }

        if (!WriteProcessMemory(hProc, pRemoteShellcode, shellcode, sizeof(shellcode), nullptr)) {
            std::cout << "[!] Failed to write shellcode to target. Error: " << GetLastError() << "\n";
            VirtualFreeEx(hProc, pTargetBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pLoaderBase, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pParam, 0, MEM_RELEASE);
            VirtualFreeEx(hProc, pRemoteShellcode, 0, MEM_RELEASE);
            CloseHandle(hProc);
            system("pause");
            return 1;
        }

		std::cout << "[+] Shellcode written to target successfully!\n";

        // Hijack
#ifdef _WIN64
        info.ctx.Rip = (DWORD64)pRemoteShellcode;
#else
        info.ctx.Eip = (DWORD)pRemoteShellcode;
#endif

        if (SetThreadContext(info.hThread, &info.ctx)) {
            std::cout << "[!] RIP/EIP successfully hijacked to Shellcode! Resuming thread...\n";
        }

        ResumeThread(info.hThread);
        CloseHandle(info.hThread);
    }

    std::cout << "[!] Injecting...\n";

    LPVOID pRemoteResultAddress = reinterpret_cast<LPVOID>(
        reinterpret_cast<uintptr_t>(pParam) + offsetof(MANUAL_MAP_PARAM, result)
        );

    ManualMapResult status = ManualMapResult::Pending;
    for (int i = 0; i < 500; i++) {
        SIZE_T bytesRead = 0;
        BOOL success = ReadProcessMemory(
            hProc,
            pRemoteResultAddress,
            &status,
            sizeof(ManualMapResult),
            &bytesRead
        );

        if (!success || bytesRead != sizeof(ManualMapResult)) {
            std::cerr << "[-] Failed to read process memory. Error: " << GetLastError() << "\n";
            Sleep(3000);
            return 1;
        }

        if (status != ManualMapResult::Pending) {
            break;
        }

        Sleep(10);
    }

    if (status == ManualMapResult::Pending) {
        std::cerr << "[!] Injection timed out after " << 5000 << "ms (DllMain may be executed successfully)\n";
        Sleep(3000);
        return 1;
    }

    CloseHandle(hProc);
    std::cout << "[+] Injection completed successfully!\n";
    Sleep(3000);
    return 0;
}
