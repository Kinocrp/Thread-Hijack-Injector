#include <Windows.h>

enum class ManualMapResult : int {
    Pending = 0,
    Success = 1,
    FailedResolveImports,
    FailedRelocations,
    FailedEntryPoint,
};

struct MANUAL_MAP_PARAM {
    ULONG_PTR pLoadLibraryA;
    ULONG_PTR pGetProcAddress;
    ULONG_PTR dllBase;
    ULONG_PTR entryPoint;
    ManualMapResult result;
};

uintptr_t RemoteMMap(MANUAL_MAP_PARAM* param) {
    auto _LoadLibraryA = (HMODULE(*)(LPCSTR))param->pLoadLibraryA;
    auto _GetProcAddress = (FARPROC(*)(HMODULE, LPCSTR))param->pGetProcAddress;

    BYTE* pBase = reinterpret_cast<BYTE*>(param->dllBase);
    auto* pDosHeader = reinterpret_cast<IMAGE_DOS_HEADER*>(pBase);
    auto* pNtHeader = reinterpret_cast<IMAGE_NT_HEADERS*>(pBase + pDosHeader->e_lfanew);

    INT_PTR locationDelta = param->dllBase - pNtHeader->OptionalHeader.ImageBase;
    DWORD imageSize = pNtHeader->OptionalHeader.SizeOfImage;
    auto relocDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];

    if (relocDir.Size > 0) {
        if (relocDir.VirtualAddress + relocDir.Size > imageSize) {
            param->result = ManualMapResult::FailedRelocations;
            return 0;
        }

        auto* pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(pBase + relocDir.VirtualAddress);
        const auto* pRelocEnd = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<uintptr_t>(pRelocData) + relocDir.Size);

        while (pRelocData < pRelocEnd && pRelocData->SizeOfBlock >= sizeof(IMAGE_BASE_RELOCATION)) {
            if (reinterpret_cast<uintptr_t>(pRelocData) + pRelocData->SizeOfBlock > reinterpret_cast<uintptr_t>(pRelocEnd)) {
                param->result = ManualMapResult::FailedRelocations;
                return 0;
            }

            UINT amountOfEntries = (pRelocData->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(WORD);
            WORD* pRelativeInfo = reinterpret_cast<WORD*>(pRelocData + 1);

            for (UINT i = 0; i < amountOfEntries; ++i, ++pRelativeInfo) {
                WORD type = (*pRelativeInfo) >> 0x0C;
                WORD offset = (*pRelativeInfo) & 0xFFF;
                DWORD rva = pRelocData->VirtualAddress + offset;

#ifdef _WIN64
                if (type == IMAGE_REL_BASED_DIR64) {
                    if (rva + sizeof(UINT_PTR) > imageSize) {
                        param->result = ManualMapResult::FailedRelocations;
                        return 0;
                    }
                    UINT_PTR* pPatch = reinterpret_cast<UINT_PTR*>(pBase + rva);
                    *pPatch += locationDelta;
                }
#else
                if (type == IMAGE_REL_BASED_HIGHLOW) {
                    if (rva + sizeof(DWORD) > imageSize) {
                        param->result = ManualMapResult::FailedRelocations;
                        return 0;
                    }
                    DWORD* pPatch = reinterpret_cast<DWORD*>(pBase + rva);
                    *pPatch += (DWORD)locationDelta;
                }
#endif
                else if (type == IMAGE_REL_BASED_ABSOLUTE) {
                    continue;
                }
            }
            pRelocData = reinterpret_cast<IMAGE_BASE_RELOCATION*>(reinterpret_cast<BYTE*>(pRelocData) + pRelocData->SizeOfBlock);
        }
    }

    auto importDir = pNtHeader->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_IMPORT];
    if (importDir.Size > 0) {
        auto* pImportDescr = reinterpret_cast<IMAGE_IMPORT_DESCRIPTOR*>(pBase + importDir.VirtualAddress);

        while (pImportDescr->Name) {
            char* szMod = reinterpret_cast<char*>(pBase + pImportDescr->Name);
            HMODULE hDll = _LoadLibraryA(szMod);

            if (!hDll) {
                param->result = ManualMapResult::FailedResolveImports;
                return 0;
            }

            if (hDll) {
                ULONG_PTR* pThunkRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->OriginalFirstThunk);
                ULONG_PTR* pFuncRef = reinterpret_cast<ULONG_PTR*>(pBase + pImportDescr->FirstThunk);

                if (!pImportDescr->OriginalFirstThunk)
                    pThunkRef = pFuncRef;

                for (; *pThunkRef; ++pThunkRef, ++pFuncRef) {
                    if (IMAGE_SNAP_BY_ORDINAL(*pThunkRef)) {
                        FARPROC pFunc = _GetProcAddress(hDll, reinterpret_cast<char*>(*pThunkRef & 0xFFFF));
                        if (!pFunc) {
                            param->result = ManualMapResult::FailedResolveImports;
                            return 0;
                        }
                        *pFuncRef = reinterpret_cast<ULONG_PTR>(pFunc);
                    }
                    else {
                        auto* pImport = reinterpret_cast<IMAGE_IMPORT_BY_NAME*>(pBase + (*pThunkRef));
                        FARPROC pFunc = _GetProcAddress(hDll, pImport->Name);
                        if (!pFunc) {
                            param->result = ManualMapResult::FailedResolveImports;
                            return 0;
                        }
                        *pFuncRef = reinterpret_cast<ULONG_PTR>(pFunc);
                    }
                }
            }
            ++pImportDescr;
        }
    }

    return ((uintptr_t)pBase + pNtHeader->OptionalHeader.AddressOfEntryPoint);
}

BOOL WINAPI KinoEntry(HINSTANCE hinstDLL, DWORD fdwReason, LPVOID lpvReserved)
{
    if (fdwReason == DLL_PROCESS_ATTACH)
    {
        ((MANUAL_MAP_PARAM*)lpvReserved)->entryPoint = RemoteMMap((MANUAL_MAP_PARAM*)lpvReserved);

        if (!((MANUAL_MAP_PARAM*)lpvReserved)->entryPoint) return FALSE;
        typedef BOOL(WINAPI* DllMain_t)(HMODULE, DWORD, LPVOID);
        DllMain_t pDllMain = reinterpret_cast<DllMain_t>(((MANUAL_MAP_PARAM*)lpvReserved)->entryPoint);
        pDllMain((HMODULE)((MANUAL_MAP_PARAM*)lpvReserved)->dllBase, DLL_PROCESS_ATTACH, NULL);

        ((MANUAL_MAP_PARAM*)lpvReserved)->result = ManualMapResult::Success;
    }
    return TRUE;
}
