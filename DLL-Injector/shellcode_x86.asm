.386
.MODEL FLAT, C
option casemap:none

.code

public LoaderShellCode

LoaderShellCode proc
    sub esp, 4h
    mov dword ptr [esp], 11223344h          ; Original EIP
    pushad
    pushfd

    push ebp
    mov ebp, esp

    push 11223344h                          ; lpvReserved
    push 1                                  ; DLL_PROCESS_ATTACH
    push 0                                  ; NULL

    mov eax, 11223344h                      ; Call Manual Map Entry
    call eax
     
    mov esp, ebp
    pop ebp

    popfd
    popad

    ret                                     ; Return to Original RIP
LoaderShellCode endp

end
