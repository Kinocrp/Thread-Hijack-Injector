.code

public LoaderShellCode

LoaderShellCode proc
    sub rsp, 8
    mov dword ptr [rsp], 11223344h          ; Original RIP Low
    mov dword ptr [rsp + 4], 55667788h      ; Original RIP High

    pushfq
    push rax
    push rcx
    push rdx
    push rbx
    push rbp
    push rsi
    push rdi
    push r8
    push r9
    push r10
    push r11
    push r12
    push r13
    push r14
    push r15

    mov rbp, rsp

    sub rsp, 200h
    and rsp, 0FFFFFFFFFFFFFFF0h
    fxsave [rsp]

    sub rsp, 20h
    xor rcx, rcx                            ; NULL
    mov rdx, 1                              ; DLL_PROCESS_ATTACH
    mov r8, 1122334455667788h               ; lpvReserved

    mov rax, 1122334455667788h              ; Call Manual Map Entry
    call rax

    add rsp, 20h
    fxrstor [rsp]

    mov rsp, rbp

    pop r15
    pop r14
    pop r13
    pop r12
    pop r11
    pop r10
    pop r9
    pop r8
    pop rdi
    pop rsi
    pop rbp
    pop rbx
    pop rdx
    pop rcx
    pop rax
    popfq

    ret                                     ; Return To Original RIP
LoaderShellCode endp

end
