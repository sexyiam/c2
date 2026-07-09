.data
PUBLIC g_ssn
PUBLIC g_gadget
g_ssn     DWORD 0
g_gadget  QWORD 0

.code
PUBLIC IndirectSyscall

IndirectSyscall PROC
    mov     r10, rcx
    mov     eax, DWORD PTR [g_ssn]
    jmp     QWORD PTR [g_gadget]
IndirectSyscall ENDP

END
