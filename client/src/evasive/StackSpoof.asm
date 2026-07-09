; Spoofed 4-arg call trampoline (x64, MASM).
;
; SpoofCall(void* target, ULONG_PTR a0, a1, a2, a3)
;   rcx = target, rdx = a0, r8 = a1, r9 = a2, [rsp+0x28] = a3
;
; Reorders args to the target's ABI (rcx=a0, rdx=a1, r8=a2, r9=a3), plants a
; spoofed return frame so the immediate return address is an ntdll gadget, then
; tail-jumps to the target. The ntdll gadget (`add rsp,0x20; ret`) skips the
; shadow space and returns to our planted continuation, which returns to the C
; caller. g_gadgetRet holds the ntdll gadget address (set by stackspoof::init).

.data
PUBLIC g_gadgetRet
g_gadgetRet QWORD 0

.code
PUBLIC SpoofCall

SpoofCall PROC
    ; save nonvolatile registers we will use
    push    rbp
    push    rbx
    sub     rsp, 20h            ; frame (sized so the target is entered aligned)

    mov     rbx, rcx            ; rbx = target
    mov     rcx, rdx            ; a0
    mov     rdx, r8             ; a1
    mov     r8,  r9             ; a2
    mov     r9,  [rsp+58h]      ; a3: entry [rsp+28h] + push*2 + sub 20h = +58h

    ; Plant continuation, shadow space, then spoofed return slot.
    lea     rbp, [cont]         ; real continuation address
    push    rbp                 ; [..] = cont
    sub     rsp, 20h            ; shadow space for the target
    mov     rax, [g_gadgetRet]  ; ntdll `add rsp,0x20; ret` gadget
    push    rax                 ; spoofed return slot (target will ret to this)

    jmp     rbx                 ; tail-call target (no return address pushed)

cont:
    ; Arrive here after the ntdll gadget pops `cont`. rsp points just above the
    ; pushed `cont` (the `sub rsp,20h` frame + pushed rbp/rbx remain).
    add     rsp, 20h
    pop     rbx
    pop     rbp
    ret
SpoofCall ENDP

END
