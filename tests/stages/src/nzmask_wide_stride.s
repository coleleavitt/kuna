// A Swift-string style count test (bit 61 of the high word picks the small
// form) guarding an indirect tail jump through a relative pointer.
    .text
    .globl widemask
    .type widemask, %function
    .p2align 2
widemask:
    stp x29, x30, [sp, #-0x20]!
    stp x19, x21, [sp, #0x10]
    mov x29, sp
    ldp x19, x21, [x0, #0x130]
    cbz x21, 1f
    and x8, x19, #0xffffffffffff
    ubfx x9, x21, #56, #4
    tst x21, #0x2000000000000000
    csel x8, x8, x9, eq
    cbz x8, 1f
    ldr x8, [x0, #0x208]
    ldrsw x9, [x8]
    add x5, x9, x8
    mov x0, x19
    mov x1, x21
    ldp x19, x21, [sp, #0x10]
    ldp x29, x30, [sp], #0x20
    br x5
1:
    ldr x0, [x0, #0x8]
    ldp x19, x21, [sp, #0x10]
    ldp x29, x30, [sp], #0x20
    br x0
    .size widemask, .-widemask
