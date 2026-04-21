// SPDX-License-Identifier: GPL-3.0
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>

    .text
    .align 2
    .global nksu_dispatch_fast
    .type   nksu_dispatch_fast, %function

// x0 = regs
nksu_dispatch_fast:

    /* -------------------------
     * nr = x8 (syscall number)
     * ------------------------- */
    mov     w1, w8

    /* bounds check */
    cmp     w1, #__NR_syscalls
    b.hs    .Lnosys

    /* -------------------------
     * load virt_table[nr]
     * ------------------------- */
    adrp    x2, virt_table
    add     x2, x2, :lo12:virt_table
    add     x2, x2, x1, lsl #3

    ldar    x3, [x2]          // fn

    cbz     x3, .Lorig

    /* -------------------------
     * slow path: call handler
     * ------------------------- */
    stp     x29, x30, [sp, #-32]!
    stp     x19, x20, [sp, #16]
    mov     x29, sp

    mov     x19, x0           // save regs
    mov     w20, w1           // save nr

    blr     x3                // fn(regs)

    cbnz    x0, .Lhandled     // if handled → return

    /* fallback to orig */
    mov     x0, x19
    mov     w1, w20

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32

    b       .Lorig

.Lhandled:
    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

.Lorig:
    adrp    x2, nksu_orig_table
    add     x2, x2, :lo12:nksu_orig_table
    add     x2, x2, x1, lsl #3

    ldar    x3, [x2]

    cbz     x3, .Lnosys

    br      x3              // tail call

.Lnosys:
    mov     x0, #-38        // -ENOSYS
    ret

.size nksu_dispatch_fast, .-nksu_dispatch_fast