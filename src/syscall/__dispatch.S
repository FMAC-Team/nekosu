// SPDX-License-Identifier: GPL-3.0
#include <linux/linkage.h>
#include <asm/asm-offsets.h>
#include <asm/unistd.h>

    .text
    .align 2
    .global nksu_dispatch_fast
    .type   nksu_dispatch_fast, %function

nksu_dispatch_fast:
    mov     w1, w8
    cmp     w1, #__NR_syscalls
    b.hs    .Lnosys

    adrp    x2, virt_table
    add     x2, x2, :lo12:virt_table
    ldr     x3, [x2, w1, uxtw #3]
    cbz     x3, .Lorig

    stp     x29, x30,[sp, #-32]!
    stp     x19, x20, [sp, #16]
    mov     x29, sp

    mov     x19, x0
    mov     x20, x1

    blr     x3

    cbz     x0, .Lfallback

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32
    ret

.Lfallback:
    mov     x0, x19
    mov     x1, x20

    ldp     x19, x20, [sp, #16]
    ldp     x29, x30, [sp], #32

.Lorig:
    adrp    x2, nksu_orig_table
    add     x2, x2, :lo12:nksu_orig_table
    ldr     x3, [x2, w1, uxtw #3]
    cbz     x3, .Lnosys
    br      x3

.Lnosys:
    mov     x0, #-38
    ret

.size nksu_dispatch_fast, .-nksu_dispatch_fast