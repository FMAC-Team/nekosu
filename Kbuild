fmac-y := src/fmac/procfs.o src/fmac/hashtable.o src/fmac/init.o src/fmac/openat.o src/fmac/hook.o
fmac-y += src/allowlist.o src/totp.o src/check.o src/anonfd.o src/nksu.o src/kprobe.o src/profile.o src/selinux.o src/syscall.o src/hijack.o src/ioctl.o

obj-$(CONFIG_FMAC) += fmac.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(IDIR)
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

ccflags-y += -std=gnu99
ccflags-y += -Wno-declaration-after-statement
ccflags-y += -Wno-unused-variable
