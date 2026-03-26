fmac-y := src/fmac/procfs.o src/fmac/check.o
fmac-y += src/allowlist.o src/totp.o src/check.o src/anonfd.o src/nksu.o src/kprobe.o src/profile.o src/selinux.o src/syscall.o src/hijack.o

obj-$(CONFIG_FMAC) += fmac.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(IDIR)
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h