fmac-y += src/anonfd.o src/nksu.o \
           src/privilege.o src/selinux.o src/tracepoint.o src/ioctl.o src/procfs.o \
           src/uid_cap.o src/manager.o

obj-$(CONFIG_FMAC) += fmac.o

ccflags-y += -I$(srctree)/security/selinux
ccflags-y += -I$(srctree)/security/selinux/include
ccflags-y += -I$(IDIR)
ccflags-y += -I$(objtree)/security/selinux
ccflags-y += -include $(srctree)/include/uapi/asm-generic/errno.h

ccflags-y += -std=gnu11
ccflags-y += -Wno-unused-variable
ccflags-y += -Werror=implicit-function-declaration
ccflags-y += -Werror=return-type

CFLAGS_src/manager.o     := -O3
CFLAGS_src/hijack.o   := -O3