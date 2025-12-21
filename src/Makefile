fmac-objs := fm.o
fmac-objs += procfs.o
fmac-objs += check.o
fmac-objs += log.o

ifdef CONFIG_FMAC_ROOT
fmac-objs += root.o
fmac-objs += allowlist.o
fmac-objs += totp.o
fmac-objs += tracepoint.o
fmac-objs += rsa_pub.o
endif

obj-$(CONFIG_FMAC) += fmac.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h
