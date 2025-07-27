fmac-objs := fm.o
fmac-objs += fmac_procfs.o
fmac-objs += root.o
fmac-objs += allowlist.o
fmac-objs += sigcheck.o

obj-$(CONFIG_FMAC) += fmac.o

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include