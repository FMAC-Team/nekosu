fmac-objs := fm.o
fmac-objs += procfs.o
fmac-objs += check.o
fmac-objs += log.o

ifdef CONFIG_FMAC_ROOT
fmac-objs += root.o
fmac-objs += allowlist.o
fmac-objs += totp.o
fmac-objs += rsa_pub.o

ifeq ($(CONFIG_FMAC),m)
    fmac-objs += kprobe.o
endif

ifeq ($(CONFIG_FMAC),y)
    fmac-objs += tracepoint.o
endif

endif

ifeq ($(CONFIG_FMAC_ROOT_KPROBE), y)
ccflags-y += -DINIT_KPROBE
else
ccflags-y += -DINIT_TP
endif

obj-$(CONFIG_FMAC) += fmac.o

KDIR := $(KDIR)
MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
CONFIG_H := $(PWD)/config.h

ccflags-y += -I$(srctree)/security/selinux -I$(srctree)/security/selinux/include
ccflags-y += -I$(MDIR)/include
ccflags-y += -I$(objtree)/security/selinux -include $(srctree)/include/uapi/asm-generic/errno.h

all:
    $(CONFIG_H)
	make -C $(KDIR) M=$(MDIR) modules
	
$(CONFIG_H):
	@echo "Running kernel-space function check..."
	@../scripts/check_funcs.sh $(CONFIG_H)