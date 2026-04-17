nksu-y += src/anonfd.o src/nksu.o src/privilege.o src/tracepoint.o src/ioctl.o src/uid_cap.o src/manager.o

nksu-y += src/selinux/rule.o src/selinux/selinux.o src/selinux/policy.o src/selinux/domain.o


obj-$(CONFIG_NKSU) += nksu.o

ifeq($(CONFIG_NKSU_DEBUG),y)
	ccflags-y += -DCONFIG_NKSU_DEBUG=1
endif

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
CFLAGS_src/tracepoint.o  := -O3
