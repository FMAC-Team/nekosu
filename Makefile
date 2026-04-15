MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
IDIR := $(MDIR)/src/include

include $(MDIR)/Kbuild

ifeq ($(KERNELRELEASE),)

.PHONY: all clean

all:
	$(MAKE) -C $(KDIR) M=$(MDIR) IDIR=$(IDIR) modules


clean:
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

endif
