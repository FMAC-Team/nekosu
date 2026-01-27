KDIR := $(KDIR)
PWD := $(shell pwd)
CONFIG_H := $(PWD)/config.h

CHECK_FUNCS := vma_set_flags get_user_pages

all: $(CONFIG_H)

$(CONFIG_H): function.c
	@echo "Checking functions..."
	@$(MAKE) -C $(KDIR) M=$(PWD) modules >/dev/null 2>&1 && \
	    echo "#define HAVE_vma_set_flags 1" > $(CONFIG_H) || \
	    echo "/* No functions detected */" > $(CONFIG_H)

clean:
	rm -f $(CONFIG_H)