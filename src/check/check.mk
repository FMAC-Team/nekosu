KDIR := $(KDIR)
PWD := $(shell pwd)

CHECK_FUNCS := vma_set_flags get_user_pages
CONFIG_H := $(PWD)/config.h
CHECK_PROGRAM := $(PWD)/function

all: $(CONFIG_H)

$(CHECK_PROGRAM): function.c
	@echo "Starting function check..."
	@$(MAKE) -C $(KDIR) M=$(PWD) modules >/dev/null 2>&1 || touch $(CHECK_PROGRAM)

$(CONFIG_H): $(CHECK_PROGRAM)
	@echo "Generating $(CONFIG_H) ..."
	@./$(CHECK_PROGRAM) > $(CONFIG_H) || echo "/* No functions detected */" > $(CONFIG_H)

clean:
	rm -f $(CONFIG_H) $(CHECK_PROGRAM)