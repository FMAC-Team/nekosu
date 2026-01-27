KDIR ?= /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)
CONFIG_H := $(PWD)/config.h

CHECK_FUNCS := vma_set_flags get_user_pages

all: $(CONFIG_H)

$(CONFIG_H):
	@echo "Checking functions..."
	@tmp_code="$$(echo '#include <linux/module.h>'; \
	             echo '#include <linux/mm.h>'; \
	             for f in $(CHECK_FUNCS); do \
	                 echo "static void check_$$f(void) { (void)$$f; }"; \
	             done)"; \
	  echo "$$tmp_code" | $(CC) -Wall -Werror -xc - -c -o /dev/null >/dev/null 2>&1; \
	  if [ $$? -eq 0 ]; then \
	      for f in $(CHECK_FUNCS); do \
	          echo "#define HAVE_$$f 1"; \
	      done > $(CONFIG_H); \
	  else \
	      echo "/* No functions detected */" > $(CONFIG_H); \
	  fi

clean:
	rm -f $(CONFIG_H)