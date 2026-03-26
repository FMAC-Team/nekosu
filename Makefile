MDIR := $(realpath $(dir $(abspath $(lastword $(MAKEFILE_LIST)))))
IDIR := $(MDIR)/src/include
GEN_HEADER := $(MDIR)/scripts/autogenhead.py

include $(MDIR)/Kbuild

FMAC_HDRS := $(foreach obj,$(fmac-y),\
               $(IDIR)/$(patsubst src/%,%,$(obj:.o=.h)))

ifeq ($(KERNELRELEASE),)

.PHONY: all clean headers clean_headers

all: headers
	$(MAKE) -C $(KDIR) M=$(MDIR) IDIR=$(IDIR) modules

headers: $(FMAC_HDRS)
	@echo "Headers generation complete."

define make_header_rule
$(IDIR)/$(patsubst src/%,%,$(1:.o=.h)): $(MDIR)/$(1:.o=.c) $(GEN_HEADER)
	@mkdir -p $$(dir $$@)
	@echo "Generating $$@"
	python3 $(GEN_HEADER) $$< $$@
endef

$(foreach obj,$(fmac-y),$(eval $(call make_header_rule,$(obj))))

clean: clean_headers
	$(MAKE) -C $(KDIR) M=$(MDIR) clean

clean_headers:
	rm -f $(FMAC_HDRS)
	find $(IDIR) -type d -empty -delete 2>/dev/null || true

endif
