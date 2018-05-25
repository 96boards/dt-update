SUBDIRS := tools/dtbtool tools/dbootimg
DTS = $(wildcard scripts/*/overlays/*.dts)
DTBS = $(DTS:.dts=.dtbo)

.PHONY: all clean install

all clean install:
	@for dir in $(SUBDIRS); do \
		echo "=====$$dir====="; \
		$(MAKE) -C $$dir $@; \
	done

dtbs : $(DTBS)

maintainer-clean : clean
	$(RM) $(DTBS)

%.dtbo : %.dts
	dtc -Wno-avoid_default_addr_size -Wno-avoid_unnecessary_addr_size \
	    -Wno-reg_format -Wno-unit_address_vs_reg -Odtb\
	    -o $@ \
	    -@ $<
