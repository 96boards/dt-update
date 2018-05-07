SUBDIRS := tools/dtbtool tools/dbootimg

.PHONY: all clean install

all clean install:
	@for dir in $(SUBDIRS); do \
		echo "=====$$dir====="; \
		$(MAKE) -C $$dir $@; \
	done
