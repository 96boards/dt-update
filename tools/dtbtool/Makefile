include libfdt/Makefile.libfdt

name = dtbtool
libfdt-path = libfdt

CFLAGS := -Wall
CFLAGS += -I$(libfdt-path)/

libfdt-sharedlib = $(libfdt-path)/libfdt-sharedlib.a
libfdt-objs = $(LIBFDT_SRCS:%.c=$(libfdt-path)/%.o)

srcs = src/$(name).c
objs = $(srcs:%.c=%.o) $(libfdt-sharedlib)

all:$(name)

$(name): $(objs)
	$(CC) $(objs) $(LDFLAGS) $(CFLAGS) -o $@

%.o : %.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ -c $<

$(libfdt-sharedlib): $(libfdt-objs)
	$(AR) rcs $@ $^

clean:
	rm -R -f src/*~ src/*.o $(name) $(libfdt-path)/*.o $(libfdt-path)/*.a

install:
	cp $(name) $(DESTDIR)/bin/$(name)

uninstall:
	rm -f $(DESTDIR)/bin/$(name)
