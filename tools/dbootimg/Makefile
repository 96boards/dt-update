name = dbootimg

CFLAGS := -Wall

srcs = src/dbootimg.c src/puff.c
objs = $(srcs:%.c=%.o)

all:$(name)

$(name): $(objs)
	$(CC) $(objs) $(LDFLAGS) $(CFLAGS) -o $@

%.o : %.c
	$(CC) $(LDFLAGS) $(CFLAGS) -o $@ -c $<

clean:
	rm -R -f src/*~ src/*.o $(name)

install:
	cp $(name) $(DESTDIR)/bin/$(name)

uninstall:
	rm -f $(DESTDIR)/bin/$(name)
