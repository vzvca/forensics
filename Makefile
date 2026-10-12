CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

BINS = symfind symtrace dwproto
OBJS = elfparse.o dwarg.o

all: $(BINS)

elfparse.o: src/elfparse.c src/elfparse.h
	$(CC) $(CFLAGS) -c -o $@ src/elfparse.c

dwarg.o: src/dwarg.c src/dwarg.h src/dwarf_consts.h src/prototypes.h
	$(CC) $(CFLAGS) -c -o $@ src/dwarg.c

symfind: src/symfind.c elfparse.o src/elfparse.h
	$(CC) $(CFLAGS) -o $@ src/symfind.c elfparse.o

symtrace: src/symtrace.c elfparse.o dwarg.o src/elfparse.h src/dwarg.h src/prototypes.h
	$(CC) $(CFLAGS) -o $@ src/symtrace.c elfparse.o dwarg.o

dwproto: src/dwproto.c dwarg.o src/dwarg.h src/prototypes.h
	$(CC) $(CFLAGS) -o $@ src/dwproto.c dwarg.o

test: $(BINS)
	./tests/run.sh

clean:
	rm -f $(BINS) $(OBJS)

install: $(BINS)
	install -D -m 755 symfind $(DESTDIR)/usr/local/bin/symfind
	install -D -m 755 symtrace $(DESTDIR)/usr/local/bin/symtrace
	install -D -m 755 dwproto $(DESTDIR)/usr/local/bin/dwproto

.PHONY: all clean install test
