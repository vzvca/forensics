CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

BINS = symfind symtrace symhijack dwproto
OBJS = elfparse.o dwarg.o common_pt.o common_target.o common_remote.o

all: $(BINS)

elfparse.o: src/elfparse.c src/elfparse.h
	$(CC) $(CFLAGS) -c -o $@ src/elfparse.c

dwarg.o: src/dwarg.c src/dwarg.h src/dwarf_consts.h src/prototypes.h
	$(CC) $(CFLAGS) -c -o $@ src/dwarg.c

symfind: src/symfind.c elfparse.o src/elfparse.h
	$(CC) $(CFLAGS) -o $@ src/symfind.c elfparse.o

symtrace: src/symtrace.c elfparse.o dwarg.o common_target.o common_pt.o src/elfparse.h src/dwarg.h src/prototypes.h src/common/target.h src/common/pt.h
	$(CC) $(CFLAGS) -Isrc -o $@ src/symtrace.c elfparse.o dwarg.o common_target.o common_pt.o

dwproto: src/dwproto.c dwarg.o src/dwarg.h src/prototypes.h
	$(CC) $(CFLAGS) -o $@ src/dwproto.c dwarg.o

common_pt.o: src/common/pt.c src/common/pt.h
	$(CC) $(CFLAGS) -Isrc -c -o $@ src/common/pt.c

common_target.o: src/common/target.c src/common/target.h src/elfparse.h
	$(CC) $(CFLAGS) -Isrc -c -o $@ src/common/target.c

common_remote.o: src/common/remote.c src/common/remote.h src/common/pt.h
	$(CC) $(CFLAGS) -Isrc -c -o $@ src/common/remote.c

symhijack: src/symhijack.c common_pt.o common_target.o common_remote.o elfparse.o \
           src/common/pt.h src/common/target.h src/common/remote.h src/elfparse.h
	$(CC) $(CFLAGS) -Isrc -o $@ src/symhijack.c common_pt.o common_target.o \
	       common_remote.o elfparse.o

test: $(BINS)
	./tests/run.sh

clean:
	rm -f $(BINS) $(OBJS)

install: $(BINS)
	install -D -m 755 symfind $(DESTDIR)/usr/local/bin/symfind
	install -D -m 755 symtrace $(DESTDIR)/usr/local/bin/symtrace
	install -D -m 755 symhijack $(DESTDIR)/usr/local/bin/symhijack
	install -D -m 755 dwproto $(DESTDIR)/usr/local/bin/dwproto

.PHONY: all clean install test
