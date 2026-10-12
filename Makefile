CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

BINS = symfind symtrace
OBJS = elfparse.o

all: $(BINS)

elfparse.o: src/elfparse.c src/elfparse.h
	$(CC) $(CFLAGS) -c -o $@ src/elfparse.c

symfind: src/symfind.c $(OBJS) src/elfparse.h
	$(CC) $(CFLAGS) -o $@ src/symfind.c $(OBJS)

symtrace: src/symtrace.c $(OBJS) src/elfparse.h
	$(CC) $(CFLAGS) -o $@ src/symtrace.c $(OBJS)

test: $(BINS)
	./tests/run.sh

clean:
	rm -f $(BINS) $(OBJS)

install: $(BINS)
	install -D -m 755 symfind $(DESTDIR)/usr/local/bin/symfind
	install -D -m 755 symtrace $(DESTDIR)/usr/local/bin/symtrace

.PHONY: all clean install test
