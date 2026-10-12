CC ?= cc
CFLAGS ?= -O2 -Wall -Wextra

BIN = symfind

all: $(BIN)

$(BIN): src/symfind.c
	$(CC) $(CFLAGS) -o $@ src/symfind.c

clean:
	rm -f $(BIN)

install: $(BIN)
	install -D -m 755 $(BIN) $(DESTDIR)/usr/local/bin/$(BIN)

test: $(BIN)
	./tests/run.sh

.PHONY: all clean install test
