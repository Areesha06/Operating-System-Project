# Builds the project's own test programs into programs/bin/.
# Requires: gcc (sudo apt install build-essential)
CC ?= gcc
CFLAGS ?= -O1 -Wall -Wno-unused-result

all: bin/worker bin/mini_httpd bin/escape_probe

bin:
	mkdir -p bin

bin/worker: src/worker.c | bin
	$(CC) $(CFLAGS) -pthread $< -o $@

bin/mini_httpd: src/mini_httpd.c | bin
	$(CC) $(CFLAGS) $< -o $@

bin/escape_probe: src/escape_probe.c | bin
	$(CC) $(CFLAGS) $< -o $@

clean:
	rm -f bin/*

.PHONY: all clean
