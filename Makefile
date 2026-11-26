# Top-level build (Linux only). Needs gcc and libseccomp-dev.
#   make            build test programs + seccomp launcher
#   make clean      remove built binaries
CC ?= gcc
CFLAGS ?= -O1 -Wall -Wno-unused-result

all: programs enforce/bin/seccomp_launcher

programs:
	$(MAKE) -C programs

enforce/bin/seccomp_launcher: enforce/src/seccomp_launcher.c
	mkdir -p enforce/bin
	$(CC) $(CFLAGS) $< -o $@ -lseccomp

clean:
	$(MAKE) -C programs clean
	rm -f enforce/bin/seccomp_launcher

.PHONY: all programs clean
