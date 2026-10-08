CC     ?= gcc
CFLAGS ?= -O2 -Wall -Wextra -std=c11

SRC = src/main.c src/pe.c src/rich.c src/info.c src/report.c
HDR = $(wildcard src/*.h)

build/pewalk: $(SRC) $(HDR)
	@mkdir -p build
	$(CC) $(CFLAGS) -o $@ $(SRC) -lm

clean:
	rm -rf build

.PHONY: clean
