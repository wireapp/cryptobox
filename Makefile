SHELL := /usr/bin/env bash

all: compile

clean:
	cargo clean
	rm -rf test/target

compile:
	cargo build

test: compile test-compile
	LD_LIBRARY_PATH=test/target valgrind --leak-check=yes --error-exitcode=1 test/target/main

test-compile:
	mkdir -p test/target
	cp target/libcryptobox-*.so test/target/libcryptobox.so 2>/dev/null || true
	cp target/libcryptobox-*.dylib test/target/libcryptobox.dylib 2>/dev/null || true
	$(CC) -std=c99 -Wall -g test/main.c -o test/target/main -I. -Ltest/target -lcryptobox
