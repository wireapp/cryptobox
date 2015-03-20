SHELL   := /usr/bin/env bash
VERSION := "0.0.1"
ARCH    := amd64
BUILD   ?= 1

all: compile

clean:
	cargo clean
	rm -rf test/target
	rm -f deb/usr/include/*.h
	rm -f deb/usr/lib/*.so

compile:
	cargo build

compile-release:
	cargo build --release

test: compile test-compile
	LD_LIBRARY_PATH=test/target valgrind --leak-check=yes --error-exitcode=1 test/target/main

test-compile:
	mkdir -p test/target
	cp target/debug/libcryptobox-*.so test/target/libcryptobox.so 2>/dev/null || true
	cp target/debug/libcryptobox-*.dylib test/target/libcryptobox.dylib 2>/dev/null || true
	$(CC) -std=c99 -Wall -g test/main.c -o test/target/main -I. -Ltest/target -lcryptobox

dist: compile-release
	mkdir -p deb/usr/include
	mkdir -p deb/usr/lib
	cp cbox.h deb/usr/include
	cp target/release/libcryptobox-*.so deb/usr/lib
	makedeb --name=cryptobox       \
			--version=$(VERSION)   \
			--debian-dir=deb       \
			--build=$(BUILD)       \
			--architecture=$(ARCH) \
			--output-dir=target/release
