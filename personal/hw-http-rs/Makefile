.PHONY: all build run

all: build install


build:
	cargo build

install:
	cargo install --path .

run: build
	./target/debug/http_server_rs --files www/
