BINARY_NAME=ls-npm-hooks
GO=go

.PHONY: all build clean test

all: build

build:
	$(GO) build -o dist/$(BINARY_NAME) main.go

clean:
	$(GO) clean
	rm -f dist/$(BINARY_NAME)

test:
	$(GO) test ./...