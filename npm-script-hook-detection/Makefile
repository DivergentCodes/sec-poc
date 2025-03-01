BINARY_NAME=ls-npm-hooks
GO=go

.PHONY: all build clean test

all: build

build:
	$(GO) build -o $(BINARY_NAME) main.go

clean:
	$(GO) clean
	rm -f $(BINARY_NAME)

test:
	$(GO) test ./...