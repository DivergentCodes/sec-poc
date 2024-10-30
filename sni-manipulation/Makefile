# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
BINARY_NAME_CLIENT=client
BINARY_NAME_SERVER=server
BINARY_NAME_FILTER=filter
DIST_DIR=dist
CERTS_DIR=server/certs

# OpenSSL parameters
OPENSSL=openssl
KEY_FILE=$(CERTS_DIR)/server.key
CERT_FILE=$(CERTS_DIR)/server.crt

# CLI parameters
HOST=localhost
PORT=8443
TARGET_HOST=https://$(HOST):$(PORT)
SNI_VALUE=spoofed.com

all: build

build: create-dirs generate-certs build-client build-server build-filter

create-dirs:
	mkdir -p $(DIST_DIR)
	mkdir -p $(CERTS_DIR)

generate-certs:
	$(OPENSSL) req -x509 -newkey rsa:4096 -keyout $(KEY_FILE) -out $(CERT_FILE) -days 365 -nodes -subj "/CN=localhost"

build-client:
	cd client && $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_CLIENT) main.go
	cd client && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_CLIENT)-linux-amd64 main.go

build-server:
	cd server && $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_SERVER) main.go
	cd server && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_SERVER)-linux-amd64 main.go

build-filter:
	cd filter && $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_FILTER) main.go
	cd filter && GOOS=linux GOARCH=amd64 $(GOBUILD) -o ../$(DIST_DIR)/$(BINARY_NAME_FILTER)-linux-amd64 main.go

clean:
	$(GOCLEAN)
	rm -rf $(DIST_DIR)
	rm -rf $(CERTS_DIR)

run-server:
	./$(DIST_DIR)/$(BINARY_NAME_SERVER) $(HOST) $(PORT)

run-client:
	./$(DIST_DIR)/$(BINARY_NAME_CLIENT) $(TARGET_HOST) $(SNI_VALUE)

run-filter:
	./$(DIST_DIR)/$(BINARY_NAME_FILTER) $(HOST) $(PORT) $(TARGET_HOST) $(SNI_VALUE)

.PHONY: all build create-dirs build-client build-server build-filter clean run-client run-server run-filter generate-certs
