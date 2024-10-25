# Go parameters
GOCMD=go
GOBUILD=$(GOCMD) build
GOCLEAN=$(GOCMD) clean
BINARY_NAME_CLIENT=client
BINARY_NAME_SERVER=server
DIST_DIR=dist
CERTS_DIR=$(DIST_DIR)/certs

# OpenSSL parameters
OPENSSL=openssl
KEY_FILE=$(CERTS_DIR)/server.key
CERT_FILE=$(CERTS_DIR)/server.crt

all: build

build: create-dirs generate-certs build-client build-server

create-dirs:
	mkdir -p $(DIST_DIR)
	mkdir -p $(CERTS_DIR)

generate-certs:
	$(OPENSSL) req -x509 -newkey rsa:4096 -keyout $(KEY_FILE) -out $(CERT_FILE) -days 365 -nodes -subj "/CN=localhost"

build-client:
	$(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME_CLIENT) client.go

build-server:
	$(GOBUILD) -o $(DIST_DIR)/$(BINARY_NAME_SERVER) server.go

clean:
	$(GOCLEAN)
	rm -rf $(DIST_DIR)

run-client:
	./$(DIST_DIR)/$(BINARY_NAME_CLIENT)

run-server:
	./$(DIST_DIR)/$(BINARY_NAME_SERVER)

.PHONY: all build create-dirs build-client build-server clean run-client run-server generate-certs
