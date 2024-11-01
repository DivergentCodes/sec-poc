.PHONY: build clean

# Binary name
BINARY_NAME=webauthn-checker
DIST_DIR=dist

# Build the application
build:
	mkdir -p $(DIST_DIR)
	go build -o $(DIST_DIR)/$(BINARY_NAME) .

# Clean build artifacts
clean:
	go clean
	rm -rf $(DIST_DIR)

# Run the application
run: build
	./$(DIST_DIR)/$(BINARY_NAME)