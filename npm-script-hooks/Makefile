.PHONY: init publish clean

# Variables
CWD=$(shell pwd)
REGISTRY_URL=http://localhost:4873
REGISTRY_USER=bob
REGISTRY_PASS=hunter22
PACKAGES=pkg-a pkg-b pkg-c pkg-d-js pkg-d-rsh pkg-d-githook

# Start registry and publish packages
init: start-registry publish

# Start Verdaccio registry
start-registry:
	@echo "Starting Verdaccio registry..."
	cd $(CWD)/registry && npm install && npm start &
	@sleep 2  # Wait for registry to start

# Publish all packages
publish:
	@echo "Publishing packages to local registry..."
	@for pkg in $(PACKAGES); do \
		echo "Publishing $$pkg..."; \
		cd $(CWD)/$$pkg && npm publish || true; \
	done

# Clean up - stop registry and remove published packages
clean:
	@echo "Cleaning up..."
	@pkill -f verdaccio || true
	@rm -rf registry/storage
	@rm -rf registry/node_modules
	@rm -rf myapp/node_modules
	@rm myapp/package-lock.json
