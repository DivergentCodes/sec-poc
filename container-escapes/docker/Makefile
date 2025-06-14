.PHONY: build-base build run run-default run-user run-privileged clean

# Build the base image
build-base:
	docker build -t container-escape-base:latest -f Dockerfile.base .

# Build all images
build: build-base
	docker compose build

# Run all containers
run: build
	docker compose up -it

# Run specific containers
run-default: build
	docker compose run -it --rm default

run-user: build
	docker compose run -it --rm user

run-privileged: build
	docker compose run -it --rm privileged

# Clean up
clean:
	docker compose down
	docker rmi container-escape-base:latest || true
	docker rmi container-escape-default:latest || true
	docker rmi container-escape-user:latest || true
	docker rmi container-escape-privileged:latest || true