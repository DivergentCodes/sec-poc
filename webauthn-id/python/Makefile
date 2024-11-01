.PHONY: install start clean

# Directory structure
BASE_DIR := $(shell pwd)
VENV := $(BASE_DIR)/.venv
PYTHON := $(VENV)/bin/python
PIP := $(VENV)/bin/pip

# Default target
all: install

# Create virtual environment and install dependencies
install: $(VENV)
	$(PIP) install flask webauthn

# Create virtual environment if it doesn't exist
$(VENV):
	python3 -m venv $(VENV)

# Start the application
start:
	$(PYTHON) app.py

# Clean up virtual environment and cache files
clean:
	rm -rf $(VENV)
	find $(BASE_DIR) -type d -name "__pycache__" -exec rm -rf {} +
	find $(BASE_DIR) -type f -name "*.pyc" -delete