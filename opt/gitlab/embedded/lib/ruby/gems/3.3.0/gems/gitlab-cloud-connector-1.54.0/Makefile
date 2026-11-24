# Makefile at the project root

# Directories
RUBY_DIR := $(shell pwd)
ROOT_DIR := ${RUBY_DIR}/../..

# Assets
ASSETS := config LICENSE CONTRIBUTING.md

.PHONY: build
build: copy-assets
	@echo "Building Ruby gem..."
	@gem build gitlab-cloud-connector.gemspec
	@echo "Ruby gem built successfully."
	@make clean

.PHONY: copy-assets
copy-assets:
	@echo "Copying assets to Ruby gem directory..."
    # Ensure the target config directory is removed
	@if [ -d "${RUBY_DIR}/config" ]; then rm -rf ${RUBY_DIR}/config; fi
    # Copy required assets
	@mkdir -p ${RUBY_DIR}/config
	@cp -r ${ROOT_DIR}/config/* ${RUBY_DIR}/config
	@cp ${ROOT_DIR}/LICENSE ${RUBY_DIR}/
	@cp ${ROOT_DIR}/CONTRIBUTING.md ${RUBY_DIR}/

.PHONY: clean
clean:
	@echo "Cleaning up Ruby gem directory..."
	@rm -rf ${RUBY_DIR}/config
	@rm -f ${RUBY_DIR}/LICENSE
	@rm -f ${RUBY_DIR}/CONTRIBUTING.md