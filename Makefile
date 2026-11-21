GO ?= go
APP_NAME ?= homepki
APP_CMD ?= ./cmd/homepki
DIST_DIR ?= dist
TARGET_OS ?= linux
TARGET_ARCH ?= arm64
RELEASE_BINARY = $(APP_NAME)-$(TARGET_OS)-$(TARGET_ARCH)
INSTALLER_DIR = $(DIST_DIR)/installer-$(TARGET_OS)-$(TARGET_ARCH)
SOURCE_ARCHIVE = $(DIST_DIR)/$(APP_NAME)-$(VERSION)-source.tar.gz

VERSION ?= dev
COMMIT ?= $(shell git --no-pager rev-parse --short HEAD 2>/dev/null || echo unknown)
BUILD_DATE ?= $(shell date -u +"%Y-%m-%dT%H:%M:%SZ")
LDFLAGS := -X 'main.version=$(VERSION)' -X 'main.commit=$(COMMIT)' -X 'main.buildDate=$(BUILD_DATE)'

.PHONY: generate test lint build source-package raspberry-pi-image cross-build cross-build-amd64 cross-build-platform \
	appliance-package appliance-package-amd64 appliance-package-platform \
	appliance-installer-package appliance-installer-package-amd64 appliance-installer-package-platform

generate:
	$(GO) generate ./...

test:
	$(GO) test ./...

lint:
	$(GO) vet ./...

build:
	mkdir -p $(DIST_DIR)
	$(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(APP_NAME) $(APP_CMD)

source-package:
	mkdir -p $(DIST_DIR)
	git archive --format=tar.gz --prefix=$(APP_NAME)-$(VERSION)/ -o $(SOURCE_ARCHIVE) HEAD

raspberry-pi-image: appliance-installer-package
	./scripts/build-raspberry-pi-image.sh

cross-build:
	$(MAKE) cross-build-platform TARGET_OS=linux TARGET_ARCH=arm64

cross-build-amd64:
	$(MAKE) cross-build-platform TARGET_OS=linux TARGET_ARCH=amd64

cross-build-platform:
	mkdir -p $(DIST_DIR)
	GOOS=$(TARGET_OS) GOARCH=$(TARGET_ARCH) CGO_ENABLED=0 $(GO) build -ldflags "$(LDFLAGS)" -o $(DIST_DIR)/$(RELEASE_BINARY) $(APP_CMD)

appliance-package:
	$(MAKE) appliance-package-platform TARGET_OS=linux TARGET_ARCH=arm64

appliance-package-amd64:
	$(MAKE) appliance-package-platform TARGET_OS=linux TARGET_ARCH=amd64

appliance-package-platform: cross-build-platform
	mkdir -p $(DIST_DIR)
	tar -czf $(DIST_DIR)/$(RELEASE_BINARY).tar.gz -C $(DIST_DIR) $(RELEASE_BINARY)

appliance-installer-package:
	$(MAKE) appliance-installer-package-platform TARGET_OS=linux TARGET_ARCH=arm64

appliance-installer-package-amd64:
	$(MAKE) appliance-installer-package-platform TARGET_OS=linux TARGET_ARCH=amd64

appliance-installer-package-platform: cross-build-platform
	mkdir -p $(INSTALLER_DIR)/migrations
	cp scripts/install.sh $(INSTALLER_DIR)/install.sh
	cp configs/appliance.example.yaml $(INSTALLER_DIR)/appliance.example.yaml
	cp configs/avahi-homepki.service $(INSTALLER_DIR)/avahi-homepki.service
	cp migrations/*.sql $(INSTALLER_DIR)/migrations/
	cp $(DIST_DIR)/$(RELEASE_BINARY) $(INSTALLER_DIR)/$(APP_NAME)
	printf '%s/%s\n' '$(TARGET_OS)' '$(TARGET_ARCH)' > $(INSTALLER_DIR)/platform
	chmod +x $(INSTALLER_DIR)/install.sh
	tar -czf $(DIST_DIR)/$(APP_NAME)-installer-$(TARGET_OS)-$(TARGET_ARCH).tar.gz -C $(INSTALLER_DIR) install.sh appliance.example.yaml avahi-homepki.service migrations platform $(APP_NAME)
