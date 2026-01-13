# Makefile for deputy-sandbox-vz plugin
#
# Usage:
#   make build       - Build the plugin
#   make install     - Build, sign, and install to ~/go/bin
#   make rootfs      - Build developer rootfs with Go/Node/Python
#   make rootfs-minimal - Build minimal rootfs (no dev tools)
#   make setup       - Download kernel + build rootfs (full setup)
#   make test        - Run plugin tests
#   make clean       - Remove build artifacts
#
# For Deputy development:
#   make setup       - One-time setup (kernel + rootfs with Go)
#   make install     - Install plugin
#   deputy exec --runtime plugin --plugin vz -- go test ./...

PLUGIN_NAME := deputy-sandbox-vz
INSTALL_DIR := $(HOME)/go/bin
ASSET_DIR := $(HOME)/.deputy/vz

GO_VERSION ?= 1.24.3
NODE_VERSION ?= 22
ROOTFS_SIZE ?= 2048

.PHONY: build install sign rootfs rootfs-minimal setup test clean help

help:
	@echo "Deputy VZ Sandbox Plugin"
	@echo ""
	@echo "Quick start:"
	@echo "  make setup     - Download assets and build rootfs (one-time)"
	@echo "  make install   - Build and install plugin"
	@echo ""
	@echo "Targets:"
	@echo "  build          - Build the plugin binary"
	@echo "  install        - Build, sign, and install to ~/go/bin"
	@echo "  sign           - Sign plugin with virtualization entitlements"
	@echo "  rootfs         - Build rootfs with Go/Node developer tools"
	@echo "  rootfs-minimal - Build minimal rootfs (Ubuntu base only)"
	@echo "  setup          - Full setup (kernel + developer rootfs)"
	@echo "  test           - Run plugin unit tests"
	@echo "  clean          - Remove build artifacts"
	@echo ""
	@echo "Variables:"
	@echo "  GO_VERSION     - Go version for rootfs (default: $(GO_VERSION))"
	@echo "  NODE_VERSION   - Node.js version for rootfs (default: $(NODE_VERSION))"
	@echo "  ROOTFS_SIZE    - Rootfs size in MB (default: $(ROOTFS_SIZE))"
	@echo ""
	@echo "After setup, test with:"
	@echo "  deputy exec --runtime plugin --plugin vz -- go version"

build: $(PLUGIN_NAME)

$(PLUGIN_NAME): main.go go.mod go.sum
	@echo "==> Building $(PLUGIN_NAME)..."
	go build -o $(PLUGIN_NAME) .

sign: $(PLUGIN_NAME)
	@echo "==> Signing with virtualization entitlements..."
	codesign --entitlements entitlements.plist --force --sign - $(PLUGIN_NAME)

install: build sign
	@echo "==> Installing to $(INSTALL_DIR)..."
	@mkdir -p $(INSTALL_DIR)
	cp $(PLUGIN_NAME) $(INSTALL_DIR)/
	@echo "==> Installed: $(INSTALL_DIR)/$(PLUGIN_NAME)"

$(ASSET_DIR)/vmlinuz:
	@echo "==> Downloading Ubuntu kernel..."
	@mkdir -p $(ASSET_DIR)
	curl -L -o $(ASSET_DIR)/vmlinuz.gz \
		"https://cloud-images.ubuntu.com/releases/24.04/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic"
	gunzip -f $(ASSET_DIR)/vmlinuz.gz
	@echo "==> Downloaded: $(ASSET_DIR)/vmlinuz"

kernel: $(ASSET_DIR)/vmlinuz

rootfs:
	@echo "==> Building developer rootfs (Go $(GO_VERSION), Node $(NODE_VERSION))..."
	./build-rootfs.sh --size $(ROOTFS_SIZE) --go-version $(GO_VERSION) --output $(ASSET_DIR)

rootfs-minimal:
	@echo "==> Building minimal rootfs..."
	./build-rootfs.sh --minimal --size 1024 --output $(ASSET_DIR)

setup: kernel rootfs install
	@echo ""
	@echo "==> Setup complete!"
	@echo ""
	@echo "Test with:"
	@echo "  deputy exec --runtime plugin --plugin vz -- uname -a"
	@echo "  deputy exec --runtime plugin --plugin vz -- go version"
	@echo ""
	@echo "For Deputy development:"
	@echo "  deputy exec --runtime plugin --plugin vz -- go build ./..."
	@echo "  deputy exec --runtime plugin --plugin vz -- go mod tidy"

test:
	go test -v ./...

clean:
	rm -f $(PLUGIN_NAME)
	@echo "==> Cleaned build artifacts"
	@echo "Note: Assets in $(ASSET_DIR) not removed. Use 'rm -rf $(ASSET_DIR)' to remove."

# Verify setup
verify:
	@echo "==> Checking setup..."
	@test -f $(INSTALL_DIR)/$(PLUGIN_NAME) || (echo "ERROR: Plugin not installed. Run 'make install'" && exit 1)
	@test -f $(ASSET_DIR)/vmlinuz || (echo "ERROR: Kernel not found. Run 'make kernel'" && exit 1)
	@test -f $(ASSET_DIR)/rootfs.img || (echo "ERROR: Rootfs not found. Run 'make rootfs'" && exit 1)
	@echo "==> All components present"
	@ls -lh $(ASSET_DIR)/vmlinuz $(ASSET_DIR)/rootfs.img
