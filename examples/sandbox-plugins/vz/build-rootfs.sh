#!/bin/bash
# build-rootfs.sh - Create a developer-focused rootfs for Deputy VZ sandbox
#
# This script creates an ext4 rootfs image with:
# - Ubuntu 24.04 LTS base
# - Go toolchain (latest stable)
# - Node.js and npm
# - Python 3 with pip
# - Build essentials (gcc, make, git)
# - Deputy init script for command execution
#
# Usage:
#   ./build-rootfs.sh                      # Build default rootfs (2GB)
#   ./build-rootfs.sh --size 4096          # Build larger rootfs (4GB)
#   ./build-rootfs.sh --minimal            # Minimal rootfs (no dev tools)
#   ./build-rootfs.sh --output /path/to    # Custom output directory
#
# Requirements:
#   - Docker (required for creating ext4 on macOS)
#   - ~3GB free disk space
#   - Internet connection for downloading packages

set -euo pipefail

# Defaults
OUTPUT_DIR="${HOME}/.deputy/vz"
ROOTFS_SIZE_MB=2048
MINIMAL=false
GO_VERSION="1.25.5"  # Match deputy's go.mod version
NODE_VERSION="22"    # LTS

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --size)
            ROOTFS_SIZE_MB="$2"
            shift 2
            ;;
        --minimal)
            MINIMAL=true
            shift
            ;;
        --output)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --go-version)
            GO_VERSION="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --size MB        Rootfs size in MB (default: 2048)"
            echo "  --minimal        Build minimal rootfs without dev tools"
            echo "  --output DIR     Output directory (default: ~/.deputy/vz)"
            echo "  --go-version VER Go version to install (default: ${GO_VERSION})"
            echo "  --help           Show this help"
            exit 0
            ;;
        *)
            echo "Unknown option: $1"
            exit 1
            ;;
    esac
done

# Create output directory
mkdir -p "${OUTPUT_DIR}"

echo "==> Building Deputy VZ rootfs"
echo "    Output: ${OUTPUT_DIR}"
echo "    Size: ${ROOTFS_SIZE_MB}MB"
echo "    Minimal: ${MINIMAL}"

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required to create ext4 filesystems on macOS"
    echo "Install Docker Desktop from https://docker.com"
    exit 1
fi

# Check if kernel exists, download if not
if [[ ! -f "${OUTPUT_DIR}/vmlinuz" ]]; then
    echo "==> Downloading Ubuntu kernel..."
    curl -L -o "${OUTPUT_DIR}/vmlinuz.gz" \
        "https://cloud-images.ubuntu.com/releases/24.04/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic"
    gunzip -f "${OUTPUT_DIR}/vmlinuz.gz"
    echo "    Downloaded kernel: ${OUTPUT_DIR}/vmlinuz"
fi

# Download root tarball if not present
ROOTFS_TAR="${OUTPUT_DIR}/ubuntu-24.04-server-cloudimg-arm64-root.tar.xz"
if [[ ! -f "${ROOTFS_TAR}" ]]; then
    echo "==> Downloading Ubuntu root filesystem tarball..."
    curl -L -o "${ROOTFS_TAR}" \
        "https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64-root.tar.xz"
    echo "    Downloaded: ${ROOTFS_TAR}"
fi

# Create the deputy-init script
DEPUTY_INIT_SCRIPT='#!/bin/bash
# deputy-init - Init script for Deputy VZ sandbox

# Set PATH immediately - this must be first for any commands to work
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin"

# Mount essential filesystems FIRST - needed for /proc/cmdline
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null

# Setup environment for development tools
export HOME="/root"
export GOPATH="/root/go"
export GOCACHE="/tmp/go-cache"
export GOMODCACHE="/tmp/go-mod-cache"
export npm_config_cache="/tmp/npm-cache"
export TERM="xterm-256color"

# Source any additional environment setup
if [ -f /etc/profile.d/deputy-dev.sh ]; then
    . /etc/profile.d/deputy-dev.sh
fi

# Get the base64-encoded command from kernel cmdline
# Note: /proc must be mounted before this
CMD_BASE64=""
WORKDIR=""
if [ -f /proc/cmdline ]; then
    read -r CMDLINE < /proc/cmdline
    for param in $CMDLINE; do
        case "$param" in
            deputy.cmd=*)
                CMD_BASE64="${param#deputy.cmd=}"
                ;;
            deputy.workdir=*)
                WORKDIR="${param#deputy.workdir=}"
                ;;
        esac
    done
fi

if [ -z "$CMD_BASE64" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: No command provided (deputy.cmd not found in kernel cmdline)"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    exec /sbin/poweroff -f
fi

# Decode the command
CMD_DECODED=$(/usr/bin/base64 -d <<< "$CMD_BASE64" 2>&1)
DECODE_EXIT=$?

if [ $DECODE_EXIT -ne 0 ] || [ -z "$CMD_DECODED" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: Failed to decode command"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    exec /sbin/poweroff -f
fi

# Change to workspace directory if specified
if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
    cd "$WORKDIR"
fi

# Signal start of output
echo "<<<DEPUTY_OUTPUT_START>>>"
echo "<<<DEPUTY_STDOUT>>>"

# Execute the command directly, letting stdout and stderr flow naturally
eval "$CMD_DECODED" 2>&1
EXIT_CODE=$?

# Signal end of output and report exit code
echo "<<<DEPUTY_OUTPUT_END>>>"
echo "<<<DEPUTY_EXIT_CODE:${EXIT_CODE}>>>"

# Shutdown the VM
exec /sbin/poweroff -f'

# Write deputy-init to output directory for Docker to pick up
echo "${DEPUTY_INIT_SCRIPT}" > "${OUTPUT_DIR}/deputy-init"
chmod +x "${OUTPUT_DIR}/deputy-init"

# Build rootfs using Docker
echo "==> Creating rootfs image with Docker..."

docker run --rm --privileged \
    -v "${OUTPUT_DIR}:/output" \
    -e ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB}" \
    -e MINIMAL="${MINIMAL}" \
    -e GO_VERSION="${GO_VERSION}" \
    -e NODE_VERSION="${NODE_VERSION}" \
    ubuntu:24.04 \
    bash -c '
set -ex

OUTPUT_DIR="/output"

# Install tools needed for image creation
apt-get update
apt-get install -y xz-utils e2fsprogs curl

# Create disk image
echo "Creating ${ROOTFS_SIZE_MB}MB disk image..."
dd if=/dev/zero of="${OUTPUT_DIR}/rootfs.img" bs=1M count="${ROOTFS_SIZE_MB}"
mkfs.ext4 -F "${OUTPUT_DIR}/rootfs.img"

# Mount the image
mkdir -p /mnt/rootfs
mount -o loop "${OUTPUT_DIR}/rootfs.img" /mnt/rootfs

# Extract Ubuntu root filesystem
echo "Extracting Ubuntu base..."
tar -xJf "${OUTPUT_DIR}/ubuntu-24.04-server-cloudimg-arm64-root.tar.xz" -C /mnt/rootfs

# Ensure essential directories exist
mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run,workspace}

if [ "${MINIMAL}" != "true" ]; then
    echo "Installing developer tools..."

    # Set up DNS resolution for the chroot
    # Ubuntu cloud images have a symlink for resolv.conf, so we remove it first
    rm -f /mnt/rootfs/etc/resolv.conf
    cp /etc/resolv.conf /mnt/rootfs/etc/resolv.conf

    # Install packages via chroot
    chroot /mnt/rootfs /bin/bash -c "
export DEBIAN_FRONTEND=noninteractive
export PATH=/usr/local/go/bin:\$PATH

# Update package lists
apt-get update

# Install build essentials and common tools
apt-get install -y --no-install-recommends \
    build-essential \
    git \
    curl \
    wget \
    ca-certificates \
    jq \
    unzip \
    openssh-client

# Clean up apt cache to save space
apt-get clean
rm -rf /var/lib/apt/lists/*
"

    # Install Go (outside chroot, direct to rootfs)
    echo "Installing Go ${GO_VERSION}..."
    curl -L "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" | \
        tar -xz -C /mnt/rootfs/usr/local/

    # Create Go symlinks
    ln -sf /usr/local/go/bin/go /mnt/rootfs/usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /mnt/rootfs/usr/local/bin/gofmt

    # Install Node.js LTS (using prebuilt binaries)
    echo "Installing Node.js ${NODE_VERSION}..."
    # Get the exact version (e.g., v22.22.0 from node-v22.22.0)
    NODE_FULL_VERSION=$(curl -s https://nodejs.org/dist/latest-v${NODE_VERSION}.x/ | grep -oE "node-v${NODE_VERSION}\.[0-9]+\.[0-9]+-linux-arm64" | head -1 | sed "s/-linux-arm64//")
    # Extract just the version number (v22.22.0 from node-v22.22.0)
    NODE_VER=$(echo "${NODE_FULL_VERSION}" | sed "s/node-//")
    if [ -n "${NODE_VER}" ]; then
        echo "Downloading Node.js ${NODE_VER}..."
        curl -L "https://nodejs.org/dist/${NODE_VER}/${NODE_FULL_VERSION}-linux-arm64.tar.xz" | \
            tar -xJ -C /mnt/rootfs/usr/local/ --strip-components=1
    else
        echo "Warning: Could not determine Node.js version, skipping"
    fi

    # Create environment setup script
    cat > /mnt/rootfs/etc/profile.d/deputy-dev.sh << 'ENVSCRIPT'
# Deputy development environment
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin:$PATH"
export GOPATH="/root/go"
export GOCACHE="/tmp/go-cache"
export GOMODCACHE="/tmp/go-mod-cache"
export npm_config_cache="/tmp/npm-cache"
ENVSCRIPT
    chmod +x /mnt/rootfs/etc/profile.d/deputy-dev.sh
fi

# Install deputy-init from the pre-created file
echo "Installing deputy-init..."
cp "${OUTPUT_DIR}/deputy-init" /mnt/rootfs/deputy-init
chmod +x /mnt/rootfs/deputy-init

# Unmount
umount /mnt/rootfs

echo "==> SUCCESS: Created rootfs.img"
'

# Clean up temporary files
rm -f "${OUTPUT_DIR}/deputy-init"

# Verify outputs
echo ""
echo "==> Build complete!"
echo ""
ls -lh "${OUTPUT_DIR}/vmlinuz" "${OUTPUT_DIR}/rootfs.img"

echo ""
echo "To test the setup:"
echo "  deputy exec --runtime plugin --plugin vz -- uname -a"
echo "  deputy exec --runtime plugin --plugin vz -- go version"
echo "  deputy exec --runtime plugin --plugin vz -- node --version"
echo ""
echo "For Deputy development:"
echo "  deputy exec --runtime plugin --plugin vz -- go build ./..."
echo "  deputy exec --runtime plugin --plugin vz -- go test ./..."
