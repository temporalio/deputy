#!/bin/bash
# build-alpine-rootfs.sh - Create an Alpine-based rootfs for Deputy VZ sandbox
#
# Alpine rootfs with virtiofs support (from Lima's Alpine kernel).
# Much smaller and faster than Ubuntu, with full virtiofs for workspace mounting.
#
# Credits:
# - Lima project (https://github.com/lima-vm/lima) for the Alpine ISO with virtiofs kernel
# - Alpine Linux (https://alpinelinux.org) for the lightweight distribution
#
# Usage:
#   ./build-alpine-rootfs.sh                      # Build default rootfs
#   ./build-alpine-rootfs.sh --size 1024          # Custom size (MB)
#   ./build-alpine-rootfs.sh --minimal            # Minimal (no dev tools)
#   ./build-alpine-rootfs.sh --output /path/to    # Custom output directory
#
# Requirements:
#   - Docker (for creating ext4 on macOS)
#   - ~1GB free disk space

set -euo pipefail

# Defaults
OUTPUT_DIR="${HOME}/.deputy/vz/alpine"
ROOTFS_SIZE_MB=8192  # 8GB to accommodate Go toolchain downloads and large project builds
MINIMAL=false
ALPINE_VERSION="3.23"
GO_VERSION="1.23.5"
NODE_VERSION="22"

# Lima Alpine ISO URL (has kernel with virtiofs support and matching modules)
LIMA_ALPINE_VERSION="0.2.47"
LIMA_ALPINE_ISO_URL="https://github.com/lima-vm/alpine-lima/releases/download/v${LIMA_ALPINE_VERSION}/alpine-lima-std-${ALPINE_VERSION}.0-aarch64.iso"

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
            echo "  --size MB        Rootfs size in MB (default: 1024)"
            echo "  --minimal        Build minimal rootfs without dev tools"
            echo "  --output DIR     Output directory (default: ~/.deputy/vz/alpine)"
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

mkdir -p "${OUTPUT_DIR}"

echo "==> Building Deputy VZ Alpine rootfs"
echo "    Output: ${OUTPUT_DIR}"
echo "    Size: ${ROOTFS_SIZE_MB}MB"
echo "    Minimal: ${MINIMAL}"

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required to create ext4 filesystems on macOS"
    exit 1
fi

# Check for bsdtar (needed to extract ISO)
if ! command -v bsdtar &> /dev/null; then
    echo "ERROR: bsdtar is required (should be available on macOS)"
    exit 1
fi

# Download Lima Alpine ISO if not present (contains kernel + matching modules)
LIMA_ISO="${OUTPUT_DIR}/../alpine-lima.iso"
if [[ ! -f "${LIMA_ISO}" ]]; then
    echo "==> Downloading Lima Alpine ISO (has virtiofs kernel + modules)..."
    curl -L -o "${LIMA_ISO}" "${LIMA_ALPINE_ISO_URL}"
fi

# Extract kernel and initramfs from ISO
echo "==> Extracting kernel, initramfs and modules from Lima Alpine ISO..."
TMPDIR=$(mktemp -d)
bsdtar -xf "${LIMA_ISO}" -C "${TMPDIR}" boot/vmlinuz-virt boot/initramfs-virt boot/modloop-virt
cp "${TMPDIR}/boot/vmlinuz-virt" "${OUTPUT_DIR}/vmlinuz"
cp "${TMPDIR}/boot/initramfs-virt" "${OUTPUT_DIR}/initrd.img"
cp "${TMPDIR}/boot/modloop-virt" "${OUTPUT_DIR}/modloop-virt"
rm -rf "${TMPDIR}"
echo "    Kernel: ${OUTPUT_DIR}/vmlinuz"
echo "    Initrd: ${OUTPUT_DIR}/initrd.img"
echo "    Modloop: ${OUTPUT_DIR}/modloop-virt"

# Create the deputy-init script for Alpine
# Note: Alpine uses busybox, so some commands differ from Ubuntu
DEPUTY_INIT_SCRIPT='#!/bin/sh
# deputy-init - Init script for Deputy VZ sandbox (Alpine version)
#
# This runs as PID 1 inside the VM. It:
# 1. Mounts essential filesystems
# 2. Syncs time from host (for TLS)
# 3. Configures networking via DHCP
# 4. Loads virtiofs module and mounts workspace
# 5. Executes the requested command
# 6. Powers off the VM

# Set PATH
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin"

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null
mount -t tmpfs tmpfs /tmp 2>/dev/null
mount -t tmpfs tmpfs /run 2>/dev/null

# Load virtio modules (required for networking and filesystem)
# Modules from Lima ISO modloop match the kernel version exactly
modprobe virtio_pci 2>/dev/null || true
modprobe virtio_net 2>/dev/null || true
modprobe virtiofs 2>/dev/null || true

# Give virtio devices time to register
sleep 0.5

# Sync time from host (fixes TLS certificate validation)
for param in $(cat /proc/cmdline 2>/dev/null); do
    case "$param" in
        deputy.time=*)
            HOST_TIME="${param#deputy.time=}"
            date -s "@${HOST_TIME}" >/dev/null 2>&1
            ;;
    esac
done

# Configure networking - find actual network interface (not just eth0)
# VZ/virtio may name it eth0, enp0s1, ens1, etc.
ip link set dev lo up 2>/dev/null

NET_IF=""
for iface in /sys/class/net/*; do
    ifname=$(basename "$iface")
    # Skip loopback
    [ "$ifname" = "lo" ] && continue
    # Found a network interface
    NET_IF="$ifname"
    break
done

if [ -n "$NET_IF" ]; then
    ip link set dev "$NET_IF" up 2>/dev/null

    # Use DHCP for IP assignment (udhcpc is BusyBox DHCP client in Alpine)
    # Note: We ignore DNS from DHCP since vmnet gateway does NOT forward DNS queries
    if command -v udhcpc >/dev/null 2>&1; then
        udhcpc -i "$NET_IF" -q -n -t 5 -s /usr/share/udhcpc/default.script 2>/dev/null || \
        udhcpc -i "$NET_IF" -q -n -t 5 2>/dev/null || true
    fi
fi

# IMPORTANT: Always set public DNS servers
# Apple vmnet NAT gateway (192.168.64.1) does NOT forward DNS queries,
# so we must use public DNS regardless of what DHCP provides
printf "nameserver 1.1.1.1\nnameserver 8.8.8.8\n" > /etc/resolv.conf

# Setup environment
# IMPORTANT: Use rootfs paths (not /tmp) for caches because /tmp is tmpfs (RAM-backed)
# and has limited space. The rootfs has plenty of space for toolchain downloads.
export HOME="/root"
export GOPATH="/root/go"
export GOCACHE="/root/.cache/go-build"
export GOMODCACHE="/root/go/pkg/mod"
export GOTMPDIR="/root/tmp"
export npm_config_cache="/root/.npm"
export TERM="xterm-256color"

# Create cache directories on rootfs
mkdir -p /root/.cache/go-build /root/go/pkg/mod /root/.npm /root/tmp 2>/dev/null

# Parse kernel cmdline for command and options
CMD_BASE64=""
WORKDIR=""
WORKSPACE_TAG=""
for param in $(cat /proc/cmdline 2>/dev/null); do
    case "$param" in
        deputy.cmd=*)
            CMD_BASE64="${param#deputy.cmd=}"
            ;;
        deputy.workdir=*)
            WORKDIR="${param#deputy.workdir=}"
            ;;
        deputy.workspace=*)
            WORKSPACE_TAG="${param#deputy.workspace=}"
            ;;
    esac
done

# Mount workspace via virtiofs if specified
# The tag "workspace" matches VirtioFileSystemDeviceConfiguration in main.go
if [ -n "$WORKSPACE_TAG" ] || [ -d /sys/bus/virtio/drivers/virtiofs ]; then
    mkdir -p /workspace 2>/dev/null
    # Try mounting with the "workspace" tag (set in main.go)
    mount -t virtiofs workspace /workspace 2>/dev/null || true
fi

if [ -z "$CMD_BASE64" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: No command provided"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    poweroff -f
    exit 1
fi

# Decode command (busybox base64)
CMD_DECODED=$(echo "$CMD_BASE64" | base64 -d 2>&1)
if [ $? -ne 0 ] || [ -z "$CMD_DECODED" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: Failed to decode command"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    poweroff -f
    exit 1
fi

# Change to workspace if specified and exists
if [ -n "$WORKDIR" ] && [ -d "$WORKDIR" ]; then
    cd "$WORKDIR"
elif [ -d /workspace ]; then
    cd /workspace
fi

# Execute command
echo "<<<DEPUTY_OUTPUT_START>>>"
echo "<<<DEPUTY_STDOUT>>>"
eval "$CMD_DECODED" 2>&1
EXIT_CODE=$?
echo "<<<DEPUTY_OUTPUT_END>>>"
echo "<<<DEPUTY_EXIT_CODE:${EXIT_CODE}>>>"

# Shutdown
poweroff -f
'

# Write deputy-init script
echo "${DEPUTY_INIT_SCRIPT}" > "${OUTPUT_DIR}/deputy-init"
chmod +x "${OUTPUT_DIR}/deputy-init"

# Build rootfs using Docker with Alpine
echo "==> Creating Alpine rootfs image with Docker..."

# Create the build script
BUILD_SCRIPT="${OUTPUT_DIR}/build-rootfs-inner.sh"
cat > "${BUILD_SCRIPT}" << 'DOCKERSCRIPT'
#!/bin/sh
set -ex

OUTPUT_DIR="/output"

# Install tools for image creation
apk add --no-cache e2fsprogs curl squashfs-tools

# Create disk image
echo "Creating ${ROOTFS_SIZE_MB}MB disk image..."
dd if=/dev/zero of="${OUTPUT_DIR}/rootfs.img" bs=1M count="${ROOTFS_SIZE_MB}"
mkfs.ext4 -F "${OUTPUT_DIR}/rootfs.img"

# Mount the image
mkdir -p /mnt/rootfs
mount -o loop "${OUTPUT_DIR}/rootfs.img" /mnt/rootfs

# Install Alpine base system
echo "Installing Alpine base system..."

# Set up repositories and keys for the target rootfs
mkdir -p /mnt/rootfs/etc/apk/keys
cp /etc/apk/repositories /mnt/rootfs/etc/apk/repositories
cp -a /etc/apk/keys/* /mnt/rootfs/etc/apk/keys/

# Initialize and install base packages
# Note: We do NOT install linux-virt here - we use Lima's modloop instead
# because Alpine 3.23's linux-virt has a kernel/module version mismatch bug
apk add --root /mnt/rootfs --initdb --no-cache \
    alpine-base \
    busybox \
    musl \
    ca-certificates \
    curl \
    wget \
    kmod

# Essential directories
mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run,workspace,root}
mkdir -p /mnt/rootfs/usr/share/udhcpc
mkdir -p /mnt/rootfs/lib/modules

# Copy udhcpc script for DHCP
if [ -f /usr/share/udhcpc/default.script ]; then
    cp /usr/share/udhcpc/default.script /mnt/rootfs/usr/share/udhcpc/
    chmod +x /mnt/rootfs/usr/share/udhcpc/default.script
fi

# Extract kernel modules from Lima modloop (squashfs)
# These modules match the Lima kernel exactly (6.18.2-0-virt)
echo "Extracting kernel modules from Lima modloop..."
unsquashfs -d /tmp/modloop "${OUTPUT_DIR}/modloop-virt"
cp -a /tmp/modloop/modules/* /mnt/rootfs/lib/modules/
rm -rf /tmp/modloop
echo "Modules installed: $(ls /mnt/rootfs/lib/modules/)"

if [ "${MINIMAL}" != "true" ]; then
    echo "Installing developer tools..."

    apk add --root /mnt/rootfs --no-cache \
        build-base \
        git \
        jq \
        unzip \
        openssh-client \
        bash

    # Install Go
    echo "Installing Go ${GO_VERSION}..."
    curl -L "https://go.dev/dl/go${GO_VERSION}.linux-arm64.tar.gz" | \
        tar -xz -C /mnt/rootfs/usr/local/

    # Create Go symlinks
    ln -sf /usr/local/go/bin/go /mnt/rootfs/usr/local/bin/go
    ln -sf /usr/local/go/bin/gofmt /mnt/rootfs/usr/local/bin/gofmt

    # Install Node.js
    echo "Installing Node.js ${NODE_VERSION}..."
    NODE_FULL_VERSION=$(curl -s https://nodejs.org/dist/latest-v${NODE_VERSION}.x/ | grep -oE "node-v${NODE_VERSION}\.[0-9]+\.[0-9]+-linux-arm64" | head -1 | sed "s/-linux-arm64//")
    NODE_VER=$(echo "${NODE_FULL_VERSION}" | sed "s/node-//")
    if [ -n "${NODE_VER}" ]; then
        curl -L "https://nodejs.org/dist/${NODE_VER}/${NODE_FULL_VERSION}-linux-arm64.tar.xz" | \
            tar -xJ -C /mnt/rootfs/usr/local/ --strip-components=1
    fi

    # Environment setup
    cat > /mnt/rootfs/etc/profile.d/deputy-dev.sh << 'ENVSCRIPT'
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin:$PATH"
export GOPATH="/root/go"
export GOCACHE="/tmp/go-cache"
export GOMODCACHE="/tmp/go-mod-cache"
export npm_config_cache="/tmp/npm-cache"
ENVSCRIPT
    chmod +x /mnt/rootfs/etc/profile.d/deputy-dev.sh
fi

# Install deputy-init
cp "${OUTPUT_DIR}/deputy-init" /mnt/rootfs/deputy-init
chmod +x /mnt/rootfs/deputy-init

# Ensure poweroff exists
if [ ! -f /mnt/rootfs/sbin/poweroff ]; then
    ln -sf /bin/busybox /mnt/rootfs/sbin/poweroff
fi

# Unmount
umount /mnt/rootfs

echo "==> SUCCESS: Created Alpine rootfs.img"
DOCKERSCRIPT
chmod +x "${BUILD_SCRIPT}"

docker run --rm --privileged \
    -v "${OUTPUT_DIR}:/output" \
    -e ROOTFS_SIZE_MB="${ROOTFS_SIZE_MB}" \
    -e MINIMAL="${MINIMAL}" \
    -e GO_VERSION="${GO_VERSION}" \
    -e NODE_VERSION="${NODE_VERSION}" \
    -e ALPINE_VERSION="${ALPINE_VERSION}" \
    alpine:${ALPINE_VERSION} \
    /output/build-rootfs-inner.sh

# Clean up build script
rm -f "${BUILD_SCRIPT}"

# Clean up
rm -f "${OUTPUT_DIR}/deputy-init"

# Verify
echo ""
echo "==> Build complete!"
echo ""
ls -lh "${OUTPUT_DIR}/vmlinuz" "${OUTPUT_DIR}/initrd.img" "${OUTPUT_DIR}/rootfs.img"

echo ""
echo "Alpine rootfs with virtiofs support!"
echo ""
echo "To use Alpine instead of Ubuntu:"
echo "  export DEPUTY_VZ_KERNEL=${OUTPUT_DIR}/vmlinuz"
echo "  export DEPUTY_VZ_INITRD=${OUTPUT_DIR}/initrd.img"
echo "  export DEPUTY_VZ_ROOTFS=${OUTPUT_DIR}/rootfs.img"
echo ""
echo "Or update the VZ plugin config to point to Alpine assets."
echo ""
echo "Test with:"
echo "  deputy exec --runtime plugin --plugin vz -- uname -a"
echo "  deputy exec --runtime plugin --plugin vz --workspace . -- ls -la /workspace"
