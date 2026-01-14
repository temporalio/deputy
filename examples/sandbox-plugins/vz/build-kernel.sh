#!/bin/bash
# build-kernel.sh - Build a custom Linux kernel for Deputy VZ sandbox
#
# This script builds an arm64 Linux kernel optimized for virtualization with:
# - CONFIG_VIRTIO_FS=y (virtiofs for host directory sharing)
# - CONFIG_NETFILTER=y (nftables for network filtering)
# - CONFIG_FUSE_FS=y (required for virtiofs)
# - Minimal config for fast boot (~70ms target)
#
# The build happens inside Docker to avoid macOS cross-compilation issues.
#
# Usage:
#   ./build-kernel.sh                    # Build kernel with default settings
#   ./build-kernel.sh --version 6.12     # Specify kernel version
#   ./build-kernel.sh --output /path     # Custom output directory
#
# Requirements:
#   - Docker Desktop for macOS
#   - ~2GB disk space for build
#   - ~5-10 minutes build time

set -euo pipefail

# Defaults
KERNEL_VERSION="${KERNEL_VERSION:-6.12.8}"
OUTPUT_DIR="${HOME}/.deputy/vz"
JOBS="${JOBS:-$(sysctl -n hw.ncpu)}"

# Parse arguments
while [[ $# -gt 0 ]]; do
    case "$1" in
        --version|-v)
            KERNEL_VERSION="$2"
            shift 2
            ;;
        --output|-o)
            OUTPUT_DIR="$2"
            shift 2
            ;;
        --jobs|-j)
            JOBS="$2"
            shift 2
            ;;
        --help|-h)
            echo "Usage: $0 [options]"
            echo ""
            echo "Options:"
            echo "  --version VER    Kernel version (default: ${KERNEL_VERSION})"
            echo "  --output DIR     Output directory (default: ~/.deputy/vz)"
            echo "  --jobs N         Parallel build jobs (default: auto)"
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

echo "==> Building Linux ${KERNEL_VERSION} for Deputy VZ"
echo "    Output: ${OUTPUT_DIR}"
echo "    Jobs: ${JOBS}"

# Check for Docker
if ! command -v docker &> /dev/null; then
    echo "ERROR: Docker is required to build the kernel"
    echo "Install Docker Desktop from https://docker.com"
    exit 1
fi

# Create kernel config optimized for VZ sandbox
# This is a minimal config with only what we need for fast boot
KERNEL_CONFIG='
# Basic arm64 config
CONFIG_ARM64=y
CONFIG_64BIT=y
CONFIG_SMP=y
CONFIG_NR_CPUS=8

# Console and early boot
CONFIG_SERIAL_AMBA_PL011=y
CONFIG_SERIAL_AMBA_PL011_CONSOLE=y
CONFIG_PRINTK=y
CONFIG_TTY=y
CONFIG_VT=y
CONFIG_VT_CONSOLE=y
CONFIG_HVC_DRIVER=y

# Block devices
CONFIG_BLK_DEV=y
CONFIG_VIRTIO_BLK=y
CONFIG_BLOCK=y

# Filesystems
CONFIG_EXT4_FS=y
CONFIG_PROC_FS=y
CONFIG_SYSFS=y
CONFIG_TMPFS=y
CONFIG_DEVTMPFS=y
CONFIG_DEVTMPFS_MOUNT=y

# VirtIO (core virtualization support)
CONFIG_VIRTIO=y
CONFIG_VIRTIO_PCI=y
CONFIG_VIRTIO_MMIO=y
CONFIG_VIRTIO_BALLOON=y
CONFIG_VIRTIO_CONSOLE=y
CONFIG_VIRTIO_INPUT=y

# VirtIO-FS (the key feature we need!)
CONFIG_FUSE_FS=y
CONFIG_VIRTIO_FS=y
CONFIG_DAX=y
CONFIG_FS_DAX=y

# VirtIO networking
CONFIG_VIRTIO_NET=y
CONFIG_NET=y
CONFIG_INET=y
CONFIG_IPV6=y
CONFIG_PACKET=y
CONFIG_UNIX=y
CONFIG_NETDEVICES=y

# Netfilter (for network allowlists)
CONFIG_NETFILTER=y
CONFIG_NF_CONNTRACK=y
CONFIG_NF_TABLES=y
CONFIG_NF_TABLES_INET=y
CONFIG_NFT_CT=y
CONFIG_NFT_REJECT=y
CONFIG_NFT_COUNTER=y
CONFIG_NFT_LOG=y
CONFIG_NF_TABLES_IPV4=y
CONFIG_NF_TABLES_IPV6=y
CONFIG_NF_REJECT_IPV4=y
CONFIG_NF_REJECT_IPV6=y
CONFIG_IP_NF_IPTABLES=y
CONFIG_IP_NF_FILTER=y
CONFIG_IP6_NF_IPTABLES=y
CONFIG_IP6_NF_FILTER=y

# 9P (alternative to virtiofs, more compatible)
CONFIG_NET_9P=y
CONFIG_NET_9P_VIRTIO=y
CONFIG_9P_FS=y
CONFIG_9P_FS_POSIX_ACL=y

# Memory and process management
CONFIG_MMU=y
CONFIG_SLAB=y
CONFIG_MODULES=y
CONFIG_MODULE_UNLOAD=y

# Power management (for clean shutdown)
CONFIG_PM=y
CONFIG_ACPI=y

# Misc required
CONFIG_MULTIUSER=y
CONFIG_SYSVIPC=y
CONFIG_POSIX_MQUEUE=y
CONFIG_FUTEX=y
CONFIG_EPOLL=y
CONFIG_SIGNALFD=y
CONFIG_TIMERFD=y
CONFIG_EVENTFD=y
CONFIG_AIO=y
CONFIG_IO_URING=y

# RNG for crypto
CONFIG_HW_RANDOM=y
CONFIG_HW_RANDOM_VIRTIO=y

# Time keeping
CONFIG_RTC_CLASS=y
CONFIG_RTC_DRV_PL031=y

# Kernel hardening (basic)
CONFIG_STRICT_KERNEL_RWX=y
CONFIG_STACKPROTECTOR=y
CONFIG_STACKPROTECTOR_STRONG=y

# Compression for smaller Image
CONFIG_KERNEL_GZIP=y

# No debugging (smaller/faster)
# CONFIG_DEBUG_INFO is not set
# CONFIG_DEBUG_KERNEL is not set
'

# Build kernel in Docker
echo "==> Starting Docker build..."

docker run --rm --platform linux/arm64 \
    -v "${OUTPUT_DIR}:/output" \
    -e KERNEL_VERSION="${KERNEL_VERSION}" \
    -e JOBS="${JOBS}" \
    ubuntu:24.04 \
    bash -c '
set -ex

# Install build dependencies
apt-get update
apt-get install -y --no-install-recommends \
    build-essential \
    bc \
    bison \
    flex \
    libssl-dev \
    libelf-dev \
    libncurses-dev \
    wget \
    xz-utils \
    kmod \
    cpio

# Download kernel source
MAJOR_VERSION=$(echo ${KERNEL_VERSION} | cut -d. -f1)
cd /tmp
wget -q "https://cdn.kernel.org/pub/linux/kernel/v${MAJOR_VERSION}.x/linux-${KERNEL_VERSION}.tar.xz"
tar xf "linux-${KERNEL_VERSION}.tar.xz"
cd "linux-${KERNEL_VERSION}"

# Start with arm64 defconfig and customize
make ARCH=arm64 defconfig

# Enable virtio-fs (the key feature)
./scripts/config --enable CONFIG_FUSE_FS
./scripts/config --enable CONFIG_VIRTIO_FS
./scripts/config --enable CONFIG_DAX
./scripts/config --enable CONFIG_FS_DAX

# Enable 9P as fallback
./scripts/config --enable CONFIG_NET_9P
./scripts/config --enable CONFIG_NET_9P_VIRTIO
./scripts/config --enable CONFIG_9P_FS
./scripts/config --enable CONFIG_9P_FS_POSIX_ACL

# Enable netfilter for network allowlists
./scripts/config --enable CONFIG_NETFILTER
./scripts/config --enable CONFIG_NF_CONNTRACK
./scripts/config --enable CONFIG_NF_TABLES
./scripts/config --enable CONFIG_NF_TABLES_INET
./scripts/config --enable CONFIG_NFT_CT
./scripts/config --enable CONFIG_NFT_REJECT
./scripts/config --enable CONFIG_IP_NF_IPTABLES
./scripts/config --enable CONFIG_IP_NF_FILTER

# Enable virtio devices
./scripts/config --enable CONFIG_VIRTIO
./scripts/config --enable CONFIG_VIRTIO_PCI
./scripts/config --enable CONFIG_VIRTIO_MMIO
./scripts/config --enable CONFIG_VIRTIO_BLK
./scripts/config --enable CONFIG_VIRTIO_NET
./scripts/config --enable CONFIG_VIRTIO_CONSOLE
./scripts/config --enable CONFIG_VIRTIO_BALLOON
./scripts/config --enable CONFIG_HW_RANDOM_VIRTIO

# Disable unnecessary features for faster boot
./scripts/config --disable CONFIG_DEBUG_INFO
./scripts/config --disable CONFIG_DEBUG_KERNEL
./scripts/config --disable CONFIG_SOUND
./scripts/config --disable CONFIG_DRM
./scripts/config --disable CONFIG_USB
./scripts/config --disable CONFIG_WIRELESS
./scripts/config --disable CONFIG_WLAN
./scripts/config --disable CONFIG_BT
./scripts/config --disable CONFIG_INPUT_MOUSE
./scripts/config --disable CONFIG_INPUT_KEYBOARD
./scripts/config --disable CONFIG_SERIO
./scripts/config --disable CONFIG_HID

# Update config
make ARCH=arm64 olddefconfig

# Build kernel
echo "==> Compiling kernel (this may take 5-10 minutes)..."
make ARCH=arm64 -j${JOBS} Image

# Copy output
cp arch/arm64/boot/Image /output/vmlinuz-deputy

# Show what we built
echo ""
echo "==> Kernel built successfully!"
ls -lh /output/vmlinuz-deputy

# Verify virtio-fs is enabled
echo ""
echo "==> Verifying configuration:"
grep -E "VIRTIO_FS|9P_FS|NETFILTER" .config | grep "=y" || true
'

echo ""
echo "==> Build complete!"
echo ""
ls -lh "${OUTPUT_DIR}/vmlinuz-deputy"

echo ""
echo "To use this kernel:"
echo "  cp ${OUTPUT_DIR}/vmlinuz-deputy ${OUTPUT_DIR}/vmlinuz"
echo "  # Or set DEPUTY_VZ_KERNEL=${OUTPUT_DIR}/vmlinuz-deputy"
echo ""
echo "Then test:"
echo "  deputy exec --runtime plugin --plugin vz --workspace . -- ls -la /workspace"
