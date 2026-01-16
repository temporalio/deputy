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
cp "${TMPDIR}/boot/initramfs-virt" "${OUTPUT_DIR}/initrd-stock.img"
cp "${TMPDIR}/boot/modloop-virt" "${OUTPUT_DIR}/modloop-virt"

# Extract raw ARM64 kernel from EFI stub
# Lima's vmlinuz-virt is an EFI stub (PE32+ executable), but VZ needs the raw ARM64 Image
# The raw kernel is embedded as gzip-compressed data inside the EFI stub
echo "==> Extracting raw ARM64 kernel from EFI stub..."
VMLINUZ_EFI="${TMPDIR}/boot/vmlinuz-virt"
KERNEL_TYPE=$(file "${VMLINUZ_EFI}" | head -1)
if echo "${KERNEL_TYPE}" | grep -q "PE32+.*EFI"; then
    # Find gzip signature (1f 8b 08) using grep with byte offset
    # LC_ALL=C ensures binary matching works correctly
    GZIP_OFFSET=$(LC_ALL=C grep -abo $'\x1f\x8b\x08' "${VMLINUZ_EFI}" 2>/dev/null | head -1 | cut -d: -f1)
    if [ -n "${GZIP_OFFSET}" ]; then
        echo "    Found gzip data at byte offset ${GZIP_OFFSET}"

        dd if="${VMLINUZ_EFI}" bs=1 skip=${GZIP_OFFSET} of="${OUTPUT_DIR}/vmlinuz.gz" 2>/dev/null

        # Decompress - use Docker for reliability (macOS gzip can have issues with this format)
        docker run --rm -v "${OUTPUT_DIR}:/output" alpine:${ALPINE_VERSION} sh -c '
            gzip -dc /output/vmlinuz.gz > /output/vmlinuz && rm /output/vmlinuz.gz
        '
        echo "    Extracted raw kernel from EFI stub"
    else
        echo "ERROR: Could not find gzip data in EFI stub"
        exit 1
    fi
elif echo "${KERNEL_TYPE}" | grep -q "Linux kernel ARM64"; then
    # Already a raw ARM64 kernel
    cp "${VMLINUZ_EFI}" "${OUTPUT_DIR}/vmlinuz"
    echo "    Kernel is already raw ARM64 format"
else
    echo "ERROR: Unknown kernel format: ${KERNEL_TYPE}"
    exit 1
fi

# Verify kernel format
KERNEL_CHECK=$(file "${OUTPUT_DIR}/vmlinuz")
if ! echo "${KERNEL_CHECK}" | grep -q "Linux kernel ARM64"; then
    echo "ERROR: Extracted kernel is not ARM64 format: ${KERNEL_CHECK}"
    exit 1
fi

rm -rf "${TMPDIR}"
echo "    Kernel: ${OUTPUT_DIR}/vmlinuz"
echo "    Kernel format: $(file "${OUTPUT_DIR}/vmlinuz" | sed 's/.*: //')"
echo "    Stock initrd: ${OUTPUT_DIR}/initrd-stock.img"
echo "    Modloop: ${OUTPUT_DIR}/modloop-virt"

# Create custom initrd with virtiofs modules and a custom init script
# The stock Lima initrd has a complex init designed for different boot flow.
# We need a simple init that: loads modules, mounts rootfs, switch_root to /deputy-init
echo "==> Creating custom initrd with virtiofs modules..."
docker run --rm --privileged \
    -v "${OUTPUT_DIR}:/output" \
    alpine:${ALPINE_VERSION} sh -c '
set -ex
apk add --no-cache cpio gzip squashfs-tools kmod

# Extract stock initrd (we need its busybox and libraries)
mkdir -p /tmp/initrd
cd /tmp/initrd
gzip -dc /output/initrd-stock.img | cpio -idm 2>/dev/null || true

# Extract modules from modloop (squashfs)
mkdir -p /tmp/modloop
unsquashfs -d /tmp/modloop /output/modloop-virt

# Find the kernel version from modloop
KVER=$(ls /tmp/modloop/modules/ | head -1)
echo "Kernel version from modloop: ${KVER}"

# Copy ALL modules from modloop to initrd (ensures deps are available)
rm -rf /tmp/initrd/usr/lib/modules 2>/dev/null || true
mkdir -p /tmp/initrd/usr/lib/modules
cp -a /tmp/modloop/modules/${KVER} /tmp/initrd/usr/lib/modules/

# Also create symlink at /lib/modules for compatibility
mkdir -p /tmp/initrd/lib
ln -sf ../usr/lib/modules /tmp/initrd/lib/modules

# Regenerate module dependencies
depmod -b /tmp/initrd ${KVER} 2>/dev/null || true

# Ensure required directories exist
mkdir -p /tmp/initrd/proc /tmp/initrd/sys /tmp/initrd/dev /tmp/initrd/mnt
mkdir -p /tmp/initrd/usr/bin /tmp/initrd/usr/sbin /tmp/initrd/bin /tmp/initrd/sbin

# Ensure modprobe exists (link to kmod)
if [ ! -f /tmp/initrd/usr/sbin/modprobe ]; then
    ln -sf ../bin/kmod /tmp/initrd/usr/sbin/modprobe 2>/dev/null || true
fi

# Create custom init script for Deputy VZ boot
cat > /tmp/initrd/init << "INITSCRIPT"
#!/bin/sh
# Deputy VZ initrd init script
# Loads modules, mounts rootfs, and switches to /deputy-init
export PATH=/usr/bin:/bin:/usr/sbin:/sbin

# Mount essential filesystems
/usr/bin/busybox mount -t proc proc /proc
/usr/bin/busybox mount -t sysfs sys /sys
/usr/bin/busybox mount -t devtmpfs dev /dev

# Redirect output to virtio console for debugging
exec > /dev/hvc0 2>&1

echo "=== Deputy VZ initrd starting ==="

# Load kernel modules for boot
echo "Loading kernel modules..."
# ext4 dependencies
/usr/sbin/modprobe mbcache 2>&1 || true
/usr/sbin/modprobe jbd2 2>&1 || true
/usr/sbin/modprobe ext4 2>&1 || echo "ext4 load: $?"

# virtio block device
/usr/sbin/modprobe virtio_blk 2>&1 || echo "virtio_blk load: $?"

# virtiofs for workspace
/usr/sbin/modprobe fuse 2>&1 || true
/usr/sbin/modprobe virtiofs 2>&1 || echo "virtiofs load: $?"

# Wait for block devices to appear
/usr/bin/busybox sleep 1
echo "Block devices: $(/usr/bin/busybox ls /dev/vd* 2>/dev/null || echo none)"

# Check if read-only mode was requested via kernel cmdline
# The "ro" parameter tells the kernel to mount rootfs read-only
# We check for " ro " (with spaces) to avoid matching "root=" etc
MOUNT_OPTS=""
if /usr/bin/busybox grep -q ' ro ' /proc/cmdline; then
    # Read-only mode: use noload to skip journal recovery
    # (ext4 journal replay requires write access)
    MOUNT_OPTS="-o ro,noload"
    echo "Read-only mode: mounting with ro,noload"
else
    echo "Read-write mode: mounting normally"
fi

# Mount rootfs
echo "Mounting rootfs..."
/usr/bin/busybox mkdir -p /mnt
/usr/bin/busybox mount -t ext4 $MOUNT_OPTS /dev/vda /mnt 2>&1 || {
    echo "ERROR: Failed to mount /dev/vda"
    echo "Available devices:"
    /usr/bin/busybox ls -la /dev/ | /usr/bin/busybox head -20
    exec /usr/bin/busybox sh
}

# Mount virtiofs workspace if available
echo "Mounting workspace..."
/usr/bin/busybox mkdir -p /mnt/workspace
if /usr/bin/busybox mount -t virtiofs workspace /mnt/workspace 2>&1; then
    echo "Workspace mounted successfully"
else
    echo "No workspace to mount (normal if --no-workspace)"
fi

# Verify deputy-init exists
if [ ! -x /mnt/deputy-init ]; then
    echo "ERROR: /mnt/deputy-init not found or not executable"
    /usr/bin/busybox ls -la /mnt/ 2>&1 | /usr/bin/busybox head -10
    exec /usr/bin/busybox sh
fi

# Switch to real root
echo "Switching root..."
exec /usr/bin/busybox switch_root /mnt /deputy-init

echo "ERROR: switch_root failed"
exec /usr/bin/busybox sh
INITSCRIPT
chmod +x /tmp/initrd/init

# List modules in initrd
echo "Modules in initrd:"
find /tmp/initrd/usr/lib/modules -name "*.ko" 2>/dev/null | wc -l
echo "Key modules:"
find /tmp/initrd/usr/lib/modules -name "ext4.ko" -o -name "virtio_blk.ko" -o -name "virtiofs.ko" 2>/dev/null

# Repack initrd
cd /tmp/initrd
find . | cpio -o -H newc 2>/dev/null | gzip -9 > /output/initrd.img
echo "Created /output/initrd.img with custom init"
'

# Verify initrd was created
if [ ! -f "${OUTPUT_DIR}/initrd.img" ]; then
    echo "ERROR: Failed to create custom initrd"
    exit 1
fi

echo "    Initrd: ${OUTPUT_DIR}/initrd.img (with virtiofs)"
echo "    Size: $(ls -lh "${OUTPUT_DIR}/initrd.img" | awk '{print $5}')"

# Create the deputy-init script for Alpine
# Note: Alpine uses busybox, so some commands differ from Ubuntu
DEPUTY_INIT_SCRIPT='#!/bin/sh
# deputy-init - Init script for Deputy VZ sandbox (Alpine version)
#
# This runs as PID 1 inside the VM. It:
# 1. Mounts essential filesystems
# 2. Syncs time from host (for TLS)
# 3. Configures networking via DHCP
# 4. Loads virtiofs module and mounts workspace (direct or overlay mode)
# 5. Executes the requested command
# 6. Powers off the VM
#
# Workspace modes:
# - Direct: mounts "workspace" virtiofs tag directly at /workspace
# - Overlay: mounts "workspace-base" (RO) + "workspace-upper" (RW) with overlayfs
#   Changes go to workspace-upper, leaving base workspace unchanged.

# Set PATH
export PATH="/usr/local/go/bin:/usr/local/bin:/usr/bin:/bin:/sbin:/usr/sbin"

# Mount essential filesystems
# IMPORTANT: In read-only rootfs mode, we cannot redirect to /dev/null until
# devtmpfs is mounted. Mount filesystems first without redirection.
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
mount -t tmpfs tmpfs /tmp
mount -t tmpfs tmpfs /run

# Now /dev/null exists and we can use redirections safely

# Load modules (required for networking, filesystem, and overlay)
modprobe virtio_pci 2>/dev/null || true
modprobe virtio_net 2>/dev/null || true
modprobe virtiofs 2>/dev/null || true
modprobe overlay 2>/dev/null || true  # For workspace overlay mode

# Give virtio devices time to register
sleep 0.5

# Parse all kernel cmdline parameters upfront
CMD_BASE64=""
WORKDIR=""
ALLOWLIST_BASE64=""
HOST_TIME=""
for param in $(cat /proc/cmdline 2>/dev/null); do
    case "$param" in
        deputy.cmd=*)
            CMD_BASE64="${param#deputy.cmd=}"
            ;;
        deputy.workdir=*)
            WORKDIR="${param#deputy.workdir=}"
            ;;
        deputy.allowlist=*)
            ALLOWLIST_BASE64="${param#deputy.allowlist=}"
            ;;
        deputy.time=*)
            HOST_TIME="${param#deputy.time=}"
            ;;
    esac
done

# Sync time from host (fixes TLS certificate validation)
if [ -n "$HOST_TIME" ]; then
    date -s "@${HOST_TIME}" >/dev/null 2>&1
fi

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
export GOTOOLCHAIN="local"  # Prevent auto-downloading newer Go versions
export npm_config_cache="/root/.npm"
export TERM="xterm-256color"

# Create cache directories on rootfs
mkdir -p /root/.cache/go-build /root/go/pkg/mod /root/.npm /root/tmp 2>/dev/null

# Configure network allowlist if specified (ALLOWLIST network mode)
# The allowlist is a newline-separated list of allowed hosts (host:port or just host)
# Format: base64-encoded "host1:port1\nhost2:port2\n..."
# Special marker "__DEPUTY_ALLOWLIST_EMPTY__" signals empty allowlist (DROP all except DNS/DHCP)
if [ -n "$ALLOWLIST_BASE64" ] && [ -n "$NET_IF" ]; then
    ALLOWLIST=$(echo "$ALLOWLIST_BASE64" | base64 -d 2>/dev/null || echo "")
    # Check for empty allowlist marker
    if [ "$ALLOWLIST" = "__DEPUTY_ALLOWLIST_EMPTY__" ]; then
        ALLOWLIST=""
    fi
    if command -v nft >/dev/null 2>&1; then
        # Load netfilter modules
        modprobe nf_tables 2>/dev/null || true
        modprobe nft_chain_nat 2>/dev/null || true

        # Create nftables ruleset for egress filtering
        # Default policy: DROP all outbound connections except allowlisted hosts
        # Always allow: DNS (53), DHCP (67,68), loopback, established connections
        nft flush ruleset 2>/dev/null || true

        # Create base table and chains
        nft add table inet deputy_filter
        nft add chain inet deputy_filter output "{ type filter hook output priority 0; policy drop; }"
        nft add chain inet deputy_filter input "{ type filter hook input priority 0; policy accept; }"

        # Allow loopback
        nft add rule inet deputy_filter output oif lo accept

        # Allow established/related connections (responses to our requests)
        nft add rule inet deputy_filter output ct state established,related accept

        # Allow DNS queries (UDP and TCP port 53) - needed for hostname resolution
        nft add rule inet deputy_filter output udp dport 53 accept
        nft add rule inet deputy_filter output tcp dport 53 accept

        # Allow DHCP (needed for IP assignment)
        nft add rule inet deputy_filter output udp dport 67 accept
        nft add rule inet deputy_filter output udp sport 68 accept

        # Parse and add allowlist rules
        echo "$ALLOWLIST" | while IFS= read -r entry; do
            [ -z "$entry" ] && continue

            # Parse host:port format
            case "$entry" in
                *:*)
                    HOST="${entry%%:*}"
                    PORT="${entry#*:}"
                    ;;
                *)
                    HOST="$entry"
                    PORT=""
                    ;;
            esac

            # Resolve hostname to IP if needed
            # Note: We resolve at boot time since DNS may be blocked later
            # We prefer IPv4 addresses for simplicity (IPv6 support could be added later)
            if echo "$HOST" | grep -qE "^[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+$"; then
                IP="$HOST"
            elif echo "$HOST" | grep -qE "^[0-9a-fA-F:]+$"; then
                # Skip pure IPv6 addresses for now
                IP=""
            else
                # Resolve hostname - try multiple times as DNS may not be ready
                # Filter for IPv4 addresses only (match lines starting with digits)
                IP=""
                for i in 1 2 3; do
                    IP=$(getent ahostsv4 "$HOST" 2>/dev/null | awk "/STREAM/{print \$1; exit}")
                    [ -n "$IP" ] && break
                    sleep 0.5
                done
            fi

            if [ -n "$IP" ]; then
                if [ -n "$PORT" ]; then
                    # Allow specific port
                    nft add rule inet deputy_filter output ip daddr "$IP" tcp dport "$PORT" accept 2>/dev/null
                    nft add rule inet deputy_filter output ip daddr "$IP" udp dport "$PORT" accept 2>/dev/null
                else
                    # Allow all ports to this host
                    nft add rule inet deputy_filter output ip daddr "$IP" accept 2>/dev/null
                fi
            fi
        done
    fi
fi

# Mount workspace via virtiofs
# Check for overlay mode first (workspace-base + workspace-upper tags),
# then fall back to direct mode (workspace tag).
mkdir -p /workspace 2>/dev/null
OVERLAY_MODE=false
CHANGES_SYNC=false

# Wait for virtiofs devices to be fully ready
# The host directory sharing takes a moment to initialize after VM boot
sleep 1

# Try overlay mode: mount workspace-base (RO) via virtiofs
# In overlay mode, changes are stored on the VM local ext4 rootfs, NOT synced to host.
# This provides isolation (host workspace protected) without virtiofs workdir issues.
#
# Note: virtiofs through macOS VZ.framework has issues with overlayfs workdir operations
# (EACCES when creating internal directories). Using local ext4 for upper/work avoids this.
mkdir -p /mnt/workspace-base /mnt/overlay-upper /mnt/overlay-work 2>/dev/null

if mount -t virtiofs workspace-base /mnt/workspace-base 2>/dev/null; then
    # workspace-base mounted - set up overlayfs with local upper/work dirs
    # Changes stay in the VM and are discarded on shutdown (ephemeral isolation)
    if mount -t overlay overlay -o \
        rw,lowerdir=/mnt/workspace-base,upperdir=/mnt/overlay-upper,workdir=/mnt/overlay-work \
        /workspace 2>/dev/null; then
        OVERLAY_MODE=true
    else
        # Overlay mount failed, clean up
        umount /mnt/workspace-base 2>/dev/null
    fi
fi

# Fall back to direct mode if overlay mode failed
if [ "$OVERLAY_MODE" = "false" ]; then
    mount -t virtiofs workspace /workspace 2>/dev/null || true
fi

# Try to mount workspace-changes for review_before_commit workflow
# This share is only created when review_before_commit is enabled
mkdir -p /mnt/workspace-changes 2>/dev/null
if mount -t virtiofs workspace-changes /mnt/workspace-changes 2>/dev/null; then
    CHANGES_SYNC=true
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

# Sync overlay filesystems before copying changes
# This ensures all written data is flushed from the overlayfs cache to the upper layer
sync

# Sync changes for review_before_commit workflow
# When overlay mode is active and workspace-changes share is mounted,
# copy changed files from the overlay upper layer to the host-accessible share
if [ "$OVERLAY_MODE" = "true" ] && [ "$CHANGES_SYNC" = "true" ]; then
    echo "<<<DEPUTY_CHANGES_START>>>"

    # Find and sync all changed files from the overlay upper layer
    # The upper layer contains only files that were added or modified
    if [ -d /mnt/overlay-upper ] && [ "$(ls -A /mnt/overlay-upper 2>/dev/null)" ]; then
        cd /mnt/overlay-upper
        find . -type f 2>/dev/null | while read -r file; do
            # Remove leading ./
            relpath="${file#./}"

            # Check if file exists in base (modified) or not (added)
            if [ -f "/mnt/workspace-base/$relpath" ]; then
                change_type="M"
            else
                change_type="A"
            fi

            # Copy the file to workspace-changes, preserving directory structure
            target_dir="/mnt/workspace-changes/$(dirname "$relpath")"
            mkdir -p "$target_dir" 2>/dev/null

            # Use cat for reliable copy across virtiofs
            cat "$file" > "/mnt/workspace-changes/$relpath"

            # Report the change
            echo "<<<DEPUTY_CHANGE:${change_type}:${relpath}>>>"
        done

        # Find deleted files by checking for whiteout files
        # OverlayFS uses character devices with 0/0 major/minor for whiteouts
        find . -type c 2>/dev/null | while read -r file; do
            relpath="${file#./}"
            # Check if it is a whiteout (char device 0,0)
            if [ "$(stat -c "%t,%T" "$file" 2>/dev/null)" = "0,0" ]; then
                # This is a whiteout - the file was deleted
                echo "<<<DEPUTY_CHANGE:D:${relpath}>>>"
            fi
        done
    fi

    echo "<<<DEPUTY_CHANGES_END>>>"
fi

# Sync filesystem before shutdown to ensure all writes are flushed
# This prevents corrupt caches (e.g., Go toolchain downloads) on next boot
sync

# Shutdown
poweroff -f
'

# Write deputy-init script
echo "${DEPUTY_INIT_SCRIPT}" > "${OUTPUT_DIR}/deputy-init"
chmod +x "${OUTPUT_DIR}/deputy-init"

# Build rootfs using Docker with Alpine
echo "==> Creating Alpine rootfs image with Docker..."

# Create the disk image on macOS BEFORE Docker runs
# This ensures the file has proper macOS characteristics for VZ.framework
# Using truncate creates a sparse file that VZ handles correctly
echo "Creating ${ROOTFS_SIZE_MB}MB sparse disk image on macOS..."
rm -f "${OUTPUT_DIR}/rootfs.img"
truncate -s ${ROOTFS_SIZE_MB}M "${OUTPUT_DIR}/rootfs.img"

# Create the build script
BUILD_SCRIPT="${OUTPUT_DIR}/build-rootfs-inner.sh"
cat > "${BUILD_SCRIPT}" << 'DOCKERSCRIPT'
#!/bin/sh
set -ex

OUTPUT_DIR="/output"

# Install tools for image creation
apk add --no-cache e2fsprogs curl squashfs-tools

# Format the pre-created disk image (created by macOS truncate)
echo "Formatting disk image..."
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
    kmod \
    nftables \
    iptables

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
export GOTOOLCHAIN="local"
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

# Fix permissions - VZ requires read-write access to rootfs.img
# This is critical: without proper permissions, VZ will fail to attach the disk
chmod 666 "${OUTPUT_DIR}/rootfs.img"
chmod 644 "${OUTPUT_DIR}/vmlinuz"
chmod 644 "${OUTPUT_DIR}/initrd.img"
chmod 644 "${OUTPUT_DIR}/initrd-stock.img" 2>/dev/null || true

# Clear any extended attributes that might interfere with VZ
# macOS adds com.apple.provenance to downloaded/created files
xattr -c "${OUTPUT_DIR}/rootfs.img" 2>/dev/null || true
xattr -c "${OUTPUT_DIR}/vmlinuz" 2>/dev/null || true
xattr -c "${OUTPUT_DIR}/initrd.img" 2>/dev/null || true

# Create convenience symlinks in parent directory (~/.deputy/vz/)
# This allows the plugin to work with default paths (no env vars needed)
PARENT_DIR="${OUTPUT_DIR}/.."
ln -sf alpine/vmlinuz "${PARENT_DIR}/vmlinuz" 2>/dev/null || true
ln -sf alpine/rootfs.img "${PARENT_DIR}/rootfs.img" 2>/dev/null || true
# Note: initrd symlink not created at parent level since Ubuntu doesn't need one
# The plugin checks ~/.deputy/vz/alpine/initrd.img as a fallback

# Verify
echo ""
echo "==> Build complete!"
echo ""
ls -lh "${OUTPUT_DIR}/vmlinuz" "${OUTPUT_DIR}/initrd.img" "${OUTPUT_DIR}/rootfs.img"

echo ""
echo "==> Alpine rootfs with virtiofs + network support!"
echo ""
echo "The build script has created symlinks so the plugin works with default paths."
echo "No environment variables are required for basic usage."
echo ""
echo "Test your setup:"
echo ""
echo "  # Basic test (uses default paths)"
echo "  deputy exec --runtime plugin --plugin vz -- uname -a"
echo ""
echo "  # Test Go toolchain (requires --network host)"
echo "  deputy exec --runtime plugin --plugin vz --network host -- go version"
echo ""
echo "  # Test workspace mounting"
echo "  deputy exec --runtime plugin --plugin vz --workspace . -- ls /workspace"
echo ""
echo "  # Build a Go project with network access"
echo "  deputy exec --runtime plugin --plugin vz --workspace . --network host --cpu 4 --memory 4g -- go build ./..."
echo ""
echo "Optional: Set environment variables for explicit paths (add to ~/.zshrc):"
echo ""
echo "  export DEPUTY_VZ_KERNEL=${OUTPUT_DIR}/vmlinuz"
echo "  export DEPUTY_VZ_INITRD=${OUTPUT_DIR}/initrd.img"
echo "  export DEPUTY_VZ_ROOTFS=${OUTPUT_DIR}/rootfs.img"
echo ""
echo "For full documentation, see: examples/sandbox-plugins/vz/README.md"
