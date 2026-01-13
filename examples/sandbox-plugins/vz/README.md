# deputy-sandbox-vz

A Deputy sandbox runtime plugin using Apple's Virtualization.framework for VM-based isolation on macOS.

## Overview

This plugin provides maximum isolation by running each sandbox execution in a lightweight VM using the [vz](https://github.com/Code-Hex/vz) Go bindings for macOS Virtualization.framework.

**Key Benefits:**
- Hardware-backed isolation (each execution runs in a separate VM)
- No container escape vulnerabilities - VMs are a stronger security boundary
- Native macOS performance on Apple Silicon
- No root/sudo required

**Requirements:**
- macOS 11.0+ (Big Sur or later)
- Apple Silicon (arm64) - required for Virtualization.framework
- Code signing with virtualization entitlements

## Quick Start (Alpine Linux)

This section provides exact commands to get a working VM sandbox using Alpine Linux.

### 1. Build and Install the Plugin

```bash
# From the deputy repository root
cd examples/sandbox-plugins/vz

# Build the plugin
go build -o deputy-sandbox-vz .

# Sign with virtualization entitlement (required by macOS)
codesign --entitlements entitlements.plist --sign - deputy-sandbox-vz

# Install to a directory in your PATH
mkdir -p ~/bin
cp deputy-sandbox-vz ~/bin/

# Verify it's discoverable
export PATH="$HOME/bin:$PATH"
which deputy-sandbox-vz
```

### 2. Download Alpine Linux Assets

```bash
# Create the asset directory
mkdir -p ~/.deputy/vz
cd ~/.deputy/vz

# Download Alpine virt ISO (contains kernel and initramfs)
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-virt-3.19.0-aarch64.iso

# Extract kernel and initramfs from the ISO
bsdtar -xf alpine-virt.iso boot/vmlinuz-virt boot/initramfs-virt

# Move to expected locations
mv boot/vmlinuz-virt vmlinuz.efi
mv boot/initramfs-virt initrd.img
rmdir boot
```

### 3. Extract the Uncompressed Kernel

The `vmlinuz-virt` file is an EFI stub. Virtualization.framework needs the raw kernel image:

```bash
cd ~/.deputy/vz

# Find the gzip-compressed kernel inside the EFI wrapper
# The gzip signature (1f 8b 08) is at offset 0xc920 (51488 decimal)
OFFSET=$(xxd vmlinuz.efi | grep "1f8b 08" | head -1 | cut -d: -f1)
OFFSET_DEC=$((16#${OFFSET}))

# Extract and decompress
dd if=vmlinuz.efi bs=1 skip=$OFFSET_DEC of=vmlinux.gz 2>/dev/null
gunzip -f vmlinux.gz 2>/dev/null || true  # Ignore trailing garbage warning
mv vmlinux vmlinuz

# Verify it's a proper kernel image
file vmlinuz
# Should show: Linux kernel ARM64 boot executable Image, little-endian, 4K pages
```

### 4. Create a Root Filesystem

The Alpine initramfs needs a root filesystem to complete its boot sequence.

**Option A: Quick Setup with Docker** (Recommended)

```bash
# Use Docker to create an ext4 rootfs (macOS can't create ext4 natively)
docker run --rm -v ~/.deputy/vz:/output alpine:3.19 sh -c '
  apk add --no-cache e2fsprogs
  dd if=/dev/zero of=/output/rootfs.img bs=1M count=256
  mkfs.ext4 -F /output/rootfs.img
  mkdir -p /mnt/rootfs
  mount /output/rootfs.img /mnt/rootfs

  # Install a minimal Alpine system
  apk add --no-cache --root /mnt/rootfs --initdb alpine-base busybox

  # Create essential directories
  mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run}

  # Create a simple init script
  cat > /mnt/rootfs/init << "EOF"
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
exec /bin/sh
EOF
  chmod +x /mnt/rootfs/init

  umount /mnt/rootfs
  echo "Created rootfs.img"
'
```

**Option B: Use a Linux VM/Machine**

If you have access to a Linux system:

```bash
# On Linux:
dd if=/dev/zero of=rootfs.img bs=1M count=256
mkfs.ext4 -F rootfs.img
sudo mkdir -p /mnt/rootfs
sudo mount -o loop rootfs.img /mnt/rootfs

# Download and extract Alpine minirootfs
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz
sudo tar -xzf alpine-minirootfs-3.19.0-aarch64.tar.gz -C /mnt/rootfs

sudo umount /mnt/rootfs

# Copy rootfs.img to your Mac
scp rootfs.img your-mac:~/.deputy/vz/
```

**Option C: Minimal Placeholder** (For Testing Plugin Discovery)

If you just want to test plugin discovery without full VM execution:

```bash
# Create a minimal (empty) placeholder
dd if=/dev/zero of=~/.deputy/vz/rootfs.img bs=1M count=64
```

### 5. Verify Your Setup

```bash
ls -la ~/.deputy/vz/
# Should show:
# - vmlinuz      (Linux kernel, ~30-35MB)
# - initrd.img   (initramfs, ~8MB)
# - rootfs.img   (root filesystem, 256MB)

# Verify kernel format
file ~/.deputy/vz/vmlinuz
# Expected: Linux kernel ARM64 boot executable Image, little-endian, 4K pages
```

### 6. Test the Plugin

```bash
# Ensure plugin is in PATH
export PATH="$HOME/bin:$PATH"

# Build deputy if not already built
cd /path/to/deputy
go build -o deputy .

# Test plugin discovery (should not fall back to sandbox-exec)
DEPUTY_LOG_LEVEL=debug ./deputy exec --runtime plugin --plugin vz -- echo hello

# If you see "runtime=RUNTIME_PLUGIN" in the logs, the plugin is working!
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEPUTY_VZ_KERNEL` | Path to Linux kernel (vmlinuz) | `~/.deputy/vz/vmlinuz` |
| `DEPUTY_VZ_ROOTFS` | Path to root filesystem image | `~/.deputy/vz/rootfs.img` |
| `DEPUTY_VZ_INITRD` | Path to initrd (optional) | `~/.deputy/vz/initrd.img` |

Override the defaults for custom setups:

```bash
export DEPUTY_VZ_KERNEL=/path/to/custom/vmlinuz
export DEPUTY_VZ_ROOTFS=/path/to/custom/rootfs.img
./deputy exec --runtime plugin --plugin vz -- ls -la
```

## Usage Examples

```bash
# Run a command in a VM
deputy exec --runtime plugin --plugin vz -- ls -la

# Read-only mode (workspace mounted read-only)
deputy exec --runtime plugin --plugin vz --mode read-only -- cat /etc/os-release

# With memory limit
deputy exec --runtime plugin --plugin vz --memory 1g -- make build

# With CPU limit
deputy exec --runtime plugin --plugin vz --cpu 2 -- npm install

# Network isolated (no network interface)
deputy exec --runtime plugin --plugin vz --network none -- ./build.sh

# With timeout
deputy exec --runtime plugin --plugin vz --timeout 30s -- long-running-task
```

## Using Other Linux Distributions

### Ubuntu

```bash
# Download Ubuntu cloud image for arm64
curl -LO https://cloud-images.ubuntu.com/jammy/current/jammy-server-cloudimg-arm64.img

# Extract kernel from the image (requires mounting on Linux)
# Or download kernel separately:
curl -LO http://ports.ubuntu.com/ubuntu-ports/dists/jammy/main/installer-arm64/current/legacy-images/netboot/ubuntu-installer/arm64/linux
mv linux ~/.deputy/vz/vmlinuz

# Use the cloud image as rootfs (convert from qcow2 if needed)
qemu-img convert -f qcow2 -O raw jammy-server-cloudimg-arm64.img ~/.deputy/vz/rootfs.img
```

### Debian

```bash
# Download Debian cloud image
curl -LO https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.raw

# Extract or download kernel
# Copy rootfs
cp debian-12-generic-arm64.raw ~/.deputy/vz/rootfs.img
```

### Custom Kernel

Build your own kernel with minimal config:

```bash
git clone --depth 1 https://github.com/torvalds/linux.git
cd linux

# Use a minimal ARM64 config
make ARCH=arm64 defconfig

# Enable virtio drivers (required)
./scripts/config --enable VIRTIO
./scripts/config --enable VIRTIO_BLK
./scripts/config --enable VIRTIO_NET
./scripts/config --enable VIRTIO_CONSOLE
./scripts/config --enable VIRTIO_FS
./scripts/config --enable FUSE_FS

# Build
make ARCH=arm64 CROSS_COMPILE=aarch64-linux-gnu- -j$(nproc)

# Output is arch/arm64/boot/Image
cp arch/arm64/boot/Image ~/.deputy/vz/vmlinuz
```

## Capabilities

| Capability | Supported | Notes |
|------------|-----------|-------|
| Network Isolation | Yes | NAT or none via virtio-net |
| Filesystem Isolation | Yes | Full VM boundary |
| Resource Limits | Yes | CPU cores, memory |
| Seccomp | No | N/A for VMs |
| AppArmor/SELinux | No | N/A for VMs |
| Streaming Output | Yes | Via virtio-console |
| Interactive Stdin | Yes | Via virtio-console |
| Workspace Mounting | Yes | Via virtio-fs |
| GPU Passthrough | No | Not yet implemented |

## Supported Modes

| Mode | Description |
|------|-------------|
| `read-only` | Workspace mounted read-only inside VM |
| `workspace-write` | Workspace mounted read-write (default) |
| `ephemeral` | Changes discarded after execution |
| `network-isolated` | No network interface attached |

## Architecture

```
+-------------------------------------------------------------+
|                    Deputy CLI / Agent                        |
+-----------------------------+-------------------------------+
                              | ConnectRPC (Unix Socket)
                              v
+-------------------------------------------------------------+
|                  deputy-sandbox-vz Plugin                    |
|  - Receives ExecuteRequest                                   |
|  - Creates VM configuration                                  |
|  - Manages VM lifecycle                                      |
|  - Streams output via virtio-console                         |
+-----------------------------+-------------------------------+
                              | Virtualization.framework
                              v
+-------------------------------------------------------------+
|                    Lightweight VM                            |
|  +-------------------------------------------------------+  |
|  | Linux Guest                                           |  |
|  |  - virtio-blk: rootfs disk                            |  |
|  |  - virtio-fs: workspace directory                     |  |
|  |  - virtio-console: stdin/stdout/stderr                |  |
|  |  - virtio-net: network (if enabled)                   |  |
|  |  - virtio-balloon: memory management                  |  |
|  |  - virtio-entropy: randomness                         |  |
|  +-------------------------------------------------------+  |
+-------------------------------------------------------------+
```

## Security Model

The VM boundary provides stronger isolation than containers:

1. **Separate Kernel**: Each VM runs its own kernel; kernel vulnerabilities cannot escape
2. **Hardware Isolation**: Uses Apple's Hypervisor.framework for hardware-backed isolation
3. **No Shared State**: Unlike containers, VMs don't share cgroups, namespaces, or kernel state
4. **Controlled I/O**: All I/O goes through virtio devices which can be audited
5. **No Root Required**: Uses user-space virtualization, no elevated privileges needed

### Comparison with Other Runtimes

| Aspect | none | sandbox-exec | docker | gvisor | vz |
|--------|------|--------------|--------|--------|-----|
| Isolation Level | None | Process | Namespace | Syscall | VM |
| Kernel Shared | Yes | Yes | Yes | Partially | No |
| Escape Risk | High | Medium | Medium | Low | Very Low |
| Startup Time | ~1ms | ~5ms | ~100ms | ~50ms | ~200ms |
| Overhead | None | Low | Low | Medium | Medium |

## Limitations

- **macOS Only**: Requires macOS 11.0+ on Apple Silicon
- **Startup Overhead**: VMs take ~100-500ms to boot (vs ~10ms for containers)
- **Asset Management**: Requires pre-built kernel and rootfs images
- **No GPU Passthrough**: GPU workloads not supported
- **Disk Space**: Rootfs images consume disk space (~256MB minimum)

## Troubleshooting

### "Virtualization.framework not available"

Ensure you're running on:
- macOS 11.0 (Big Sur) or later
- Apple Silicon (M1/M2/M3/M4)

Intel Macs are **not supported** by Virtualization.framework for Linux VMs.

### "plugin not found in PATH"

```bash
# Check PATH includes the plugin location
echo $PATH | tr ':' '\n' | grep -E "bin$"

# Verify plugin is executable
ls -la ~/bin/deputy-sandbox-vz
# Should show: -rwxr-xr-x

# Verify plugin name matches expected pattern
# Must be named: deputy-sandbox-<name>
```

### "kernel not found" or "rootfs not found"

```bash
# Check asset directory
ls -la ~/.deputy/vz/
# Must contain: vmlinuz, rootfs.img

# Or set environment variables
export DEPUTY_VZ_KERNEL=/path/to/vmlinuz
export DEPUTY_VZ_ROOTFS=/path/to/rootfs.img
```

### "code signature invalid"

```bash
# Re-sign with entitlements
codesign --entitlements entitlements.plist --sign - ~/bin/deputy-sandbox-vz

# Verify signature
codesign -dvvv ~/bin/deputy-sandbox-vz
# Should show entitlements including com.apple.security.virtualization
```

### "Internal Virtualization error"

This usually means:
1. **Wrong kernel format**: Ensure `vmlinuz` is an uncompressed ARM64 Image, not an EFI stub
   ```bash
   file ~/.deputy/vz/vmlinuz
   # Must show: Linux kernel ARM64 boot executable Image
   # NOT: PE32+ executable (EFI application)
   ```

2. **Kernel/rootfs mismatch**: Ensure kernel and rootfs are both arm64

3. **Insufficient resources**: Try increasing memory
   ```bash
   deputy exec --runtime plugin --plugin vz --memory 1g -- ...
   ```

### VM starts but hangs

The VM is booting but init isn't completing. Common causes:

1. **Empty rootfs**: The rootfs needs actual files, not just an empty ext4 image
2. **Missing init**: Ensure `/sbin/init` or `/init` exists in rootfs
3. **initramfs issues**: The initramfs may be waiting for hardware that doesn't exist

Check kernel messages by enabling console output:
```bash
DEPUTY_LOG_LEVEL=debug deputy exec --runtime plugin --plugin vz -- ...
```

### "using fallback runtime"

If you see this in debug logs, the vz plugin wasn't available. Check:
```bash
# Verify plugin exists and is signed
ls -la ~/bin/deputy-sandbox-vz
codesign -d --entitlements - ~/bin/deputy-sandbox-vz

# Verify assets exist
ls ~/.deputy/vz/{vmlinuz,rootfs.img}

# Try running plugin directly to see errors
~/bin/deputy-sandbox-vz --socket /tmp/test.sock &
# Watch for any error messages
```

## Development

### Building from Source

```bash
cd examples/sandbox-plugins/vz
go mod tidy
go build -o deputy-sandbox-vz .
```

### Running Tests

```bash
go test -v ./...
```

### Protocol

The plugin implements the `SandboxRuntimeService` ConnectRPC interface:

```protobuf
service SandboxRuntimeService {
  rpc GetInfo(GetRuntimeInfoRequest) returns (GetRuntimeInfoResponse);
  rpc Execute(RuntimeExecuteRequest) returns (stream ExecuteEvent);
  rpc Cleanup(CleanupRequest) returns (CleanupResponse);
}
```

Communication happens over a Unix socket passed via `--socket` flag.

## References

- [vz library](https://github.com/Code-Hex/vz) - Go bindings for Virtualization.framework
- [Apple Virtualization.framework](https://developer.apple.com/documentation/virtualization)
- [apple/container](https://github.com/apple/container) - Apple's container runtime using the same framework
- [Alpine Linux Downloads](https://alpinelinux.org/downloads/) - ARM64 images
- [LinuxKit](https://github.com/linuxkit/linuxkit) - Tool for building minimal Linux images
- [Deputy Sandbox Architecture](../../../docs/design/sandbox-architecture.md) - Design documentation
