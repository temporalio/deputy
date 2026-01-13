# deputy-sandbox-vz

A Deputy sandbox runtime plugin using Apple's Virtualization.framework for VM-based isolation on macOS.

> [!WARNING]
> **Work in Progress**: This plugin demonstrates the Deputy sandbox plugin architecture but is not yet fully functional for command execution. The VM boots successfully, but command injection and output capture are still being implemented. Use this as a reference for building sandbox plugins or contributing to its development.

## Overview

This plugin provides maximum isolation by running each sandbox execution in a lightweight VM using the [vz](https://github.com/Code-Hex/vz) Go bindings for macOS Virtualization.framework.

**Key Benefits:**
- Hardware-backed isolation (each execution runs in a separate VM)
- No container escape vulnerabilities - VMs are a stronger security boundary
- Native macOS performance on Apple Silicon
- No root/sudo required

**Current Status:**
- [x] Plugin discovery and registration
- [x] VM configuration and boot
- [x] Virtio device setup (disk, network, console, filesystem sharing)
- [ ] Command injection into guest
- [ ] Output capture and streaming
- [ ] Exit code detection

**Requirements:**
- macOS 11.0+ (Big Sur or later)
- Apple Silicon (arm64) - required for Virtualization.framework
- Code signing with virtualization entitlements
- Docker (for creating rootfs on macOS)

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

> [!NOTE]
> This guide uses Alpine Linux 3.19.0 (aarch64 virt edition). To use a newer stable release,
> check [alpinelinux.org/downloads](https://alpinelinux.org/downloads/) and update both
> `v3.19` and `3.19.0` in the URL and filename below.

```bash
# Create the asset directory
mkdir -p ~/.deputy/vz
cd ~/.deputy/vz

# Download Alpine virt ISO (contains kernel and initramfs)
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-virt-3.19.0-aarch64.iso

# Extract kernel and initramfs from the ISO
bsdtar -xf alpine-virt-3.19.0-aarch64.iso boot/vmlinuz-virt boot/initramfs-virt

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
# The gzip signature (1f 8b 08) marks the start of the compressed kernel
OFFSET=$(xxd vmlinuz.efi | grep "1f8b 08" | head -1 | cut -d: -f1)
if [ -z "$OFFSET" ]; then
    echo "Error: Failed to locate gzip signature in vmlinuz.efi."
    echo "The kernel format may have changed. Please verify the Alpine ISO version"
    echo "and check https://github.com/picatz/deputy for updated extraction instructions."
    exit 1
fi
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

First, download the Alpine minirootfs tarball:

```bash
cd ~/.deputy/vz
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz
```

Then create the rootfs image using Docker with `--privileged` (required for loop mounting):

```bash
# Use Docker to create an ext4 rootfs (macOS can't create ext4 natively)
# Note: --privileged is required to mount the disk image inside the container
docker run --rm --privileged -v ~/.deputy/vz:/output alpine:3.19 sh -c '
  apk add --no-cache e2fsprogs

  # Create and format the disk image
  dd if=/dev/zero of=/output/rootfs.img bs=1M count=256
  mkfs.ext4 -F /output/rootfs.img

  # Mount using loop device (needs privileged)
  mkdir -p /mnt/rootfs
  mount -o loop /output/rootfs.img /mnt/rootfs

  # Extract the minirootfs
  tar -xzf /output/alpine-minirootfs-3.19.0-aarch64.tar.gz -C /mnt/rootfs

  # Create a simple init script
  cat > /mnt/rootfs/init << "EOF"
#!/bin/sh
mount -t proc proc /proc
mount -t sysfs sys /sys
mount -t devtmpfs dev /dev
exec /bin/sh
EOF
  chmod +x /mnt/rootfs/init

  # Ensure essential directories exist
  mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run}

  umount /mnt/rootfs
  echo "SUCCESS: Created rootfs.img with Alpine minirootfs"
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

# Test plugin discovery - verify the plugin starts and responds to GetInfo
# This confirms the plugin architecture is working
~/bin/deputy-sandbox-vz --socket /tmp/test-vz.sock &
VZ_PID=$!
sleep 2
ls -la /tmp/test-vz.sock  # Should show the socket file
kill $VZ_PID

# Test via deputy (plugin will be discovered and started automatically)
# Note: Currently the VM boots but command execution is not yet implemented
DEPUTY_LOG_LEVEL=debug ./deputy exec --runtime plugin --plugin vz -- echo hello

# If you see "runtime=RUNTIME_PLUGIN" and "vz sandbox plugin listening" in the logs,
# the plugin architecture is working correctly!
```

> [!NOTE]
> Since command injection is not yet implemented, the command will appear to hang
> as the VM boots to a shell but doesn't execute the requested command. Press
> Ctrl+C to cancel. This demonstrates that:
> 1. Deputy discovers the plugin via PATH
> 2. The plugin starts and creates a Unix socket
> 3. Deputy communicates with the plugin via ConnectRPC
> 4. The VM boots successfully with the configured kernel and rootfs

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

> [!WARNING]
> These examples show the intended interface. Command execution inside the VM
> is not yet implemented. Currently the VM boots but commands are not injected.

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

# Sign with virtualization entitlement (required)
codesign --entitlements entitlements.plist --sign - deputy-sandbox-vz
```

### Running Tests

```bash
go test -v ./...
```

### Contributing

The main missing functionality is command injection and output capture. Here's what needs to be implemented:

1. **Command Injection**: Modify the kernel command line or use an init script that:
   - Reads the command from a configuration source (e.g., kernel parameters, virtio-serial)
   - Executes the command inside the VM
   - Captures stdout/stderr

2. **Output Streaming**: Use the virtio-console to stream output back to the host:
   - The serial port is already configured (`vz.NewFileHandleSerialPortAttachment`)
   - Need to parse and relay output as `ExecuteEvent_Output` messages

3. **Exit Code Detection**: Determine when the command completes and capture its exit code:
   - Could use a sentinel value written to the console
   - Or monitor for VM shutdown

4. **Timeout Handling**: Implement proper timeout support:
   - Stop the VM if execution exceeds the configured timeout
   - Return appropriate error events

See [apple/container](https://github.com/apple/container) for reference on how Apple implements similar functionality.

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
