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
- Docker (for creating rootfs on macOS)

## Quick Start (Ubuntu 24.04 LTS)

This section provides exact commands to get a working VM sandbox using Ubuntu 24.04 LTS (Noble Numbat).

### 1. Build and Install the Plugin

```bash
# From the deputy repository root
cd examples/sandbox-plugins/vz

# Build the plugin
go build -o deputy-sandbox-vz .

# Sign with virtualization entitlement (required by macOS)
codesign --entitlements entitlements.plist --sign - deputy-sandbox-vz

# Install to Go's bin directory (automatically discovered by deputy)
mkdir -p ~/go/bin
cp deputy-sandbox-vz ~/go/bin/

# Verify it's discoverable
ls ~/go/bin/deputy-sandbox-vz
```

**Plugin Discovery:** Deputy searches for sandbox plugins (`deputy-sandbox-*`) in:
1. Current working directory (for development)
2. `$GOPATH/bin` (if GOPATH is set)
3. `$HOME/go/bin` (default Go bin location)
4. All directories in `PATH`

### 2. Download Ubuntu Assets

Download the kernel and root filesystem from Ubuntu's official cloud images:

```bash
# Create the asset directory
mkdir -p ~/.deputy/vz
cd ~/.deputy/vz

# Download kernel (vmlinuz) - this is a gzip-compressed file
curl -LO https://cloud-images.ubuntu.com/releases/24.04/release/unpacked/ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic
mv ubuntu-24.04-server-cloudimg-arm64-vmlinuz-generic vmlinuz.gz

# Decompress the kernel
gunzip vmlinuz.gz

# Verify it's a proper ARM64 kernel
file vmlinuz
# Expected: Linux kernel ARM64 boot executable Image, little-endian, 4K pages

# Download root filesystem tarball
curl -LO https://cloud-images.ubuntu.com/releases/24.04/release/ubuntu-24.04-server-cloudimg-arm64-root.tar.xz
```

> **Note:** No initrd is needed! The Ubuntu kernel boots directly to the rootfs with virtio drivers built-in, achieving ~70ms boot times.

### 3. Create the Root Filesystem Image

Use Docker to create an ext4 disk image from the root tarball (macOS can't create ext4 natively):

```bash
cd ~/.deputy/vz

# Use Docker to create an ext4 rootfs (requires --privileged for loop mount)
docker run --rm --privileged -v ~/.deputy/vz:/output ubuntu:24.04 bash -c '
  set -ex
  apt-get update && apt-get install -y xz-utils e2fsprogs

  # Create a 2GB disk image (Ubuntu needs more space than Alpine)
  dd if=/dev/zero of=/output/rootfs.img bs=1M count=2048
  mkfs.ext4 -F /output/rootfs.img

  # Mount the image
  mkdir -p /mnt/rootfs
  mount -o loop /output/rootfs.img /mnt/rootfs

  # Extract the Ubuntu root filesystem
  tar -xJf /output/ubuntu-24.04-server-cloudimg-arm64-root.tar.xz -C /mnt/rootfs

  # Create deputy-init script for command execution
  cat > /mnt/rootfs/deputy-init << "INITSCRIPT"
#!/bin/bash
# deputy-init - Init script for Deputy VZ sandbox
#
# This script is executed as the init process (PID 1) inside the VM.
# It reads the base64-encoded command from the kernel cmdline parameter "deputy.cmd",
# executes it using eval, and reports the exit code via protocol markers.

# Mount essential filesystems
mount -t proc proc /proc 2>/dev/null
mount -t sysfs sys /sys 2>/dev/null
mount -t devtmpfs dev /dev 2>/dev/null

# Get the base64-encoded command from kernel cmdline
CMD_BASE64=""
for param in $(cat /proc/cmdline); do
    case "$param" in
        deputy.cmd=*)
            CMD_BASE64="${param#deputy.cmd=}"
            break
            ;;
    esac
done

if [ -z "$CMD_BASE64" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: No command provided (deputy.cmd not found in kernel cmdline)"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    exec /sbin/poweroff -f
fi

# Decode the command (space-separated, executed via eval)
CMD_DECODED=$(echo "$CMD_BASE64" | base64 -d 2>/dev/null)

if [ -z "$CMD_DECODED" ]; then
    echo "<<<DEPUTY_OUTPUT_START>>>"
    echo "<<<DEPUTY_STDERR>>>"
    echo "Error: Failed to decode command"
    echo "<<<DEPUTY_OUTPUT_END>>>"
    echo "<<<DEPUTY_EXIT_CODE:1>>>"
    exec /sbin/poweroff -f
fi

# Signal start of output
echo "<<<DEPUTY_OUTPUT_START>>>"
echo "<<<DEPUTY_STDOUT>>>"

# Create temporary files for capturing stdout and stderr
STDOUT_FILE="/tmp/deputy_stdout"
STDERR_FILE="/tmp/deputy_stderr"
touch "$STDOUT_FILE" "$STDERR_FILE"

# Execute the command using eval, capturing stdout and stderr separately
eval "$CMD_DECODED" >"$STDOUT_FILE" 2>"$STDERR_FILE"
EXIT_CODE=$?

# Output stdout
if [ -s "$STDOUT_FILE" ]; then
    cat "$STDOUT_FILE"
fi

# Output stderr if any
if [ -s "$STDERR_FILE" ]; then
    echo "<<<DEPUTY_STDERR>>>"
    cat "$STDERR_FILE"
fi

# Signal end of output and report exit code
echo "<<<DEPUTY_OUTPUT_END>>>"
echo "<<<DEPUTY_EXIT_CODE:${EXIT_CODE}>>>"

# Shutdown the VM
exec /sbin/poweroff -f
INITSCRIPT
  chmod +x /mnt/rootfs/deputy-init

  # Ensure essential directories exist
  mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run}

  umount /mnt/rootfs
  echo "SUCCESS: Created rootfs.img with Ubuntu and deputy-init"
'
```

### 4. Verify Your Setup

```bash
ls -la ~/.deputy/vz/
# Should show:
# - vmlinuz      (Linux kernel, ~35-40MB)
# - rootfs.img   (root filesystem, 2GB)

# Verify kernel format
file ~/.deputy/vz/vmlinuz
# Expected: Linux kernel ARM64 boot executable Image, little-endian, 4K pages
```

### 5. Test the Plugin

```bash
# Build deputy if not already built
cd /path/to/deputy
go build -o deputy .

# Test plugin discovery - start the plugin manually to verify it works
~/go/bin/deputy-sandbox-vz --socket /tmp/test-vz.sock &
VZ_PID=$!
sleep 2
ls -la /tmp/test-vz.sock  # Should show the socket file
kill $VZ_PID

# Test via deputy (full end-to-end)
./deputy exec --runtime plugin --plugin vz -- echo "hello from VM"

# Try more commands
./deputy exec --runtime plugin --plugin vz -- uname -a
# Expected: Linux (none) 6.8.0-90-generic ... aarch64 GNU/Linux

./deputy exec --runtime plugin --plugin vz -- cat /etc/os-release
# Expected: PRETTY_NAME="Ubuntu 24.04.3 LTS" ...
```

## Environment Variables

| Variable | Description | Default |
|----------|-------------|---------|
| `DEPUTY_VZ_KERNEL` | Path to Linux kernel (vmlinuz) | `~/.deputy/vz/vmlinuz` |
| `DEPUTY_VZ_ROOTFS` | Path to root filesystem image | `~/.deputy/vz/rootfs.img` |

Override the defaults for custom setups:

```bash
export DEPUTY_VZ_KERNEL=/path/to/custom/vmlinuz
export DEPUTY_VZ_ROOTFS=/path/to/custom/rootfs.img
deputy exec --runtime plugin --plugin vz -- ls -la
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

### Debian

```bash
# Download Debian cloud image
curl -LO https://cloud.debian.org/images/cloud/bookworm/latest/debian-12-generic-arm64.raw

# Extract or download kernel
# Copy rootfs
cp debian-12-generic-arm64.raw ~/.deputy/vz/rootfs.img
```

### Fedora

```bash
# Download Fedora kernel and initrd
RELEASE=40
curl -LO https://download.fedoraproject.org/pub/fedora/linux/releases/${RELEASE}/Everything/aarch64/os/images/pxeboot/vmlinuz
curl -LO https://download.fedoraproject.org/pub/fedora/linux/releases/${RELEASE}/Everything/aarch64/os/images/pxeboot/initrd.img
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
| Startup Time | ~1ms | ~5ms | ~100ms | ~50ms | ~70ms |
| Overhead | None | Low | Low | Medium | Medium |

## Limitations

- **macOS Only**: Requires macOS 11.0+ on Apple Silicon
- **Startup Overhead**: VMs take ~70-200ms to boot (vs ~10ms for containers)
- **Asset Management**: Requires pre-built kernel and rootfs images
- **No GPU Passthrough**: GPU workloads not supported
- **Disk Space**: Rootfs images consume disk space (~2GB for Ubuntu)

## Troubleshooting

### "Virtualization.framework not available"

Ensure you're running on:
- macOS 11.0 (Big Sur) or later
- Apple Silicon (M1/M2/M3/M4)

Intel Macs are **not supported** by Virtualization.framework for Linux VMs.

### "plugin not found" or "runtime RUNTIME_PLUGIN is not available"

```bash
# Check if plugin is installed in ~/go/bin
ls -la ~/go/bin/deputy-sandbox-vz
# Should show: -rwxr-xr-x

# Verify plugin is signed with virtualization entitlement
codesign -dv ~/go/bin/deputy-sandbox-vz 2>&1 | grep -i entitlement
# Should show entitlements

# Test plugin starts correctly
~/go/bin/deputy-sandbox-vz --socket /tmp/test.sock &
sleep 2
ls /tmp/test.sock && echo "Plugin started OK"
kill %1

# If plugin hangs, check for extended attributes
xattr ~/go/bin/deputy-sandbox-vz
# If "com.apple.provenance" exists, remove it:
xattr -d com.apple.provenance ~/go/bin/deputy-sandbox-vz
codesign --entitlements entitlements.plist --force --sign - ~/go/bin/deputy-sandbox-vz
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
# Re-sign with entitlements (from the vz plugin directory)
cd examples/sandbox-plugins/vz
codesign --entitlements entitlements.plist --force --sign - ~/go/bin/deputy-sandbox-vz

# Verify signature
codesign -dvvv ~/go/bin/deputy-sandbox-vz
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

### VM boots but command doesn't execute

Check that the rootfs contains the `deputy-init` script:
```bash
# Re-create rootfs with deputy-init (see step 3 above)
```

### No output from VM

Enable debug logging to see console output:
```bash
DEPUTY_LOG_LEVEL=debug deputy exec --runtime plugin --plugin vz -- echo hello
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

### Command Execution Protocol

Commands are passed to the VM via kernel command line parameters:
1. Command and arguments are joined with spaces
2. The result is base64-encoded
3. Passed as `deputy.cmd=<base64>` kernel parameter

The `deputy-init` script inside the VM:
1. Reads `deputy.cmd` from `/proc/cmdline`
2. Base64 decodes and executes via `eval`
3. Outputs results with protocol markers:
   - `<<<DEPUTY_OUTPUT_START>>>` - marks beginning of output
   - `<<<DEPUTY_STDOUT>>>` - switches to stdout
   - `<<<DEPUTY_STDERR>>>` - switches to stderr
   - `<<<DEPUTY_OUTPUT_END>>>` - marks end of output
   - `<<<DEPUTY_EXIT_CODE:N>>>` - reports exit code

<details>
<summary>Historical: Alpine Linux Setup (Experimental)</summary>

> [!WARNING]
> Alpine Linux support is experimental. The Alpine virt kernel uses modular virtio drivers
> that require a compatible initrd to load. This can cause "No such device" errors when
> mounting the rootfs. Ubuntu is recommended instead.

### Alpine Setup (for reference only)

```bash
mkdir -p ~/.deputy/vz && cd ~/.deputy/vz

# Download Alpine virt ISO
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-virt-3.19.0-aarch64.iso

# Extract kernel and initramfs
bsdtar -xf alpine-virt-3.19.0-aarch64.iso boot/vmlinuz-virt boot/initramfs-virt
mv boot/vmlinuz-virt vmlinuz.efi
mv boot/initramfs-virt initrd.img
rmdir boot

# Extract the raw kernel from the EFI stub
OFFSET=$(xxd vmlinuz.efi | grep "1f8b 08" | head -1 | cut -d: -f1)
OFFSET_DEC=$((16#${OFFSET}))
dd if=vmlinuz.efi bs=1 skip=$OFFSET_DEC of=vmlinux.gz 2>/dev/null
gunzip -f vmlinux.gz 2>/dev/null || true
mv vmlinux vmlinuz

# Download minirootfs
curl -LO https://dl-cdn.alpinelinux.org/alpine/v3.19/releases/aarch64/alpine-minirootfs-3.19.0-aarch64.tar.gz

# Create rootfs with Docker
docker run --rm --privileged -v ~/.deputy/vz:/output alpine:3.19 sh -c '
  apk add --no-cache e2fsprogs
  dd if=/dev/zero of=/output/rootfs.img bs=1M count=256
  mkfs.ext4 -F /output/rootfs.img
  mkdir -p /mnt/rootfs
  mount -o loop /output/rootfs.img /mnt/rootfs
  tar -xzf /output/alpine-minirootfs-3.19.0-aarch64.tar.gz -C /mnt/rootfs
  mkdir -p /mnt/rootfs/{dev,proc,sys,tmp,run}
  umount /mnt/rootfs
'
```

**Known issues:**
- The Alpine virt kernel has virtio as a loadable module, not built-in
- The stock Alpine initrd expects specific boot parameters for module loading
- Mount errors like "No such device" occur when virtio_blk module isn't loaded

</details>

## References

- [vz library](https://github.com/Code-Hex/vz) - Go bindings for Virtualization.framework
- [Apple Virtualization.framework](https://developer.apple.com/documentation/virtualization)
- [apple/container](https://github.com/apple/container) - Apple's container runtime using the same framework
- [Ubuntu Cloud Images](https://cloud-images.ubuntu.com/) - Official ARM64 images
- [Deputy Sandbox Architecture](../../../docs/design/sandbox-architecture.md) - Design documentation
