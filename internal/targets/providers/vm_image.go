package providers

import (
	"context"
	"fmt"
	"io/fs"
	"log/slog"
	"path/filepath"
	"strconv"
	"strings"

	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/vmimage"
	"github.com/temporalio/deputy/internal/vmimage/fsys"
)

// priorityVMImage determines detection order relative to other providers.
// VM images have priority 70, which is:
//   - Lower than local Git repos (100) - prefer Git if .git exists
//   - Lower than container images (75) - container images are more common
//   - Higher than plain directories (50) - prefer VM if scheme/extension matches
const priorityVMImage = 70

// vmImageProvider implements [targets.Provider] for VM disk images and rootfs images.
type vmImageProvider struct{}

func (vmImageProvider) Priority() int { return priorityVMImage }

func (vmImageProvider) Detect(_ context.Context, target string) bool {
	// Check for explicit schemes
	if strings.HasPrefix(target, "vm://") ||
		strings.HasPrefix(target, "rootfs://") {
		return true
	}

	// Check for file extensions
	ext := strings.ToLower(filepath.Ext(target))
	switch ext {
	case ".qcow2", ".qcow", ".vmdk", ".vhd", ".vhdx", ".vdi":
		return true
	case ".raw", ".img":
		// Only match these if they don't look like container tarballs
		// and aren't being picked up by other providers
		return !strings.Contains(strings.ToLower(target), "docker") &&
			!strings.Contains(strings.ToLower(target), "oci")
	}

	return false
}

func (vmImageProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	// Parse target to get the path
	path, isRootfs := parseVMTarget(target)
	if path == "" {
		return targets.Materialized{}, fmt.Errorf("invalid VM target %q: expected vm://path or rootfs://path", target)
	}

	meta := targets.Descriptor{
		Kind:    targets.KindVMImage,
		Target:  target,
		Options: opts,
		Provenance: map[string]string{
			"path": path,
		},
	}

	// Open the disk image
	var disk vmimage.DiskImage
	var err error

	if isRootfs {
		// For rootfs, treat as raw filesystem image (no partition table)
		disk, err = vmimage.OpenRootfs(path)
		meta.Provenance["type"] = "rootfs"
	} else {
		disk, err = vmimage.Open(path)
		meta.Provenance["type"] = "disk"
	}

	if err != nil {
		return targets.Materialized{}, fmt.Errorf("open disk image %q: %w", path, err)
	}

	meta.Provenance["format"] = disk.Format()

	// Determine how to handle partitions
	partitionOpt := strings.TrimSpace(opts["partition"])

	var fsFS fs.FS
	var cleanup func()

	if isRootfs {
		// Rootfs images don't have partition tables - they're raw filesystems
		fsFS, err = openRootfsFilesystem(disk)
		if err != nil {
			disk.Close()
			return targets.Materialized{}, fmt.Errorf("open rootfs filesystem: %w", err)
		}
		cleanup = func() { disk.Close() }
	} else {
		// Regular disk image - parse partition table
		fsFS, cleanup, err = openDiskFilesystem(ctx, disk, partitionOpt, meta.Provenance)
		if err != nil {
			disk.Close()
			return targets.Materialized{}, err
		}
	}

	return targets.Materialized{
		FS:      fsFS,
		Path:    path,
		Meta:    meta,
		Cleanup: cleanup,
	}, nil
}

// parseVMTarget extracts the path from a VM target string.
// Returns the path and a boolean indicating if it's a rootfs image.
func parseVMTarget(target string) (string, bool) {
	if after, ok := strings.CutPrefix(target, "vm://"); ok {
		return after, false
	}
	if after, ok := strings.CutPrefix(target, "rootfs://"); ok {
		return after, true
	}
	// Bare path - determine type from extension
	ext := strings.ToLower(filepath.Ext(target))
	if ext == ".ext4" || ext == ".xfs" || ext == ".btrfs" {
		return target, true // Filesystem image
	}
	return target, false // Disk image
}

// openRootfsFilesystem opens a filesystem from a raw rootfs image (no partition table).
func openRootfsFilesystem(disk vmimage.DiskImage) (fs.FS, error) {
	// Detect filesystem type
	fsType, err := fsys.DetectFilesystem(disk, 0)
	if err != nil {
		// Default to ext4
		fsType = fsys.FilesystemExt4
	}

	// Open filesystem at offset 0 (no partition table)
	return fsys.OpenFilesystem(disk, 0, disk.Size(), fsType)
}

// openDiskFilesystem opens a filesystem from a partitioned disk image.
func openDiskFilesystem(ctx context.Context, disk vmimage.DiskImage, partitionOpt string, provenance map[string]string) (fs.FS, func(), error) {
	// Read partition table
	pt, err := vmimage.ReadPartitions(disk)
	if err != nil {
		// No partition table - treat as raw filesystem
		slog.DebugContext(ctx, "no partition table found, treating as raw filesystem",
			"error", err,
		)
		fs, err := openRootfsFilesystem(disk)
		if err != nil {
			return nil, nil, fmt.Errorf("open raw filesystem: %w", err)
		}
		provenance["partition_table"] = "none"
		return fs, func() { disk.Close() }, nil
	}

	provenance["partition_table"] = pt.Type
	provenance["partition_count"] = strconv.Itoa(len(pt.Partitions))

	var partition *vmimage.Partition

	switch partitionOpt {
	case "", "auto":
		// Auto-detect root partition
		partition, err = pt.FindRootPartition()
		if err != nil {
			// No Linux partition found - this might be a raw filesystem with boot code
			// that looks like an MBR (e.g., SYSLINUX). Try treating as raw filesystem.
			slog.DebugContext(ctx, "no Linux partition found, checking for raw filesystem at offset 0",
				"error", err,
			)
			fsType, detectErr := fsys.DetectFilesystem(disk, 0)
			if detectErr == nil {
				slog.DebugContext(ctx, "found raw filesystem at offset 0",
					"type", fsType,
				)
				fs, openErr := openRootfsFilesystem(disk)
				if openErr == nil {
					provenance["partition_table"] = "none"
					provenance["partition_selection"] = "raw"
					provenance["filesystem_type"] = string(fsType)
					return fs, func() { disk.Close() }, nil
				}
			}
			return nil, nil, fmt.Errorf("find root partition: %w", err)
		}
		provenance["partition_selection"] = "auto"

	case "all":
		// Scan all partitions - for now, just use the root partition
		// TODO: Implement merged filesystem view for scanning all partitions
		partition, err = pt.FindRootPartition()
		if err != nil {
			return nil, nil, fmt.Errorf("find root partition: %w", err)
		}
		provenance["partition_selection"] = "all"
		slog.WarnContext(ctx, "scanning all partitions not yet fully implemented, using root partition")

	default:
		// Explicit partition number
		index, parseErr := strconv.Atoi(partitionOpt)
		if parseErr != nil {
			return nil, nil, fmt.Errorf("invalid partition number %q: %w", partitionOpt, parseErr)
		}
		partition, err = pt.GetPartition(index)
		if err != nil {
			return nil, nil, fmt.Errorf("get partition %d: %w", index, err)
		}
		provenance["partition_selection"] = partitionOpt
	}

	provenance["partition_index"] = strconv.Itoa(partition.Index)
	provenance["partition_type"] = string(partition.Type)
	provenance["partition_start"] = strconv.FormatInt(partition.Start, 10)
	provenance["partition_size"] = strconv.FormatInt(partition.Size, 10)

	slog.DebugContext(ctx, "opening filesystem on partition",
		"index", partition.Index,
		"type", partition.Type,
		"start", partition.Start,
		"size", partition.Size,
	)

	// Detect and open filesystem
	fsType, err := fsys.DetectFilesystem(disk, partition.Start)
	if err != nil {
		// Default to ext4 for Linux partitions
		if partition.Type == vmimage.PartitionTypeLinux {
			fsType = fsys.FilesystemExt4
		} else {
			return nil, nil, fmt.Errorf("detect filesystem type: %w", err)
		}
	}

	provenance["filesystem_type"] = string(fsType)

	fs, err := fsys.OpenFilesystem(disk, partition.Start, partition.Size, fsType)
	if err != nil {
		return nil, nil, fmt.Errorf("open %s filesystem: %w", fsType, err)
	}

	return fs, func() { disk.Close() }, nil
}

var _ targets.Provider = (*vmImageProvider)(nil)
var _ targets.PriorityProvider = (*vmImageProvider)(nil)
