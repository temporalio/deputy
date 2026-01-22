// Package vmimage provides abstractions for reading virtual machine disk images
// and their filesystems without requiring root privileges or kernel mounts.
//
// The package supports multiple disk image formats (qcow2, vmdk, vhd, raw) and
// filesystem types (ext4, xfs) through a layered architecture:
//
//   - DiskImage: Provides io.ReaderAt access to disk image contents
//   - Partition: Represents a partition within a disk image
//   - Filesystem adapters in fsys/ package provide fs.FS for each partition
//
// This enables Deputy to scan VM images for vulnerabilities and secrets using
// the same infrastructure as container image scanning.
package vmimage

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// DiskImage provides random read access to a disk image's contents.
// Implementations handle format-specific details (qcow2 compression, VMDK sparse files, etc.)
// and present a unified block device view.
type DiskImage interface {
	io.ReaderAt
	io.Closer

	// Size returns the virtual size of the disk image in bytes.
	Size() int64

	// Format returns the disk image format (e.g., "qcow2", "vmdk", "raw").
	Format() string
}

// DiskFormat represents a supported disk image format.
type DiskFormat string

const (
	FormatRaw   DiskFormat = "raw"
	FormatQCOW2 DiskFormat = "qcow2"
	FormatVMDK  DiskFormat = "vmdk"
	FormatVHD   DiskFormat = "vhd"
	FormatVHDX  DiskFormat = "vhdx"
	FormatVDI   DiskFormat = "vdi"
)

// ErrUnsupportedFormat is returned when attempting to open an unsupported disk image format.
var ErrUnsupportedFormat = errors.New("unsupported disk image format")

// ErrInvalidImage is returned when a disk image file is corrupted or invalid.
var ErrInvalidImage = errors.New("invalid disk image")

// Open opens a disk image file, auto-detecting the format from the file extension
// and magic bytes. It returns a DiskImage that provides random read access to
// the disk's virtual contents.
func Open(path string) (DiskImage, error) {
	// First, check if file exists and is readable
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open disk image: %w", err)
	}

	// Read magic bytes for format detection
	magic := make([]byte, 8)
	if _, err := f.Read(magic); err != nil {
		f.Close()
		return nil, fmt.Errorf("read disk image header: %w", err)
	}
	f.Close()

	// Detect format from magic bytes first, then fall back to extension
	format := detectFormat(path, magic)

	switch format {
	case FormatRaw:
		return OpenRaw(path)
	case FormatQCOW2:
		return OpenQCOW2(path)
	case FormatVMDK:
		return OpenVMDK(path)
	case FormatVHDX:
		return OpenVHDX(path)
	case FormatVHD:
		return OpenVHD(path)
	case FormatVDI:
		return OpenVDI(path)
	default:
		return nil, fmt.Errorf("%w: %s", ErrUnsupportedFormat, format)
	}
}

// detectFormat determines the disk image format from magic bytes and file extension.
func detectFormat(path string, magic []byte) DiskFormat {
	// Check magic bytes first (most reliable)
	switch {
	case string(magic[:4]) == "QFI\xfb": // QCOW2
		return FormatQCOW2
	case string(magic[:4]) == "KDMV": // VMDK sparse
		return FormatVMDK
	case string(magic[:8]) == "vhdxfile": // VHDX
		return FormatVHDX
	case string(magic[:8]) == "conectix": // VHD (at end of file, but some tools put marker at start)
		return FormatVHD
	case string(magic[:4]) == "<<< ": // VDI
		return FormatVDI
	}

	// Fall back to extension
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".qcow2", ".qcow":
		return FormatQCOW2
	case ".vmdk":
		return FormatVMDK
	case ".vhd":
		return FormatVHD
	case ".vhdx":
		return FormatVHDX
	case ".vdi":
		return FormatVDI
	case ".raw", ".img", ".bin":
		return FormatRaw
	default:
		// Default to raw for unknown extensions
		return FormatRaw
	}
}

// OpenRootfs opens a raw filesystem image (e.g., ext4.img) directly without
// partition table parsing. This is useful for rootfs images that don't have
// a partition table.
func OpenRootfs(path string) (DiskImage, error) {
	return OpenRaw(path)
}

// FormatFromPath returns the likely disk format based on file extension.
// This is useful for quick checks without reading the file.
func FormatFromPath(path string) DiskFormat {
	ext := strings.ToLower(filepath.Ext(path))
	switch ext {
	case ".qcow2", ".qcow":
		return FormatQCOW2
	case ".vmdk":
		return FormatVMDK
	case ".vhd":
		return FormatVHD
	case ".vhdx":
		return FormatVHDX
	case ".vdi":
		return FormatVDI
	default:
		return FormatRaw
	}
}
