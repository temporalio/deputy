// Package fsys provides filesystem implementations for virtual machine disk images.
// It wraps filesystem-specific parsing libraries to provide a unified fs.FS interface
// that can be used with Deputy's existing scanning infrastructure.
package fsys

import (
	"errors"
	"io"
	"io/fs"
)

// FilesystemType represents a supported filesystem type.
type FilesystemType string

const (
	FilesystemExt4 FilesystemType = "ext4"
	FilesystemXFS  FilesystemType = "xfs"
)

// ErrUnsupportedFilesystem is returned when a filesystem type is not supported.
var ErrUnsupportedFilesystem = errors.New("unsupported filesystem type")

// PartitionReader provides read access to a partition within a disk image.
// It implements io.ReaderAt for random access to the partition's contents.
type PartitionReader struct {
	disk   io.ReaderAt
	offset int64
	size   int64
	pos    int64
}

// NewPartitionReader creates a reader for a partition at the given offset and size.
func NewPartitionReader(disk io.ReaderAt, offset, size int64) *PartitionReader {
	return &PartitionReader{
		disk:   disk,
		offset: offset,
		size:   size,
		pos:    0,
	}
}

// Read implements io.Reader.
func (r *PartitionReader) Read(p []byte) (n int, err error) {
	if r.pos >= r.size {
		return 0, io.EOF
	}
	remaining := r.size - r.pos
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	n, err = r.disk.ReadAt(p, r.offset+r.pos)
	r.pos += int64(n)
	return n, err
}

// ReadAt implements io.ReaderAt.
func (r *PartitionReader) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= r.size {
		return 0, io.EOF
	}
	remaining := r.size - off
	if int64(len(p)) > remaining {
		p = p[:remaining]
	}
	return r.disk.ReadAt(p, r.offset+off)
}

// Seek implements io.Seeker.
func (r *PartitionReader) Seek(offset int64, whence int) (int64, error) {
	var newPos int64
	switch whence {
	case io.SeekStart:
		newPos = offset
	case io.SeekCurrent:
		newPos = r.pos + offset
	case io.SeekEnd:
		newPos = r.size + offset
	default:
		return 0, errors.New("invalid whence")
	}
	if newPos < 0 {
		return 0, errors.New("negative position")
	}
	r.pos = newPos
	return newPos, nil
}

// Size returns the size of the partition.
func (r *PartitionReader) Size() int64 {
	return r.size
}

// OpenFilesystem opens a filesystem at the given partition within a disk image.
// The fsType parameter specifies the expected filesystem type (ext4, xfs, etc.).
// If fsType is empty, the function will attempt to auto-detect the filesystem.
func OpenFilesystem(disk io.ReaderAt, offset, size int64, fsType FilesystemType) (fs.FS, error) {
	reader := NewPartitionReader(disk, offset, size)

	switch fsType {
	case FilesystemExt4, "": // Default to ext4 for auto-detection
		return OpenExt4(reader)
	case FilesystemXFS:
		return nil, errors.New("xfs filesystem support not yet implemented")
	default:
		return nil, ErrUnsupportedFilesystem
	}
}

// DetectFilesystem attempts to detect the filesystem type from magic bytes.
func DetectFilesystem(disk io.ReaderAt, offset int64) (FilesystemType, error) {
	// Read the superblock area (ext4 superblock starts at offset 1024)
	buf := make([]byte, 2048)
	_, err := disk.ReadAt(buf, offset)
	if err != nil {
		return "", err
	}

	// Check for ext4 magic (0xEF53 at offset 0x438 from partition start)
	// Superblock is at offset 1024, magic is at offset 56 within superblock
	if len(buf) >= 1080 && buf[1024+56] == 0x53 && buf[1024+57] == 0xEF {
		return FilesystemExt4, nil
	}

	// Check for XFS magic ("XFSB" at offset 0)
	if len(buf) >= 4 && string(buf[:4]) == "XFSB" {
		return FilesystemXFS, nil
	}

	return "", ErrUnsupportedFilesystem
}
