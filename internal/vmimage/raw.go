package vmimage

import (
	"fmt"
	"os"
)

// RawDisk provides access to a raw disk image file.
// Raw images are the simplest format - direct 1:1 mapping of bytes.
type RawDisk struct {
	file *os.File
	size int64
}

// OpenRaw opens a raw disk image file.
func OpenRaw(path string) (*RawDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open raw disk image: %w", err)
	}

	info, err := f.Stat()
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("stat raw disk image: %w", err)
	}

	return &RawDisk{
		file: f,
		size: info.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (r *RawDisk) ReadAt(p []byte, off int64) (n int, err error) {
	return r.file.ReadAt(p, off)
}

// Close closes the underlying file.
func (r *RawDisk) Close() error {
	return r.file.Close()
}

// Size returns the size of the disk image.
func (r *RawDisk) Size() int64 {
	return r.size
}

// Format returns "raw".
func (r *RawDisk) Format() string {
	return string(FormatRaw)
}

var _ DiskImage = (*RawDisk)(nil)
