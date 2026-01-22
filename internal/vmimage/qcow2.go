package vmimage

import (
	"fmt"
	"io"
	"os"

	"github.com/lima-vm/go-qcow2reader"
	"github.com/lima-vm/go-qcow2reader/image"
)

// QCOW2Disk provides access to a QCOW2 disk image.
// QCOW2 (QEMU Copy-On-Write version 2) is a common format for KVM/QEMU virtual machines.
// It supports compression, encryption, and backing files (snapshots).
type QCOW2Disk struct {
	file *os.File
	img  image.Image
	size int64
}

// OpenQCOW2 opens a QCOW2 disk image file.
// The go-qcow2reader library handles decompression and sparse file handling transparently.
func OpenQCOW2(path string) (*QCOW2Disk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open qcow2 file: %w", err)
	}

	img, err := qcow2reader.Open(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse qcow2 image: %w", err)
	}

	return &QCOW2Disk{
		file: f,
		img:  img,
		size: img.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (q *QCOW2Disk) ReadAt(p []byte, off int64) (n int, err error) {
	return q.img.ReadAt(p, off)
}

// Close closes the underlying image and file.
func (q *QCOW2Disk) Close() error {
	var errs []error
	if closer, ok := q.img.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if q.file != nil {
		if err := q.file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Size returns the virtual size of the disk image.
func (q *QCOW2Disk) Size() int64 {
	return q.size
}

// Format returns "qcow2".
func (q *QCOW2Disk) Format() string {
	return string(FormatQCOW2)
}

var _ DiskImage = (*QCOW2Disk)(nil)
