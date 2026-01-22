package vmimage

import (
	"fmt"
	"io"
	"os"

	"github.com/lima-vm/go-qcow2reader"
	"github.com/lima-vm/go-qcow2reader/image"
)

// VMDKDisk provides access to a VMDK disk image.
// VMDK (Virtual Machine Disk) is VMware's disk format, also used by VirtualBox.
// The go-qcow2reader library provides VMDK support through its multi-format capability.
type VMDKDisk struct {
	file *os.File
	img  image.Image
	size int64
}

// OpenVMDK opens a VMDK disk image file.
func OpenVMDK(path string) (*VMDKDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vmdk file: %w", err)
	}

	img, err := qcow2reader.Open(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse vmdk image: %w", err)
	}

	return &VMDKDisk{
		file: f,
		img:  img,
		size: img.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (v *VMDKDisk) ReadAt(p []byte, off int64) (n int, err error) {
	return v.img.ReadAt(p, off)
}

// Close closes the underlying image and file.
func (v *VMDKDisk) Close() error {
	var errs []error
	if closer, ok := v.img.(io.Closer); ok {
		if err := closer.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if v.file != nil {
		if err := v.file.Close(); err != nil {
			errs = append(errs, err)
		}
	}
	if len(errs) > 0 {
		return errs[0]
	}
	return nil
}

// Size returns the virtual size of the disk image.
func (v *VMDKDisk) Size() int64 {
	return v.size
}

// Format returns "vmdk".
func (v *VMDKDisk) Format() string {
	return string(FormatVMDK)
}

var _ DiskImage = (*VMDKDisk)(nil)
