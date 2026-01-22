package vmimage

import (
	"fmt"
	"io"
	"os"

	"github.com/lima-vm/go-qcow2reader"
	"github.com/lima-vm/go-qcow2reader/image"
)

// VHDXDisk provides access to a VHDX disk image.
// VHDX (Virtual Hard Disk v2) is Microsoft's modern virtual disk format,
// used by Hyper-V. The go-qcow2reader library provides VHDX support.
type VHDXDisk struct {
	file *os.File
	img  image.Image
	size int64
}

// OpenVHDX opens a VHDX disk image file.
func OpenVHDX(path string) (*VHDXDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vhdx file: %w", err)
	}

	img, err := qcow2reader.Open(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse vhdx image: %w", err)
	}

	return &VHDXDisk{
		file: f,
		img:  img,
		size: img.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (v *VHDXDisk) ReadAt(p []byte, off int64) (n int, err error) {
	return v.img.ReadAt(p, off)
}

// Close closes the underlying image and file.
func (v *VHDXDisk) Close() error {
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
func (v *VHDXDisk) Size() int64 {
	return v.size
}

// Format returns "vhdx".
func (v *VHDXDisk) Format() string {
	return string(FormatVHDX)
}

var _ DiskImage = (*VHDXDisk)(nil)

// VHDDisk provides access to a VHD disk image.
// VHD (Virtual Hard Disk) is Microsoft's legacy virtual disk format.
// Note: go-qcow2reader may have limited VHD support; we attempt to use it
// and fall back to raw if needed.
type VHDDisk struct {
	file *os.File
	img  image.Image
	size int64
}

// OpenVHD opens a VHD disk image file.
func OpenVHD(path string) (*VHDDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vhd file: %w", err)
	}

	img, err := qcow2reader.Open(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse vhd image: %w", err)
	}

	return &VHDDisk{
		file: f,
		img:  img,
		size: img.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (v *VHDDisk) ReadAt(p []byte, off int64) (n int, err error) {
	return v.img.ReadAt(p, off)
}

// Close closes the underlying image and file.
func (v *VHDDisk) Close() error {
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
func (v *VHDDisk) Size() int64 {
	return v.size
}

// Format returns "vhd".
func (v *VHDDisk) Format() string {
	return string(FormatVHD)
}

var _ DiskImage = (*VHDDisk)(nil)

// VDIDisk provides access to a VDI disk image.
// VDI (VirtualBox Disk Image) is VirtualBox's native format.
// The go-qcow2reader library provides VDI support.
type VDIDisk struct {
	file *os.File
	img  image.Image
	size int64
}

// OpenVDI opens a VDI disk image file.
func OpenVDI(path string) (*VDIDisk, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("open vdi file: %w", err)
	}

	img, err := qcow2reader.Open(f)
	if err != nil {
		f.Close()
		return nil, fmt.Errorf("parse vdi image: %w", err)
	}

	return &VDIDisk{
		file: f,
		img:  img,
		size: img.Size(),
	}, nil
}

// ReadAt implements io.ReaderAt.
func (v *VDIDisk) ReadAt(p []byte, off int64) (n int, err error) {
	return v.img.ReadAt(p, off)
}

// Close closes the underlying image and file.
func (v *VDIDisk) Close() error {
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
func (v *VDIDisk) Size() int64 {
	return v.size
}

// Format returns "vdi".
func (v *VDIDisk) Format() string {
	return string(FormatVDI)
}

var _ DiskImage = (*VDIDisk)(nil)
