package vmimage

import (
	"os"
	"path/filepath"
	"testing"
)

func TestFormatFromPath(t *testing.T) {
	tests := []struct {
		path     string
		expected DiskFormat
	}{
		{"disk.qcow2", FormatQCOW2},
		{"disk.QCOW2", FormatQCOW2},
		{"disk.qcow", FormatQCOW2},
		{"disk.vmdk", FormatVMDK},
		{"disk.vhd", FormatVHD},
		{"disk.vhdx", FormatVHDX},
		{"disk.vdi", FormatVDI},
		{"disk.raw", FormatRaw},
		{"disk.img", FormatRaw},
		{"disk.bin", FormatRaw},
		{"disk.unknown", FormatRaw},
		{"disk", FormatRaw},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := FormatFromPath(tt.path)
			if got != tt.expected {
				t.Errorf("FormatFromPath(%q) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name     string
		magic    []byte
		path     string
		expected DiskFormat
	}{
		{
			name:     "qcow2 magic",
			magic:    []byte{'Q', 'F', 'I', 0xfb, 0, 0, 0, 0},
			path:     "disk.qcow2",
			expected: FormatQCOW2,
		},
		{
			name:     "vmdk magic",
			magic:    []byte{'K', 'D', 'M', 'V', 0, 0, 0, 0},
			path:     "disk.vmdk",
			expected: FormatVMDK,
		},
		{
			name:     "vhdx magic",
			magic:    []byte("vhdxfile"),
			path:     "disk.vhdx",
			expected: FormatVHDX,
		},
		{
			name:     "fallback to extension",
			magic:    []byte{0, 0, 0, 0, 0, 0, 0, 0},
			path:     "disk.qcow2",
			expected: FormatQCOW2,
		},
		{
			name:     "unknown defaults to raw",
			magic:    []byte{0, 0, 0, 0, 0, 0, 0, 0},
			path:     "disk.dat",
			expected: FormatRaw,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectFormat(tt.path, tt.magic)
			if got != tt.expected {
				t.Errorf("detectFormat(%q, magic) = %q, want %q", tt.path, got, tt.expected)
			}
		})
	}
}

func TestOpenRaw(t *testing.T) {
	// Create a temporary raw disk image
	tmpDir := t.TempDir()
	imgPath := filepath.Join(tmpDir, "test.raw")

	// Write some test data
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}
	if err := os.WriteFile(imgPath, data, 0644); err != nil {
		t.Fatalf("failed to create test image: %v", err)
	}

	// Open the raw image
	disk, err := OpenRaw(imgPath)
	if err != nil {
		t.Fatalf("OpenRaw failed: %v", err)
	}
	defer disk.Close()

	// Check size
	if disk.Size() != int64(len(data)) {
		t.Errorf("Size() = %d, want %d", disk.Size(), len(data))
	}

	// Check format
	if disk.Format() != string(FormatRaw) {
		t.Errorf("Format() = %q, want %q", disk.Format(), FormatRaw)
	}

	// Test ReadAt
	buf := make([]byte, 256)
	n, err := disk.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if n != len(buf) {
		t.Errorf("ReadAt returned %d bytes, want %d", n, len(buf))
	}
	for i, b := range buf {
		if b != byte(i%256) {
			t.Errorf("ReadAt[%d] = %d, want %d", i, b, byte(i%256))
			break
		}
	}

	// Test ReadAt at offset
	n, err = disk.ReadAt(buf, 1024)
	if err != nil {
		t.Fatalf("ReadAt at offset failed: %v", err)
	}
	if n != len(buf) {
		t.Errorf("ReadAt at offset returned %d bytes, want %d", n, len(buf))
	}
	for i, b := range buf {
		expected := byte((1024 + i) % 256)
		if b != expected {
			t.Errorf("ReadAt[%d] at offset 1024 = %d, want %d", i, b, expected)
			break
		}
	}
}

func TestOpenNonExistent(t *testing.T) {
	_, err := Open("/nonexistent/path/disk.qcow2")
	if err == nil {
		t.Error("Open on non-existent file should return error")
	}
}
