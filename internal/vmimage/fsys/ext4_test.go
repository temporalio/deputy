package fsys

import (
	"io"
	"testing"
)

func TestNewPartitionReader(t *testing.T) {
	// Create a mock reader with some test data
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mockReader := &mockReaderAt{data: data}
	partSize := int64(len(data))

	pr := NewPartitionReader(mockReader, 0, partSize)

	if pr.Size() != partSize {
		t.Errorf("Size() = %d, want %d", pr.Size(), partSize)
	}

	// Test ReadAt
	buf := make([]byte, 256)
	n, err := pr.ReadAt(buf, 0)
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
}

func TestNewPartitionReaderWithOffset(t *testing.T) {
	// Create a mock reader with test data
	data := make([]byte, 8192)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mockReader := &mockReaderAt{data: data}

	// Create a partition reader starting at offset 1024
	offset := int64(1024)
	partSize := int64(2048)
	pr := NewPartitionReader(mockReader, offset, partSize)

	if pr.Size() != partSize {
		t.Errorf("Size() = %d, want %d", pr.Size(), partSize)
	}

	// Read from the beginning of the partition (which is offset 1024 in the underlying data)
	buf := make([]byte, 256)
	n, err := pr.ReadAt(buf, 0)
	if err != nil {
		t.Fatalf("ReadAt failed: %v", err)
	}
	if n != len(buf) {
		t.Errorf("ReadAt returned %d bytes, want %d", n, len(buf))
	}

	// Verify the data matches the underlying data at offset 1024
	for i, b := range buf {
		expected := byte((1024 + i) % 256)
		if b != expected {
			t.Errorf("ReadAt[%d] = %d, want %d (underlying offset %d)", i, b, expected, 1024+i)
			break
		}
	}
}

func TestPartitionReaderBoundary(t *testing.T) {
	data := make([]byte, 4096)
	for i := range data {
		data[i] = byte(i % 256)
	}

	mockReader := &mockReaderAt{data: data}
	partSize := int64(len(data))
	pr := NewPartitionReader(mockReader, 0, partSize)

	// Try to read past the end
	buf := make([]byte, 256)
	n, err := pr.ReadAt(buf, partSize-128)
	if err != nil && err != io.EOF {
		t.Fatalf("ReadAt at boundary failed: %v", err)
	}
	// Should read only 128 bytes (to the end)
	if n != 128 {
		t.Errorf("ReadAt at boundary returned %d bytes, want 128", n)
	}
}

// mockReaderAt implements io.ReaderAt for testing
type mockReaderAt struct {
	data []byte
}

func (m *mockReaderAt) ReadAt(p []byte, off int64) (n int, err error) {
	if off >= int64(len(m.data)) {
		return 0, io.EOF
	}
	n = copy(p, m.data[off:])
	if off+int64(n) >= int64(len(m.data)) {
		err = io.EOF
	}
	return n, err
}
