package targets

import (
	"debug/buildinfo"
)

// BinaryType represents the type of binary detected.
type BinaryType int

const (
	// BinaryTypeUnknown indicates the file is not a recognized binary.
	BinaryTypeUnknown BinaryType = iota
	// BinaryTypeGo indicates a Go binary with embedded buildinfo.
	BinaryTypeGo
	// BinaryTypeRust indicates a Rust binary (detected by SCALIBR at scan time).
	BinaryTypeRust
)

// String returns a human-readable name for the binary type.
func (t BinaryType) String() string {
	switch t {
	case BinaryTypeGo:
		return "go"
	case BinaryTypeRust:
		return "rust"
	default:
		return "unknown"
	}
}

// DetectBinaryType checks if a file is a Go binary.
// Rust binary detection is handled by SCALIBR's cargoauditable extractor at scan time.
// This function uses Go's standard library debug/buildinfo (no external deps).
func DetectBinaryType(path string) BinaryType {
	if IsGoBinary(path) {
		return BinaryTypeGo
	}
	// Note: Rust binaries are detected by SCALIBR at scan time using cargoauditable.
	// We don't detect them here to avoid pulling in additional dependencies.
	return BinaryTypeUnknown
}

// IsGoBinary checks if a file is a Go binary by attempting to read its buildinfo.
// Uses Go's standard library debug/buildinfo package.
func IsGoBinary(path string) bool {
	_, err := buildinfo.ReadFile(path)
	return err == nil
}

// ReadGoBinaryInfo extracts buildinfo from a Go binary.
// Returns the embedded module information including dependencies.
func ReadGoBinaryInfo(path string) (*buildinfo.BuildInfo, error) {
	return buildinfo.ReadFile(path)
}
