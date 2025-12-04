package workspace

import (
	"io/fs"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ReadableFS defines read-only filesystem operations aligned with io/fs patterns.
// All paths are relative to the workspace root and use forward slashes.
type ReadableFS interface {
	fs.ReadDirFS
	fs.StatFS

	// Open opens the named file for reading.
	Open(name string) (fs.File, error)

	// ReadFile reads the entire contents of the named file.
	ReadFile(path string) ([]byte, error)
}

// WritableFS defines write-only filesystem operations.
// All paths are relative to the workspace root and use forward slashes.
type WritableFS interface {
	// WriteFile writes data to the named file, creating it if necessary.
	WriteFile(name string, data []byte, perm fs.FileMode) error

	// MkdirAll creates all directories in the path.
	MkdirAll(path string, perm fs.FileMode) error

	// Remove removes the named file or empty directory.
	Remove(path string) error

	// RemoveAll removes the named file or directory tree.
	RemoveAll(path string) error
}

// MutableFS combines readable and writable filesystem operations.
type MutableFS interface {
	ReadableFS
	WritableFS
}

// Metadata provides workspace metadata and lifecycle management.
type Metadata interface {
	// RootPath returns the underlying on-disk root or "" for virtual workspaces.
	RootPath() string

	// IsVirtual returns true if the workspace exists only in memory.
	IsVirtual() bool

	// Close releases resources associated with the workspace.
	Close() error
}

// FS represents a complete workspace filesystem with metadata.
// This is the primary interface for most Deputy operations.
type FS interface {
	ReadableFS
	WritableFS
	Metadata
}

// Scanner provides scan roots for osv-scalibr integration.
// This interface is intentionally separate from the core FS interface
// to isolate scalibr-specific concerns.
type Scanner interface {
	// ScanRoots returns the scan roots for osv-scalibr.
	// This method is only used by the inventory scanning code.
	ScanRoots() []*scalibrfs.ScanRoot
}

// ScannerFS combines a workspace filesystem with scanning capabilities.
// Only inventory scanning code should depend on this interface.
type ScannerFS interface {
	FS
	Scanner
}

// ToScanner adapts a workspace FS to provide Scanner capabilities.
// This adapter isolates the scalibr dependency from the rest of the codebase.
func ToScanner(ws FS) Scanner {
	// If the workspace already implements Scanner, use it directly
	if s, ok := ws.(Scanner); ok {
		return s
	}
	// Otherwise, create scan roots from the workspace root
	if root := ws.RootPath(); root != "" {
		return &scannerAdapter{
			scanRoots: scalibrfs.RealFSScanRoots(root),
		}
	}
	// Virtual workspaces get a synthetic root
	return &scannerAdapter{
		scanRoots: []*scalibrfs.ScanRoot{{FS: ws, Path: ""}},
	}
}

// scannerAdapter wraps scan roots to provide Scanner interface.
type scannerAdapter struct {
	scanRoots []*scalibrfs.ScanRoot
}

func (s *scannerAdapter) ScanRoots() []*scalibrfs.ScanRoot {
	return s.scanRoots
}
