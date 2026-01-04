package workspace

import (
	"fmt"
	"io/fs"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// ReadOnlyFS wraps an io/fs filesystem as a read-only workspace.
// Write operations return ErrReadOnly.
type ReadOnlyFS struct {
	*baseWorkspace
	fsys fs.FS
}

// NewReadOnlyFS constructs a read-only workspace backed by the provided filesystem.
func NewReadOnlyFS(fsys fs.FS) *ReadOnlyFS {
	if fsys == nil {
		return nil
	}
	ro := &ReadOnlyFS{fsys: fsys}
	ro.baseWorkspace = newBaseWorkspace("", []*scalibrfs.ScanRoot{{FS: ro, Path: ""}}, nil)
	return ro
}

// ensureOpen verifies the workspace has not been closed yet.
func (r *ReadOnlyFS) ensureOpen() error {
	return r.baseWorkspace.ensureOpen()
}

// ReadFile reads the named file from the workspace.
func (r *ReadOnlyFS) ReadFile(name string) ([]byte, error) {
	if err := r.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return nil, fmt.Errorf("%w: cannot read directory root", ErrInvalidPath)
	}
	return fs.ReadFile(r.fsys, rel)
}

// Open opens the named file for reading.
func (r *ReadOnlyFS) Open(name string) (fs.File, error) {
	if err := r.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	return r.fsys.Open(rel)
}

// ReadDir reads the directory named by name and returns a list of directory entries.
func (r *ReadOnlyFS) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := r.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = "."
	}
	return fs.ReadDir(r.fsys, rel)
}

// Stat returns a FileInfo describing the named file.
func (r *ReadOnlyFS) Stat(name string) (fs.FileInfo, error) {
	if err := r.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	return fs.Stat(r.fsys, rel)
}

// WriteFile returns ErrReadOnly for read-only workspaces.
func (r *ReadOnlyFS) WriteFile(string, []byte, fs.FileMode) error {
	return ErrReadOnly
}

// MkdirAll returns ErrReadOnly for read-only workspaces.
func (r *ReadOnlyFS) MkdirAll(string, fs.FileMode) error {
	return ErrReadOnly
}

// Remove returns ErrReadOnly for read-only workspaces.
func (r *ReadOnlyFS) Remove(string) error {
	return ErrReadOnly
}

// RemoveAll returns ErrReadOnly for read-only workspaces.
func (r *ReadOnlyFS) RemoveAll(string) error {
	return ErrReadOnly
}

// Close closes the workspace and releases any resources.
func (r *ReadOnlyFS) Close() error {
	return r.baseWorkspace.Close()
}

// IsVirtual returns true for read-only virtual workspaces.
func (r *ReadOnlyFS) IsVirtual() bool { return true }

var _ FS = (*ReadOnlyFS)(nil)
