package workspace

import (
	"fmt"
	"io/fs"

	billy "github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/helper/iofs"
	"github.com/go-git/go-billy/v5/memfs"
	billyutil "github.com/go-git/go-billy/v5/util"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

// Memory implements an in-memory workspace backed by a billy filesystem.
type Memory struct {
	*baseWorkspace
	fsys    billy.Filesystem
	adapter scalibrfs.FS
}

// NewMemory constructs an in-memory workspace using go-billy's memfs implementation.
func NewMemory() *Memory {
	return NewMemoryFromBillyFS(memfs.New())
}

// NewMemoryFromBillyFS wraps an existing billy filesystem (for example a go-git worktree) as a Workspace.
func NewMemoryFromBillyFS(fs billy.Filesystem) *Memory {
	adapter := iofs.New(fs)
	scalibrAdapter, ok := adapter.(scalibrfs.FS)
	if !ok {
		scalibrAdapter = &billyAdapter{
			base: adapter,
			dir:  iofs.NewReadDirFS(fs),
			stat: iofs.NewStatFS(fs),
		}
	}
	roots := []*scalibrfs.ScanRoot{{
		FS:   scalibrAdapter,
		Path: "",
	}}
	return &Memory{
		baseWorkspace: newBaseWorkspace("", roots, nil),
		fsys:          fs,
		adapter:       scalibrAdapter,
	}
}

// ensureOpen verifies the workspace has not been closed yet.
func (m *Memory) ensureOpen() error {
	return m.baseWorkspace.ensureOpen()
}

// ReadFile reads the named file from the workspace.
func (m *Memory) ReadFile(name string) ([]byte, error) {
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return nil, fmt.Errorf("%w: cannot read directory root", ErrInvalidPath)
	}
	return fs.ReadFile(m.adapter, rel)
}

// Open opens the named file for reading.
func (m *Memory) Open(name string) (fs.File, error) {
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	return m.adapter.Open(rel)
}

// ReadDir reads the directory named by name and returns a list of directory entries.
func (m *Memory) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = "."
	}
	return m.adapter.ReadDir(rel)
}

// Stat returns a FileInfo describing the named file.
func (m *Memory) Stat(name string) (fs.FileInfo, error) {
	if err := m.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return m.fsys.Stat(".")
	}
	return m.adapter.Stat(rel)
}

// WriteFile writes data to the named file, creating it if necessary.
func (m *Memory) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if err := m.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return err
	}
	return billyutil.WriteFile(m.fsys, rel, data, perm)
}

// MkdirAll creates a directory named path, along with any necessary parents.
func (m *Memory) MkdirAll(path string, perm fs.FileMode) error {
	if err := m.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	return m.fsys.MkdirAll(rel, perm)
}

// Remove removes the named file or (empty) directory.
func (m *Memory) Remove(path string) error {
	if err := m.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return m.fsys.Remove(rel)
}

// RemoveAll removes path and any children it contains.
func (m *Memory) RemoveAll(path string) error {
	if err := m.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return billyutil.RemoveAll(m.fsys, rel)
}

// Close closes the workspace and releases any resources.
func (m *Memory) Close() error {
	return m.baseWorkspace.Close()
}

// IsVirtual returns true for Memory.
func (m *Memory) IsVirtual() bool { return true }

var _ FS = (*Memory)(nil)

// billyAdapter adapts separate FS/ReadDirFS/StatFS values into a single structure implementing scalibrfs.FS.
type billyAdapter struct {
	base fs.FS
	dir  fs.ReadDirFS
	stat fs.StatFS
}

// Open opens the named file for reading.
func (b *billyAdapter) Open(name string) (fs.File, error) {
	return b.base.Open(name)
}

// ReadDir reads the directory named by name and returns a list of directory entries.
func (b *billyAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	return b.dir.ReadDir(name)
}

// Stat returns a FileInfo describing the named file.
func (b *billyAdapter) Stat(name string) (fs.FileInfo, error) {
	return b.stat.Stat(name)
}
