package workspace

import (
	"fmt"
	"io/fs"
	"os"
	"sync"

	billy "github.com/go-git/go-billy/v5"
	"github.com/go-git/go-billy/v5/helper/iofs"
	"github.com/go-git/go-billy/v5/memfs"
	billyutil "github.com/go-git/go-billy/v5/util"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

type Memory struct {
	mu        sync.RWMutex
	fsys      billy.Filesystem
	adapter   scalibrfs.FS
	scanRoots []*scalibrfs.ScanRoot
	closed    bool
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
	return &Memory{
		fsys:    fs,
		adapter: scalibrAdapter,
		scanRoots: []*scalibrfs.ScanRoot{{
			FS:   scalibrAdapter,
			Path: "",
		}},
	}
}

func (m *Memory) ensureOpen() error {
	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.closed {
		return fmt.Errorf("workspace: closed")
	}
	return nil
}

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

func (m *Memory) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if err := m.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return err
	}
	return billyutil.WriteFile(m.fsys, rel, data, os.FileMode(perm))
}

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
	return m.fsys.MkdirAll(rel, os.FileMode(perm))
}

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

func (m *Memory) ScalibrRoots() []*scalibrfs.ScanRoot {
	m.mu.RLock()
	defer m.mu.RUnlock()
	return m.scanRoots
}

func (m *Memory) RootPath() string { return "" }

func (m *Memory) IsVirtual() bool { return true }

func (m *Memory) Close() error {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.closed = true
	return nil
}

var _ FS = (*Memory)(nil)

// billyAdapter adapts separate FS/ReadDirFS/StatFS values into a single structure implementing scalibrfs.FS.
type billyAdapter struct {
	base fs.FS
	dir  fs.ReadDirFS
	stat fs.StatFS
}

func (b *billyAdapter) Open(name string) (fs.File, error) {
	return b.base.Open(name)
}

func (b *billyAdapter) ReadDir(name string) ([]fs.DirEntry, error) {
	return b.dir.ReadDir(name)
}

func (b *billyAdapter) Stat(name string) (fs.FileInfo, error) {
	return b.stat.Stat(name)
}

var _ scalibrfs.FS = (*billyAdapter)(nil)
