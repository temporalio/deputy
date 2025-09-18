package workspace

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sync"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// DirWorkspace implements Workspace backed by a directory on the host
// filesystem. It uses os.Root to guard against path traversal to ancestors and
// exposes the directory as a scalibr ScanRoot.
type DirWorkspace struct {
	mu            sync.RWMutex
	base          string
	root          *os.Root
	fsys          scalibrfs.FS
	removeOnClose bool
	scanRoots     []*scalibrfs.ScanRoot
}

// NewDir returns a workspace rooted at the provided path. The path must exist
// and refer to a directory. Call Close when finished to release underlying OS
// resources (it will not remove the directory).
func NewDir(path string) (*DirWorkspace, error) {
	if path == "" {
		path = "."
	}
	abs, err := filepath.Abs(path)
	if err != nil {
		return nil, err
	}
	info, err := os.Stat(abs)
	if err != nil {
		return nil, err
	}
	if !info.IsDir() {
		return nil, &fs.PathError{Op: "opendir", Path: abs, Err: errors.New("not a directory")}
	}
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	fsys := scalibrfs.DirFS(abs)
	return &DirWorkspace{
		base:      abs,
		root:      root,
		fsys:      fsys,
		scanRoots: scalibrfs.RealFSScanRoots(abs),
	}, nil
}

// NewTempDir creates a temporary workspace on disk using os.MkdirTemp. The
// returned workspace removes the directory during Close.
func NewTempDir(prefix string) (*DirWorkspace, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, err
	}
	ws, err := NewDir(dir)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	ws.removeOnClose = true
	return ws, nil
}

func (w *DirWorkspace) ensureOpen() error {
	w.mu.RLock()
	defer w.mu.RUnlock()
	if w.root == nil {
		return errors.New("workspace: closed")
	}
	return nil
}

func (w *DirWorkspace) ReadFile(name string) ([]byte, error) {
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return nil, fmt.Errorf("%w: cannot read directory root", ErrInvalidPath)
	}
	return fs.ReadFile(w.fsys, rel)
}

func (w *DirWorkspace) Open(name string) (fs.File, error) {
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	return w.fsys.Open(rel)
}

func (w *DirWorkspace) ReadDir(name string) ([]fs.DirEntry, error) {
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = "."
	}
	return w.fsys.ReadDir(rel)
}

func (w *DirWorkspace) Stat(name string) (fs.FileInfo, error) {
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return os.Stat(w.base)
	}
	return w.fsys.Stat(rel)
}

func (w *DirWorkspace) WriteFile(name string, data []byte, perm fs.FileMode) error {
	rel, err := cleanPath(name)
	if err != nil {
		return err
	}
	if err := w.ensureOpen(); err != nil {
		return err
	}
	f, err := w.root.OpenFile(rel, os.O_RDWR|os.O_CREATE|os.O_TRUNC, os.FileMode(perm))
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

func (w *DirWorkspace) MkdirAll(path string, perm fs.FileMode) error {
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if err := w.ensureOpen(); err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	return w.root.MkdirAll(rel, os.FileMode(perm))
}

func (w *DirWorkspace) Remove(path string) error {
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if err := w.ensureOpen(); err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return w.root.Remove(rel)
}

func (w *DirWorkspace) RemoveAll(path string) error {
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if err := w.ensureOpen(); err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return w.root.RemoveAll(rel)
}

func (w *DirWorkspace) ScalibrRoots() []*scalibrfs.ScanRoot {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.scanRoots
}

func (w *DirWorkspace) RootPath() string {
	w.mu.RLock()
	defer w.mu.RUnlock()
	return w.base
}

func (w *DirWorkspace) IsVirtual() bool { return false }

func (w *DirWorkspace) Close() error {
	w.mu.Lock()
	defer w.mu.Unlock()
	if w.root == nil {
		return nil
	}
	err := w.root.Close()
	w.root = nil
	if w.removeOnClose {
		if rmErr := os.RemoveAll(w.base); err == nil {
			err = rmErr
		}
	}
	return err
}

var _ Workspace = (*DirWorkspace)(nil)
