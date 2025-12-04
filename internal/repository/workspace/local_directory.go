package workspace

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// LocalDirectory implements Workspace backed by a directory on the host
// filesystem. It uses os.Root to guard against path traversal to ancestors and
// exposes the directory as a scalibr ScanRoot.
type LocalDirectory struct {
	*baseWorkspace
	fs   scalibrfs.FS
	root *os.Root
}

// newLocalDirectory builds a LocalDirectory workspace rooted at abs with optional cleanup.
func newLocalDirectory(abs string, removeOnClose bool) (*LocalDirectory, error) {
	root, err := os.OpenRoot(abs)
	if err != nil {
		return nil, err
	}
	cleanup := func() error {
		err := root.Close()
		if removeOnClose {
			if rmErr := os.RemoveAll(abs); err == nil {
				err = rmErr
			}
		}
		return err
	}
	ws := &LocalDirectory{
		baseWorkspace: newBaseWorkspace(abs, scalibrfs.RealFSScanRoots(abs), cleanup),
		fs:            scalibrfs.DirFS(abs),
		root:          root,
	}
	return ws, nil
}

// NewDir returns a workspace rooted at the provided path. The path must exist
// and refer to a directory. Call Close when finished to release underlying OS
// resources (it will not remove the directory).
func NewDir(path string) (*LocalDirectory, error) {
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
		return nil, &fs.PathError{Op: "opendir", Path: abs, Err: fmt.Errorf("not a directory")}
	}
	return newLocalDirectory(abs, false)
}

// NewTempDir creates a temporary workspace on disk using os.MkdirTemp. The
// returned workspace removes the directory during Close.
func NewTempDir(prefix string) (*LocalDirectory, error) {
	dir, err := os.MkdirTemp("", prefix)
	if err != nil {
		return nil, err
	}
	ws, err := newLocalDirectory(dir, true)
	if err != nil {
		_ = os.RemoveAll(dir)
		return nil, err
	}
	return ws, nil
}

// ReadFile reads the named file from the workspace.
func (w *LocalDirectory) ReadFile(name string) ([]byte, error) {
	if err := w.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return nil, fmt.Errorf("%w: cannot read directory root", ErrInvalidPath)
	}
	return fs.ReadFile(w.fs, rel)
}

// Open opens the named file for reading.
func (w *LocalDirectory) Open(name string) (fs.File, error) {
	if err := w.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	return w.fs.Open(rel)
}

// ReadDir reads the directory named by name and returns a list of directory entries.
func (w *LocalDirectory) ReadDir(name string) ([]fs.DirEntry, error) {
	if err := w.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		rel = "."
	}
	return w.fs.ReadDir(rel)
}

// Stat returns a FileInfo describing the named file.
func (w *LocalDirectory) Stat(name string) (fs.FileInfo, error) {
	if err := w.ensureOpen(); err != nil {
		return nil, err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return nil, err
	}
	if rel == "." {
		return os.Stat(w.rootPath)
	}
	return w.fs.Stat(rel)
}

// WriteFile writes data to the named file, creating it if necessary.
func (w *LocalDirectory) WriteFile(name string, data []byte, perm fs.FileMode) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(name)
	if err != nil {
		return err
	}
	f, err := w.root.OpenFile(rel, os.O_RDWR|os.O_CREATE|os.O_TRUNC, perm)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write(data)
	return err
}

// MkdirAll creates a directory named path, along with any necessary parents.
func (w *LocalDirectory) MkdirAll(path string, perm fs.FileMode) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return nil
	}
	return w.root.MkdirAll(rel, perm)
}

// Remove removes the named file or (empty) directory.
func (w *LocalDirectory) Remove(path string) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return w.root.Remove(rel)
}

// RemoveAll removes path and any children it contains.
func (w *LocalDirectory) RemoveAll(path string) error {
	if err := w.ensureOpen(); err != nil {
		return err
	}
	rel, err := cleanPath(path)
	if err != nil {
		return err
	}
	if rel == "." {
		return fmt.Errorf("%w: refusing to remove workspace root", ErrInvalidPath)
	}
	return w.root.RemoveAll(rel)
}

// Close closes the workspace and releases any resources.
func (w *LocalDirectory) Close() error {
	err := w.baseWorkspace.Close()
	w.root = nil
	return err
}

// IsVirtual returns false for LocalDirectory.
func (w *LocalDirectory) IsVirtual() bool { return false }
