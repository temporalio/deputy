package workspace

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"path/filepath"
	"strings"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	ErrOutsideWorkspace = errors.New("workspace: path escapes root")
	ErrInvalidPath      = errors.New("workspace: invalid path")
	ErrReadOnly         = errors.New("workspace: workspace is read-only")
)

// Reader captures the minimal contract needed to read files from a workspace.
type Reader interface {
	ReadFile(path string) ([]byte, error)
}

// Workspace represents a repository/target filesystem that can be backed by the
// OS filesystem, go-git billy implementations, or any future virtual storage.
//
// Paths supplied to the methods are always interpreted relative to the
// workspace root. Implementations must apply appropriate sanitisation to prevent
// directory traversal outside of the root (see cleanPath).
type Workspace interface {
	Reader
	fs.ReadDirFS
	fs.StatFS

	Open(name string) (fs.File, error)
	WriteFile(name string, data []byte, perm fs.FileMode) error
	MkdirAll(path string, perm fs.FileMode) error
	Remove(path string) error
	RemoveAll(path string) error

	ScalibrRoots() []*scalibrfs.ScanRoot
	RootPath() string
	IsVirtual() bool
	Close() error
}

// MutableWorkspace extends Workspace with the guarantee that write operations
// succeed. Implementations that are read-only can return ErrReadOnly for write
// methods; callers can use a type assertion to MutableWorkspace when mutation
// is required.
type MutableWorkspace interface {
	Workspace
}

// cleanPath normalises a potentially OS-specific path into a slash-separated
// form accepted by fs.FS implementations while guaranteeing it remains within
// the workspace root.
func cleanPath(p string) (string, error) {
	if p == "" {
		return ".", nil
	}
	s := filepath.ToSlash(p)
	s = strings.TrimSpace(s)
	if s == "" {
		return ".", nil
	}
	s = path.Clean(s)
	if s == "." {
		return ".", nil
	}
	s = strings.TrimPrefix(s, "./")
	if s == "" {
		return ".", nil
	}
	if strings.HasPrefix(s, "../") || s == ".." {
		return "", ErrOutsideWorkspace
	}
	if strings.HasPrefix(s, "/") {
		return "", ErrOutsideWorkspace
	}
	if !validPath(s) {
		return "", fmt.Errorf("%w: %s", ErrInvalidPath, p)
	}
	return s, nil
}

// validPath mirrors fs.ValidPath but allows dot files and nested segments while
// prohibiting path separators outside of "/" and ".." components.
func validPath(name string) bool {
	if name == "" {
		return false
	}
	for _, elem := range strings.Split(name, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
	}
	return true
}
