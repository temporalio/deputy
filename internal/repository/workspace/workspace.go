package workspace

import (
	"errors"
	"fmt"
	"path"
	"path/filepath"
	"strings"
	"sync"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

var (
	// ErrOutsideWorkspace indicates that a requested path attempts to escape the workspace root.
	ErrOutsideWorkspace = errors.New("workspace: path escapes root")
	// ErrInvalidPath indicates that a path contains invalid characters or formatting.
	ErrInvalidPath = errors.New("workspace: invalid path")
	// ErrReadOnly indicates that a write operation was attempted on a read-only workspace.
	ErrReadOnly = errors.New("workspace: workspace is read-only")
	// ErrClosed indicates that an operation was attempted on a closed workspace.
	ErrClosed = errors.New("workspace: closed")
)

// FileReader captures the minimal contract needed to read files from a workspace.
// Deprecated: Use ReadableFS instead.
type FileReader interface {
	ReadFile(path string) ([]byte, error)
}

// Mutable extends Workspace with the guarantee that write operations
// succeed. Implementations that are read-only can return ErrReadOnly for write
// methods; callers can use a type assertion to Mutable when mutation
// is required.
// Deprecated: Use MutableFS interface instead.
type Mutable interface {
	FS
}

// baseWorkspace holds shared state (root path, scalibr roots, cleanup) that
// concrete workspace implementations embed to get consistent lifecycle
// handling.
type baseWorkspace struct {
	mu        sync.RWMutex
	rootPath  string
	scanRoots []*scalibrfs.ScanRoot
	cleanup   func() error
	closed    bool
}

// newBaseWorkspace configures a shared workspace helper that tracks closure and scan roots.
func newBaseWorkspace(rootPath string, scanRoots []*scalibrfs.ScanRoot, cleanup func() error) *baseWorkspace {
	return &baseWorkspace{
		rootPath:  rootPath,
		scanRoots: scanRoots,
		cleanup:   cleanup,
	}
}

// ensureOpen verifies the workspace hasn't been closed yet.
func (b *baseWorkspace) ensureOpen() error {
	b.mu.RLock()
	defer b.mu.RUnlock()
	if b.closed {
		return ErrClosed
	}
	return nil
}

// ScalibrRoots returns the scan roots Deputy advertises to osv-scalibr.
// Deprecated: Use Scanner interface and ToScanner adapter instead.
func (b *baseWorkspace) ScalibrRoots() []*scalibrfs.ScanRoot {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.scanRoots
}

// ScanRoots implements the Scanner interface.
func (b *baseWorkspace) ScanRoots() []*scalibrfs.ScanRoot {
	return b.ScalibrRoots()
}

// RootPath returns the underlying on-disk root or "" for virtual workspaces.
func (b *baseWorkspace) RootPath() string {
	b.mu.RLock()
	defer b.mu.RUnlock()
	return b.rootPath
}

// Close marks the workspace as closed and invokes the optional cleanup hook.
func (b *baseWorkspace) Close() error {
	b.mu.Lock()
	if b.closed {
		b.mu.Unlock()
		return nil
	}
	b.closed = true
	cleanup := b.cleanup
	b.cleanup = nil
	b.mu.Unlock()
	if cleanup != nil {
		return cleanup()
	}
	return nil
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
	for elem := range strings.SplitSeq(name, "/") {
		if elem == "" || elem == "." || elem == ".." {
			return false
		}
	}
	return true
}
