package fsys

import (
	"fmt"
	"io"
	"io/fs"
	"sync"

	ext4 "github.com/masahiro331/go-ext4-filesystem/ext4"
)

// Ext4FS wraps an ext4 filesystem to implement fs.FS.
type Ext4FS struct {
	fs *ext4.FileSystem
}

// OpenExt4 opens an ext4 filesystem from a partition reader.
// The reader should be positioned at the start of the partition.
func OpenExt4(r io.Reader) (*Ext4FS, error) {
	// The ext4 library requires an io.SectionReader
	// We need to wrap the reader appropriately
	var sr io.SectionReader

	switch v := r.(type) {
	case *io.SectionReader:
		sr = *v
	case *PartitionReader:
		// Create a section reader from our partition reader
		sr = *io.NewSectionReader(v, 0, v.Size())
	default:
		return nil, fmt.Errorf("unsupported reader type: %T (need *io.SectionReader or *PartitionReader)", r)
	}

	// Create a simple in-memory cache
	cache := newSimpleCache[string, any]()

	filesystem, err := ext4.NewFS(sr, cache)
	if err != nil {
		return nil, fmt.Errorf("open ext4 filesystem: %w", err)
	}

	return &Ext4FS{fs: filesystem}, nil
}

// OpenExt4FromSectionReader opens an ext4 filesystem from an io.SectionReader.
func OpenExt4FromSectionReader(sr *io.SectionReader) (*Ext4FS, error) {
	cache := newSimpleCache[string, any]()

	filesystem, err := ext4.NewFS(*sr, cache)
	if err != nil {
		return nil, fmt.Errorf("open ext4 filesystem: %w", err)
	}

	return &Ext4FS{fs: filesystem}, nil
}

// Open implements fs.FS.
func (e *Ext4FS) Open(name string) (fs.File, error) {
	// Normalize path (fs.FS expects paths without leading slash)
	origName := name
	if name == "" || name == "." {
		name = "/"
	} else if name[0] != '/' {
		name = "/" + name
	}

	// Try to open as a regular file first
	file, err := e.fs.Open(name)
	if err == nil {
		return file, nil
	}

	// If Open fails, check if it's a directory - some ext4 implementations
	// don't support Open() on directories, but do support Stat() and ReadDir()
	info, statErr := e.fs.Stat(name)
	if statErr != nil {
		return nil, &fs.PathError{Op: "open", Path: origName, Err: fs.ErrNotExist}
	}

	if info.IsDir() {
		// Return a directory file wrapper that supports ReadDir
		return &ext4DirFile{
			ext4fs: e,
			path:   name,
			info:   info,
		}, nil
	}

	// Not a directory and Open failed
	return nil, &fs.PathError{Op: "open", Path: origName, Err: fs.ErrNotExist}
}

// ReadDir implements fs.ReadDirFS.
func (e *Ext4FS) ReadDir(name string) ([]fs.DirEntry, error) {
	if name == "" || name == "." {
		name = "/"
	} else if name[0] != '/' {
		name = "/" + name
	}

	entries, err := e.fs.ReadDir(name)
	if err != nil {
		return nil, &fs.PathError{Op: "readdir", Path: name, Err: err}
	}

	// Filter out . and .. entries
	result := make([]fs.DirEntry, 0, len(entries))
	for _, entry := range entries {
		entryName := entry.Name()
		if entryName == "." || entryName == ".." {
			continue
		}
		result = append(result, entry)
	}
	return result, nil
}

// Stat implements fs.StatFS.
func (e *Ext4FS) Stat(name string) (fs.FileInfo, error) {
	if name == "" || name == "." {
		name = "/"
	} else if name[0] != '/' {
		name = "/" + name
	}

	info, err := e.fs.Stat(name)
	if err != nil {
		return nil, &fs.PathError{Op: "stat", Path: name, Err: fs.ErrNotExist}
	}
	return info, nil
}

var _ fs.FS = (*Ext4FS)(nil)
var _ fs.ReadDirFS = (*Ext4FS)(nil)
var _ fs.StatFS = (*Ext4FS)(nil)

// ext4DirFile implements fs.File for directories in ext4 filesystems.
// This is needed because some ext4 implementations don't support Open() on directories.
type ext4DirFile struct {
	ext4fs *Ext4FS
	path   string
	info   fs.FileInfo
	offset int // for ReadDir iteration
}

func (d *ext4DirFile) Stat() (fs.FileInfo, error) {
	return d.info, nil
}

func (d *ext4DirFile) Read(b []byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.path, Err: fs.ErrInvalid}
}

func (d *ext4DirFile) Close() error {
	return nil
}

// ReadDir implements fs.ReadDirFile for directory iteration.
func (d *ext4DirFile) ReadDir(n int) ([]fs.DirEntry, error) {
	entries, err := d.ext4fs.ReadDir(d.path)
	if err != nil {
		return nil, err
	}

	// Handle offset for multiple ReadDir calls
	if d.offset >= len(entries) {
		if n <= 0 {
			return nil, nil
		}
		return nil, io.EOF
	}

	remaining := entries[d.offset:]
	if n <= 0 || n > len(remaining) {
		d.offset = len(entries)
		return remaining, nil
	}

	d.offset += n
	return remaining[:n], nil
}

var _ fs.File = (*ext4DirFile)(nil)
var _ fs.ReadDirFile = (*ext4DirFile)(nil)

// simpleCache is a simple thread-safe in-memory cache implementing ext4.Cache.
type simpleCache[K comparable, V any] struct {
	mu   sync.RWMutex
	data map[K]V
}

func newSimpleCache[K comparable, V any]() *simpleCache[K, V] {
	return &simpleCache[K, V]{
		data: make(map[K]V),
	}
}

func (c *simpleCache[K, V]) Add(key K, value V) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	_, exists := c.data[key]
	c.data[key] = value
	return !exists
}

func (c *simpleCache[K, V]) Get(key K) (V, bool) {
	c.mu.RLock()
	defer c.mu.RUnlock()
	v, ok := c.data[key]
	return v, ok
}

var _ ext4.Cache[string, any] = (*simpleCache[string, any])(nil)
