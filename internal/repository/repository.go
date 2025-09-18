package repository

import (
	"context"
	"fmt"
	"sync"

	"github.com/go-git/go-billy/v5/memfs"
	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/storage/memory"
	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// Source represents a Git repository together with the workspace containing its
// checked out files. Workspaces may be backed by the host filesystem or remain
// purely virtual in memory.
type Source struct {
	Repo      *git.Repository
	Workspace workspace.FS

	cleanup   func() error
	closeOnce sync.Once
	closeErr  error
}

// Close releases resources associated with the repository/workspace. It is safe
// to call multiple times; the first error (if any) is returned.
func (s *Source) Close() error {
	if s == nil {
		return nil
	}
	s.closeOnce.Do(func() {
		if s.cleanup != nil {
			s.closeErr = s.cleanup()
		} else if s.Workspace != nil {
			s.closeErr = s.Workspace.Close()
		}
	})
	return s.closeErr
}

// RootPath returns the workspace root path if it exists on disk, or "" for
// virtual/in-memory workspaces.
func (s *Source) RootPath() string {
	if s == nil || s.Workspace == nil {
		return ""
	}
	return s.Workspace.RootPath()
}

// Open returns a Source backed by an existing repository on disk.
func Open(path string) (*Source, error) {
	repo, err := git.PlainOpen(path)
	if err != nil {
		return nil, fmt.Errorf("open git repo: %w", err)
	}
	ws, err := workspace.NewDir(path)
	if err != nil {
		return nil, err
	}
	src := &Source{
		Repo:      repo,
		Workspace: ws,
	}
	src.cleanup = func() error {
		return ws.Close()
	}
	return src, nil
}

// CloneInMemory clones the provided repository into an in-memory workspace using
// go-git's memory storage. The caller must Close the returned Source.
func CloneInMemory(ctx context.Context, opts *git.CloneOptions) (*Source, error) {
	if opts == nil {
		return nil, fmt.Errorf("clone options required")
	}
	storer := memory.NewStorage()
	fsys := memfs.New()
	repo, err := git.CloneContext(ctx, storer, fsys, opts)
	if err != nil {
		return nil, err
	}
	ws := workspace.NewMemoryFromBillyFS(fsys)
	src := &Source{
		Repo:      repo,
		Workspace: ws,
	}
	src.cleanup = func() error {
		return ws.Close()
	}
	return src, nil
}

// CloneToDir clones the repository into a new temporary directory on disk and
// returns a Source rooted at that directory. The directory is removed during Close.
func CloneToDir(ctx context.Context, opts *git.CloneOptions) (*Source, error) {
	if opts == nil {
		return nil, fmt.Errorf("clone options required")
	}
	ws, err := workspace.NewTempDir("deputy-clone")
	if err != nil {
		return nil, err
	}
	cleanup := func() error { return ws.Close() }
	repo, closeStorer, err := gitx.CloneContext(ctx, ws.RootPath(), opts)
	if err != nil {
		_ = ws.Close()
		return nil, err
	}
	src := &Source{
		Repo:      repo,
		Workspace: ws,
	}
	src.cleanup = func() error {
		if closeStorer != nil {
			closeStorer()
		}
		return cleanup()
	}
	return src, nil
}

// Clone chooses between CloneInMemory and CloneToDir based on the inMemory flag.
func Clone(ctx context.Context, opts *git.CloneOptions, inMemory bool) (*Source, error) {
	if inMemory {
		return CloneInMemory(ctx, opts)
	}
	return CloneToDir(ctx, opts)
}

// WithExistingWorkspace constructs a Source from pre-existing repo/workspace components.
// The cleanup function is called during Close.
func WithExistingWorkspace(repo *git.Repository, ws workspace.FS, cleanup func() error) *Source {
	return &Source{Repo: repo, Workspace: ws, cleanup: cleanup}
}
