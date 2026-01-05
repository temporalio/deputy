package inputs

import (
	"fmt"
	"path/filepath"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// Resolver abstracts file reading for manifest parsing.
type Resolver interface {
	ReadFile(path string) ([]byte, error)
}

// ResolverFunc adapts a function to the Resolver interface.
type ResolverFunc func(string) ([]byte, error)

// ReadFile calls the underlying function.
func (f ResolverFunc) ReadFile(path string) ([]byte, error) {
	return f(path)
}

// GitResolver implements Resolver using a git repository and commit hash.
type GitResolver struct {
	repo *git.Repository
	hash plumbing.Hash
}

// NewGitResolver creates a resolver for a specific git commit.
func NewGitResolver(repo *git.Repository, hash plumbing.Hash) GitResolver {
	return GitResolver{repo: repo, hash: hash}
}

// ReadFile reads a file from the git repository at the specified commit.
func (g GitResolver) ReadFile(rel string) ([]byte, error) {
	return gitx.ReadFileAtCommit(g.repo, g.hash, filepath.ToSlash(rel))
}

// WorkspaceResolver implements Resolver using a workspace.FS.
type WorkspaceResolver struct {
	ws workspace.FS
}

// NewWorkspaceResolver creates a resolver for a workspace filesystem.
func NewWorkspaceResolver(ws workspace.FS) WorkspaceResolver {
	return WorkspaceResolver{ws: ws}
}

// ReadFile reads a file from the workspace.
func (w WorkspaceResolver) ReadFile(rel string) ([]byte, error) {
	if w.ws == nil {
		return nil, fmt.Errorf("workspace unavailable")
	}
	return w.ws.ReadFile(filepath.ToSlash(rel))
}
