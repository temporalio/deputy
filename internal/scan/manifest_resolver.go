package scan

import (
	"fmt"
	"path/filepath"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// GitManifestResolver implements ManifestResolver using a git repository and commit hash.
type GitManifestResolver struct {
	repo *git.Repository
	hash plumbing.Hash
}

// NewGitManifestResolver creates a resolver for a specific git commit.
func NewGitManifestResolver(repo *git.Repository, hash plumbing.Hash) GitManifestResolver {
	return GitManifestResolver{repo: repo, hash: hash}
}

// ReadFile reads a file from the git repository at the specified commit.
func (g GitManifestResolver) ReadFile(rel string) ([]byte, error) {
	return gitx.ReadFileAtCommit(g.repo, g.hash, filepath.ToSlash(rel))
}

// WorkspaceManifestResolver implements ManifestResolver using a workspace.FS.
type WorkspaceManifestResolver struct {
	ws workspace.FS
}

// NewWorkspaceManifestResolver creates a resolver for a workspace filesystem.
func NewWorkspaceManifestResolver(ws workspace.FS) WorkspaceManifestResolver {
	return WorkspaceManifestResolver{ws: ws}
}

// ReadFile reads a file from the workspace.
func (w WorkspaceManifestResolver) ReadFile(rel string) ([]byte, error) {
	if w.ws == nil {
		return nil, fmt.Errorf("workspace unavailable")
	}
	return w.ws.ReadFile(filepath.ToSlash(rel))
}
