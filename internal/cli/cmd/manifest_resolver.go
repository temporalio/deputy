package cmd

import (
	"fmt"
	"os"
	"path/filepath"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"

	gitx "github.com/picatz/deputy/internal/gitutil"
	"github.com/picatz/deputy/internal/repository/workspace"
)

// gitManifestResolver implements manifestResolver using a git repository and commit hash.
type gitManifestResolver struct {
	repo *git.Repository
	hash plumbing.Hash
}

// ReadFile reads a file from the git repository at the specified commit.
func (g gitManifestResolver) ReadFile(rel string) ([]byte, error) {
	return gitx.ReadFileAtCommit(g.repo, g.hash, filepath.ToSlash(rel))
}

// osManifestResolver returns a manifestResolver that reads files from the OS filesystem.
func osManifestResolver(base string) manifestResolver {
	return manifestResolverFunc(func(rel string) ([]byte, error) {
		abs := filepath.Join(base, filepath.FromSlash(rel))
		return os.ReadFile(abs)
	})
}

// workspaceManifestResolver implements manifestResolver using a workspace.FS.
type workspaceManifestResolver struct {
	ws workspace.FS
}

// ReadFile reads a file from the workspace.
func (w workspaceManifestResolver) ReadFile(rel string) ([]byte, error) {
	if w.ws == nil {
		return nil, fmt.Errorf("workspace unavailable")
	}
	return w.ws.ReadFile(filepath.ToSlash(rel))
}
