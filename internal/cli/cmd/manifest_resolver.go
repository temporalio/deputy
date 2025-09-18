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

type gitManifestResolver struct {
	repo *git.Repository
	hash plumbing.Hash
}

func (g gitManifestResolver) ReadFile(rel string) ([]byte, error) {
	return gitx.ReadFileAtCommit(g.repo, g.hash, filepath.ToSlash(rel))
}

func osManifestResolver(base string) manifestResolver {
	return manifestResolverFunc(func(rel string) ([]byte, error) {
		abs := filepath.Join(base, filepath.FromSlash(rel))
		return os.ReadFile(abs)
	})
}

type workspaceManifestResolver struct {
	ws workspace.FS
}

func (w workspaceManifestResolver) ReadFile(rel string) ([]byte, error) {
	if w.ws == nil {
		return nil, fmt.Errorf("workspace unavailable")
	}
	return w.ws.ReadFile(filepath.ToSlash(rel))
}
