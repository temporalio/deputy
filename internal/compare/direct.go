package compare

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/picatz/deputy/internal/repository/workspace"
)

// CollectGoDirectModulesFromWorkspace scans the provided workspace for go.mod files
// and extracts the set of direct dependencies. It skips vendor directories and
// the .git folder. The "stdlib" pseudo-dependency is always included.
func CollectGoDirectModulesFromWorkspace(ws workspace.FS) map[string]bool {
	deps := map[string]bool{"stdlib": true}
	if ws == nil {
		return deps
	}
	_ = fs.WalkDir(ws, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return fs.SkipDir
			}
			return nil
		}
		if filepath.Base(path) != "go.mod" {
			return nil
		}
		if strings.Contains(path, "/vendor/") {
			return nil
		}
		data, err := ws.ReadFile(path)
		if err != nil {
			return nil
		}
		mergeDirectDependencies(deps, GetDirectDependenciesFromGoMod(data))
		return nil
	})
	return deps
}

// CollectGoDirectModulesFromCommit extracts direct dependencies from go.mod files
// present in a specific Git commit. It traverses the file tree of the commit,
// parsing any go.mod files found.
func CollectGoDirectModulesFromCommit(repo *git.Repository, hash plumbing.Hash) (map[string]bool, error) {
	deps := map[string]bool{"stdlib": true}
	if repo == nil {
		return deps, nil
	}
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, err
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, err
	}
	err = tree.Files().ForEach(func(f *object.File) error {
		if filepath.Base(f.Name) != "go.mod" {
			return nil
		}
		if strings.Contains(f.Name, "/vendor/") {
			return nil
		}
		contents, err := f.Contents()
		if err != nil {
			return nil
		}
		mergeDirectDependencies(deps, GetDirectDependenciesFromGoMod([]byte(contents)))
		return nil
	})
	if err != nil {
		return nil, err
	}
	return deps, nil
}

// CollectGoDirectModulesFromDisk scans a local directory for go.mod files and
// extracts direct dependencies. It respects standard exclusion rules (vendor, .git).
func CollectGoDirectModulesFromDisk(root string) map[string]bool {
	deps := map[string]bool{"stdlib": true}
	if strings.TrimSpace(root) == "" {
		return deps
	}
	_ = filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" {
				return filepath.SkipDir
			}
			return nil
		}
		if filepath.Base(path) != "go.mod" {
			return nil
		}
		if strings.Contains(path, string(filepath.Separator)+"vendor"+string(filepath.Separator)) {
			return nil
		}
		data, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		mergeDirectDependencies(deps, GetDirectDependenciesFromGoMod(data))
		return nil
	})
	return deps
}

// mergeDirectDependencies adds all direct dependencies from src to dst.
func mergeDirectDependencies(dst, src map[string]bool) {
	for mod, direct := range src {
		if direct {
			dst[mod] = true
		}
	}
}
