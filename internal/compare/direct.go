package compare

import (
	"io/fs"
	"path/filepath"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/object"

	"github.com/picatz/deputy/internal/repository/workspace"
)

// CollectGoDirectModulesFromWorkspace scans the provided workspace for go.mod files
// and extracts the set of direct dependencies. It skips vendor directories and
// the .git folder. The Go stdlib pseudo-dependency is always included under both
// "stdlib" (for OSV vulnerability matching) and "go" (for PURL matching, as OSV-SCALIBR
// uses pkg:golang/go@version for the stdlib package).
func CollectGoDirectModulesFromWorkspace(ws workspace.FS) map[string]bool {
	deps := map[string]bool{"stdlib": true, "go": true}
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
// parsing any go.mod files found. The Go stdlib pseudo-dependency is always included
// under both "stdlib" and "go" (see CollectGoDirectModulesFromWorkspace for details).
func CollectGoDirectModulesFromCommit(repo *git.Repository, hash plumbing.Hash) (map[string]bool, error) {
	deps := map[string]bool{"stdlib": true, "go": true}
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

// mergeDirectDependencies merges dependency information from src to dst.
// Direct dependencies (true) always override indirect (false).
// Indirect dependencies (false) are only added if the module isn't already known.
// This ensures proper handling of Go submodules: if one go.mod has "foo" as
// direct and another has "foo/loader" as indirect, both are tracked correctly.
func mergeDirectDependencies(dst, src map[string]bool) {
	for mod, isDirect := range src {
		if isDirect {
			// Direct always wins
			dst[mod] = true
		} else {
			// Only add indirect if not already known
			// (don't override a direct with an indirect)
			if _, exists := dst[mod]; !exists {
				dst[mod] = false
			}
		}
	}
}

// CollectMainModulesFromWorkspace scans the provided workspace for go.mod files
// and extracts the set of main module paths (the "module" declarations).
// This is useful for excluding the project's own modules from dependency comparisons.
func CollectMainModulesFromWorkspace(ws workspace.FS) map[string]bool {
	modules := make(map[string]bool)
	if ws == nil {
		return modules
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
		if mod := GetMainModuleFromGoMod(data); mod != "" {
			modules[mod] = true
		}
		return nil
	})
	return modules
}

// CollectMainModulesFromCommit extracts main module paths from go.mod files
// present in a specific Git commit.
func CollectMainModulesFromCommit(repo *git.Repository, hash plumbing.Hash) (map[string]bool, error) {
	modules := make(map[string]bool)
	if repo == nil {
		return modules, nil
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
		if mod := GetMainModuleFromGoMod([]byte(contents)); mod != "" {
			modules[mod] = true
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return modules, nil
}
