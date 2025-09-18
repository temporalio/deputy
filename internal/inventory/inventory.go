package inventory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"path"
	"slices"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/picatz/deputy/internal/repository/workspace"
)

// ScanOptions configures how scalibr scans a workspace.
type ScanOptions struct {
	Ecosystems []string
}

// ScanPackagesWorking scans the provided workspace and returns the discovered
// package inventory. The workspace may be backed by the host filesystem or be a
// virtual in-memory filesystem.
func ScanPackagesWorking(ctx context.Context, ws workspace.FS, opts ScanOptions) ([]*extractor.Package, error) {
	if ws == nil {
		return nil, fmt.Errorf("workspace is required")
	}
	return scanWorkspace(ctx, ws, opts)
}

// ScanPackagesAtCommitSnapshot materializes the tree for commitHash from repo
// into an ephemeral in-memory workspace and scans it for packages. The workspace
// is discarded after scanning.
func ScanPackagesAtCommitSnapshot(ctx context.Context, repo *git.Repository, commitHash plumbing.Hash, opts ScanOptions) ([]*extractor.Package, error) {
	if repo == nil {
		return nil, fmt.Errorf("git repository is required")
	}
	commit, err := repo.CommitObject(commitHash)
	if err != nil {
		return nil, fmt.Errorf("error getting commit: %w", err)
	}
	tree, err := commit.Tree()
	if err != nil {
		return nil, fmt.Errorf("error getting tree: %w", err)
	}
	ws := workspace.NewMemory()
	if err := populateWorkspaceFromTree(ws, tree); err != nil {
		_ = ws.Close()
		return nil, err
	}
	defer ws.Close()
	return scanWorkspace(ctx, ws, opts)
}

func scanWorkspace(ctx context.Context, ws workspace.FS, opts ScanOptions) ([]*extractor.Package, error) {
	plugins, err := resolvePlugins(opts)
	if err != nil {
		return nil, err
	}
	cfg := &scalibr.ScanConfig{ScanRoots: ws.ScalibrRoots(), Plugins: plugins}
	results := scalibr.New().Scan(ctx, cfg)
	return results.Inventory.Packages, nil
}

func resolvePlugins(opts ScanOptions) ([]plugin.Plugin, error) {
	names := normalizeEcosystems(opts.Ecosystems)
	if len(names) == 0 {
		return pl.All(), nil
	}
	plugins, err := pl.FromNames(names)
	if err != nil {
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}
	return plugins, nil
}

func normalizeEcosystems(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	seen := map[string]struct{}{}
	out := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(strings.ToLower(raw))
		if name == "" {
			continue
		}
		if name == "all" {
			return nil
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		out = append(out, name)
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return out
}

func populateWorkspaceFromTree(ws workspace.FS, tree *object.Tree) error {
	if tree == nil {
		return fmt.Errorf("nil tree")
	}
	return tree.Files().ForEach(func(f *object.File) error {
		if f == nil {
			return nil
		}
		if f.Name == ".git" || strings.HasPrefix(f.Name, ".git/") {
			return nil
		}
		switch f.Mode {
		case filemode.Dir, filemode.Submodule, filemode.Symlink:
			return nil
		}
		dir := path.Dir(f.Name)
		if dir != "." && dir != "" {
			if err := ws.MkdirAll(dir, 0o755); err != nil {
				return err
			}
		}
		reader, err := f.Reader()
		if err != nil {
			return err
		}
		data, err := io.ReadAll(reader)
		closeErr := reader.Close()
		if err != nil {
			return err
		}
		if closeErr != nil {
			return closeErr
		}
		perm := fileModeToPerm(f.Mode)
		return ws.WriteFile(f.Name, data, perm)
	})
}

func fileModeToPerm(mode filemode.FileMode) fs.FileMode {
	if mode == filemode.Executable {
		return 0o755
	}
	return 0o644
}
