package inventory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log"
	"path"
	"runtime"
	"slices"
	"strings"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/filemode"
	"github.com/go-git/go-git/v5/plumbing/object"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	fsx "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	rubygemspec "github.com/picatz/deputy/internal/inventory/plugins/ruby/gemspecx"
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

// scanWorkspace runs the scalibr scan on the provided workspace.
// It configures plugins, runs the scan, and collects results.
func scanWorkspace(ctx context.Context, ws workspace.FS, opts ScanOptions) ([]*extractor.Package, error) {
	cap := defaultCapabilities(ws)
	plugins, err := resolvePlugins(opts, cap)
	if err != nil {
		return nil, err
	}
	plugins = filterInventoryPlugins(plugins)

	// Use the Scanner adapter to isolate scalibr dependencies
	scanner := workspace.ToScanner(ws)
	cfg := &scalibr.ScanConfig{ScanRoots: scanner.ScanRoots(), Plugins: plugins, Capabilities: cap}

	results := scalibr.New().Scan(ctx, cfg)
	pkgs := results.Inventory.Packages
	if extras, err := collectGemfilePackages(ws); err != nil {
		log.Printf("inventory: scan gemfile extras: %v", err)
	} else if len(extras) > 0 {
		pkgs = append(pkgs, extras...)
	}
	if scanErr := summarizeScanFailures(results); scanErr != nil {
		if len(pkgs) > 0 {
			return pkgs, scanErr
		}
		return nil, scanErr
	}
	return pkgs, nil
}

// defaultCapabilities returns the default capabilities for the current environment.
func defaultCapabilities(ws workspace.FS) *plugin.Capabilities {
	cap := &plugin.Capabilities{OS: hostOS(), Network: plugin.NetworkOffline}
	if ws != nil && !ws.IsVirtual() {
		cap.DirectFS = true
	}
	return cap
}

// hostOS returns the scalibr OS enum for the current runtime OS.
func hostOS() plugin.OS {
	switch runtime.GOOS {
	case "linux":
		return plugin.OSLinux
	case "windows":
		return plugin.OSWindows
	case "darwin":
		return plugin.OSMac
	default:
		return plugin.OSUnknown
	}
}

// summarizeScanFailures checks the scan result for plugin failures and returns an error if any critical failures occurred.
func summarizeScanFailures(res *scalibr.ScanResult) error {
	if res == nil {
		return nil
	}

	failures := make([]string, 0, len(res.PluginStatus))
	for _, st := range res.PluginStatus {
		if st == nil || st.Status == nil {
			continue
		}
		if st.Status.Status != plugin.ScanStatusFailed {
			continue
		}
		reason := st.Status.FailureReason
		if reason == "" {
			reason = "unknown error"
		}
		failures = append(failures, fmt.Sprintf("%s: %s", st.Name, reason))
	}
	if len(failures) > 0 {
		return fmt.Errorf("plugin failures: %s", strings.Join(failures, "; "))
	}

	if res.Status == nil {
		return nil
	}

	switch res.Status.Status {
	case plugin.ScanStatusSucceeded:
		return nil
	case plugin.ScanStatusFailed:
		if res.Status.FailureReason != "" {
			return fmt.Errorf("scan failed: %s", res.Status.FailureReason)
		}
		return fmt.Errorf("scan failed")
	case plugin.ScanStatusPartiallySucceeded:
		if res.Status.FailureReason != "" {
			return fmt.Errorf("scan partially succeeded: %s", res.Status.FailureReason)
		}
	}
	return nil
}

// resolvePlugins determines which plugins to use based on the scan options and capabilities.
func resolvePlugins(opts ScanOptions, cap *plugin.Capabilities) ([]plugin.Plugin, error) {
	names := normalizeEcosystems(opts.Ecosystems)
	if len(names) == 0 {
		return pl.FromCapabilities(cap), nil
	}
	plugins, err := pl.FromNames(names)
	if err != nil {
		return nil, fmt.Errorf("error creating plugins: %w", err)
	}
	return plugin.FilterByCapabilities(plugins, cap), nil
}

// filterInventoryPlugins filters out plugins that are not relevant for inventory scanning or are explicitly excluded.
func filterInventoryPlugins(plugins []plugin.Plugin) []plugin.Plugin {
	if len(plugins) == 0 {
		return plugins
	}
	allowedSegments := map[string]struct{}{
		"go":         {},
		"golang":     {},
		"javascript": {},
		"python":     {},
		"ruby":       {},
		"rust":       {},
		"php":        {},
		"java":       {},
		"dotnet":     {},
		"haskell":    {},
		"dart":       {},
		"elixir":     {},
		"erlang":     {},
		"swift":      {},
		"r":          {},
		"cpp":        {},
	}
	excluded := map[string]struct{}{
		"rust/cargoauditable": {},
	}
	out := make([]plugin.Plugin, 0, len(plugins))
	for _, p := range plugins {
		if _, ok := p.(fsx.Extractor); !ok {
			continue
		}
		if p.Name() == rubygemspec.Name {
			out = append(out, rubygemspec.New())
			continue
		}
		if _, banned := excluded[p.Name()]; banned {
			continue
		}
		seg, _, _ := strings.Cut(p.Name(), "/")
		if _, ok := allowedSegments[seg]; !ok {
			continue
		}
		out = append(out, p)
	}
	return out
}

// normalizeEcosystems cleans up and sorts the ecosystem names.
// It returns nil if "all" is present or the list is empty.
func normalizeEcosystems(names []string) []string {
	if len(names) == 0 {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, raw := range names {
		name := strings.TrimSpace(strings.ToLower(raw))
		if name == "all" {
			return nil
		}
		if name != "" {
			out = append(out, name)
		}
	}
	if len(out) == 0 {
		return nil
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// populateWorkspaceFromTree copies files from a git tree into the workspace.
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

// fileModeToPerm converts a git file mode to a filesystem permission.
func fileModeToPerm(mode filemode.FileMode) fs.FileMode {
	if mode == filemode.Executable {
		return 0o755
	}
	return 0o644
}
