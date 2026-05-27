package inventory

import (
	"context"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
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

	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/ecosystem"
	dockerfilex "github.com/temporalio/deputy/internal/inventory/plugins/docker/dockerfilex"
	"github.com/temporalio/deputy/internal/logs"
	"github.com/temporalio/deputy/internal/dependency/graph"
	ghactions "github.com/temporalio/deputy/internal/inventory/plugins/github/actionsx"
	gradlex "github.com/temporalio/deputy/internal/inventory/plugins/java/gradlex"
	"github.com/temporalio/deputy/internal/inventory/registry"
	rubygemspec "github.com/temporalio/deputy/internal/inventory/plugins/ruby/gemspecx"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

func init() {
	// Initialize the BOM resolver for Gradle projects.
	// This enables version resolution from deps.dev for BOM-managed dependencies.
	graph.InitGradleBOMResolver()
}

// ScanOptions configures how scalibr scans a workspace.
type ScanOptions struct {
	Ecosystems []string
	// DetectBaseImage enables base image detection for container image scans.
	// When true, the baseimage enricher queries deps.dev to determine if layers
	// belong to known base images, populating LayerDetails.InBaseImage.
	// This requires network access and adds latency to the scan.
	DetectBaseImage bool
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
		_ = ws.Close() // best-effort cleanup on error
		return nil, err
	}
	defer ws.Close()
	return scanWorkspace(ctx, ws, opts)
}

// scanWorkspace runs the scalibr scan on the provided workspace.
// It configures plugins, runs the scan, and collects results.
func scanWorkspace(ctx context.Context, ws workspace.FS, opts ScanOptions) ([]*extractor.Package, error) {
	// Discover and register external plugins from PATH (deputy-extractor-* binaries)
	if registered, err := registry.DiscoverAndRegisterDefault(ctx); err != nil {
		logs.Debug(ctx, "inventory: plugin discovery failed", "error", err)
	} else if len(registered) > 0 {
		logs.Debug(ctx, "inventory: discovered external plugins", "plugins", registered)
	}

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
	extras, err := collectGemfilePackages(ws)
	if err != nil {
		slog.WarnContext(ctx, "inventory: scan gemfile extras", "error", err)
	}
	if len(extras) > 0 {
		pkgs = append(pkgs, extras...)
	}
	if scanErr := summarizeScanFailures(results); scanErr != nil {
		if len(pkgs) > 0 {
			return deduplicatePackages(pkgs), scanErr
		}
		return nil, scanErr
	}
	return deduplicatePackages(pkgs), nil
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
	includeActions := shouldIncludeGitHubActions(names)
	includeDockerfile := shouldIncludeDockerfile(names)
	includeGradle := shouldIncludeGradle(names)
	scalibrNames := filterExternalEcosystems(names)

	var plugins []plugin.Plugin

	switch {
	case len(scalibrNames) > 0:
		// SCALIBR ecosystems specified
		var err error
		plugins, err = pl.FromNames(scalibrNames)
		if err != nil {
			return nil, fmt.Errorf("error creating plugins: %w", err)
		}
		plugins = appendRegisteredPlugins(plugins)
		plugins = plugin.FilterByCapabilities(plugins, cap)
	case names != nil:
		// Only internal ecosystems (user specified something but no SCALIBR names)
	default:
		// "all" case
		plugins = pl.FromCapabilities(cap)
		plugins = appendRegisteredPlugins(plugins)
	}

	if includeActions {
		plugins = append(plugins, ghactions.New())
	}
	if includeDockerfile {
		plugins = append(plugins, dockerfilex.New())
	}
	if includeGradle {
		plugins = append(plugins, gradlex.NewBuildGradleExtractor())
		plugins = append(plugins, gradlex.NewVerificationMetadataExtractor())
	}

	return plugins, nil
}

// appendRegisteredPlugins adds SCALIBR-adapted plugins from the registry.
func appendRegisteredPlugins(plugins []plugin.Plugin) []plugin.Plugin {
	extPlugins := registry.ToScalibrPlugins()
	for _, ext := range extPlugins {
		slog.Debug("inventory: adding registered plugin", "name", ext.Name())
		plugins = append(plugins, ext)
	}
	return plugins
}

// filterInventoryPlugins filters out plugins that are not relevant for inventory scanning or are explicitly excluded.
func filterInventoryPlugins(plugins []plugin.Plugin) []plugin.Plugin {
	if len(plugins) == 0 {
		return plugins
	}
	allowedSegments := collections.NewSet(ecosystem.AllScalibrPrefixes()...)
	excluded := collections.NewSet("rust/cargoauditable")
	// Deputy-provided custom plugins that bypass the SCALIBR prefix filter.
	// This includes both built-in Deputy plugins and discovered external plugins.
	deputyPlugins := collections.NewSet(
		rubygemspec.Name,
		dockerfilex.Name,
		gradlex.BuildGradleName,
		gradlex.VerificationMetadataName,
	)
	// Add discovered external plugins to the allowlist
	for _, p := range registry.GetPlugins() {
		if p.Info != nil {
			deputyPlugins.Add(p.Info.Name)
			slog.Debug("inventory: adding external plugin to allowlist", "name", p.Info.Name)
		}
	}
	out := make([]plugin.Plugin, 0, len(plugins))
	for _, p := range plugins {
		if _, ok := p.(fsx.Extractor); !ok {
			slog.Debug("inventory: filtering out non-extractor plugin", "name", p.Name())
			continue
		}
		// Deputy-provided custom plugins bypass the SCALIBR prefix filter.
		if deputyPlugins.Has(p.Name()) {
			slog.Debug("inventory: keeping deputy/external plugin", "name", p.Name())
			out = append(out, p)
			continue
		}
		if excluded.Has(p.Name()) {
			slog.Debug("inventory: excluding plugin", "name", p.Name())
			continue
		}
		seg, _, _ := strings.Cut(p.Name(), "/")
		if !allowedSegments.Has(seg) {
			slog.Debug("inventory: filtering out plugin with unknown prefix", "name", p.Name(), "segment", seg)
			continue
		}
		out = append(out, p)
	}
	slog.Debug("inventory: filtered plugins", "count", len(out))
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

// shouldIncludeGitHubActions reports whether the internal GitHub Actions plugin should run.
// If names is nil (meaning all ecosystems), it returns true.
// githubActionsAliases contains all recognized aliases for GitHub Actions ecosystem.
var githubActionsAliases = collections.NewSet(
	"github", "github-actions", "githubactions", "actions", "gha",
)

// isGitHubActionsEcosystem checks if a name is an alias for GitHub Actions.
func isGitHubActionsEcosystem(name string) bool {
	return githubActionsAliases.Has(name)
}

func shouldIncludeGitHubActions(names []string) bool {
	if names == nil {
		return true
	}
	return slices.ContainsFunc(names, isGitHubActionsEcosystem)
}

// dockerfileAliases contains all recognized aliases for Dockerfile ecosystem.
var dockerfileAliases = collections.NewSet(
	"docker", "dockerfile", "container", "containerfile", "oci",
)

// isDockerfileEcosystem checks if a name is an alias for Dockerfile scanning.
func isDockerfileEcosystem(name string) bool {
	return dockerfileAliases.Has(name)
}

// shouldIncludeDockerfile reports whether the internal Dockerfile plugin should run.
// If names is nil (meaning all ecosystems), it returns true.
func shouldIncludeDockerfile(names []string) bool {
	if names == nil {
		return true
	}
	return slices.ContainsFunc(names, isDockerfileEcosystem)
}

// gradleAliases contains all recognized aliases for Gradle/Maven ecosystem.
var gradleAliases = collections.NewSet(
	"java", "maven", "gradle", "jvm", "kotlin",
)

// isGradleEcosystem checks if a name is an alias for Gradle/Maven scanning.
func isGradleEcosystem(name string) bool {
	return gradleAliases.Has(name)
}

// shouldIncludeGradle reports whether the internal Gradle plugins should run.
// If names is nil (meaning all ecosystems), it returns true.
func shouldIncludeGradle(names []string) bool {
	if names == nil {
		return true
	}
	return slices.ContainsFunc(names, isGradleEcosystem)
}

// filterExternalEcosystems removes internal ecosystem aliases so upstream scalibr
// plugin resolution does not error on unknown names.
func filterExternalEcosystems(names []string) []string {
	if names == nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if isGitHubActionsEcosystem(n) || isDockerfileEcosystem(n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
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

// DefaultScanner returns a function that uses the default scanning logic.
// This adapter is useful for dependency injection in tests or custom pipelines.
func DefaultScanner() func(ctx context.Context, ws workspace.FS, ecosystems []string) ([]*extractor.Package, error) {
	return func(ctx context.Context, ws workspace.FS, ecosystems []string) ([]*extractor.Package, error) {
		return ScanPackagesWorking(ctx, ws, ScanOptions{Ecosystems: ecosystems})
	}
}

// deduplicatePackages collapses packages with identical PURLs, merging their locations.
// This handles cases where multiple extractors discover the same package (e.g., go.mod and go.sum).
func deduplicatePackages(pkgs []*extractor.Package) []*extractor.Package {
	if len(pkgs) == 0 {
		return pkgs
	}

	// Use PURL as the deduplication key since it uniquely identifies a package
	seen := make(map[string]*extractor.Package, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		purl := pkg.PURL()
		if purl == nil {
			// Keep packages without PURLs as-is (shouldn't happen in practice)
			continue
		}
		key := purl.String()
		if existing, ok := seen[key]; ok {
			// Merge locations from duplicate
			existing.Locations = mergeLocations(existing.Locations, pkg.Locations)
			// Merge licenses (take non-empty)
			if len(existing.Licenses) == 0 && len(pkg.Licenses) > 0 {
				existing.Licenses = pkg.Licenses
			}
		} else {
			seen[key] = pkg
		}
	}

	out := make([]*extractor.Package, 0, len(seen))
	for _, pkg := range seen {
		out = append(out, pkg)
	}

	// Sort for deterministic output - map iteration order is randomized in Go.
	// This ensures consistent diff results regardless of iteration order.
	slices.SortFunc(out, func(a, b *extractor.Package) int {
		// Primary sort by PURL string for deterministic ordering
		aPURL, bPURL := a.PURL(), b.PURL()
		if aPURL != nil && bPURL != nil {
			return strings.Compare(aPURL.String(), bPURL.String())
		}
		// Fallback to name if PURL is nil
		if n := strings.Compare(a.Name, b.Name); n != 0 {
			return n
		}
		return strings.Compare(a.Version, b.Version)
	})

	return out
}

// mergeLocations combines two location slices, removing duplicates.
// The result is sorted for deterministic output.
func mergeLocations(a, b []string) []string {
	if len(b) == 0 {
		if len(a) > 1 {
			slices.Sort(a)
		}
		return a
	}
	if len(a) == 0 {
		if len(b) > 1 {
			slices.Sort(b)
		}
		return b
	}
	seen := make(map[string]struct{}, len(a)+len(b))
	for _, loc := range a {
		seen[loc] = struct{}{}
	}
	for _, loc := range b {
		if _, ok := seen[loc]; !ok {
			a = append(a, loc)
			seen[loc] = struct{}{}
		}
	}
	slices.Sort(a)
	return a
}
