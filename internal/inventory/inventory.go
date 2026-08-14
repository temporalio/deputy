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
	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/go-git/go-git/v5/plumbing/object"
	scalibr "github.com/google/osv-scalibr"
	"github.com/google/osv-scalibr/extractor"
	fsx "github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/plugin"
	pl "github.com/google/osv-scalibr/plugin/list"

	"github.com/temporalio/deputy/internal/collections"
	"github.com/temporalio/deputy/internal/dependency"
	"github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/ecosystem"
	asdfx "github.com/temporalio/deputy/internal/inventory/plugins/asdf/asdfx"
	dockerfilex "github.com/temporalio/deputy/internal/inventory/plugins/docker/dockerfilex"
	ghactions "github.com/temporalio/deputy/internal/inventory/plugins/github/actionsx"
	gradlex "github.com/temporalio/deputy/internal/inventory/plugins/java/gradlex"
	misex "github.com/temporalio/deputy/internal/inventory/plugins/mise/misex"
	rubygemspec "github.com/temporalio/deputy/internal/inventory/plugins/ruby/gemspecx"
	"github.com/temporalio/deputy/internal/inventory/registry"
	"github.com/temporalio/deputy/internal/logs"
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
	// UseGitignore applies .gitignore handling for real local source workspaces.
	// Directory ignores are enforced before scanning; SCALIBR handles file-level
	// ignores best-effort. The option is ignored for virtual workspaces because
	// commit snapshots already represent exact tracked contents.
	UseGitignore bool
	// DetectBaseImage enables base image detection for container image scans.
	// When true, the baseimage enricher queries deps.dev to determine if layers
	// belong to known base images, populating LayerDetails.InBaseImage.
	// This requires network access and adds latency to the scan.
	DetectBaseImage bool
	// ExcludePaths lists glob patterns for directory paths to skip during the
	// filesystem walk (e.g., ".bin/**", "**/testdata"). Matching subtrees are
	// never inventoried. See [CompileExcludePaths] for pattern semantics.
	ExcludePaths []string
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
	ws, err := CommitSnapshotWorkspace(repo, commitHash)
	if err != nil {
		return nil, err
	}
	defer ws.Close()
	return scanWorkspace(ctx, ws, opts)
}

// CommitSnapshotWorkspace materializes the commit's tree into an in-memory
// workspace, giving a ref the same file access a working-tree scan gets from
// its directory: package extraction and graph edge resolution both read from
// it. The caller owns the workspace and must Close it.
func CommitSnapshotWorkspace(repo *git.Repository, commitHash plumbing.Hash) (workspace.FS, error) {
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
	return ws, nil
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
	if opts.UseGitignore && !ws.IsVirtual() {
		cfg.UseGitignore = true
	}

	// Compile .gitignore once and reuse it for both directory pruning and
	// post-scan package-location filtering, avoiding a second workspace walk.
	var ignoredDirs gitignore.Matcher
	if opts.UseGitignore && !ws.IsVirtual() {
		ignoredDirs, err = compileWorkspaceGitignore(ws)
		if err != nil {
			return nil, err
		}
	}

	// Prune excluded directory subtrees from the walk (e.g., vendored tool
	// binaries under .bin). Patterns are compiled up front so a malformed glob
	// surfaces as a scan error rather than silently scanning everything.
	skip, err := compileScanSkipDirGlob(ws, opts, ignoredDirs)
	if err != nil {
		return nil, err
	}
	if skip != nil {
		cfg.SkipDirGlob = skip
	}

	results := scalibr.New().Scan(ctx, cfg)
	pkgs := results.Inventory.Packages
	extras, err := collectGemfilePackages(ws)
	if err != nil {
		slog.WarnContext(ctx, "inventory: scan gemfile extras", "error", err)
	}
	if len(extras) > 0 {
		pkgs = append(pkgs, extras...)
	}
	if ignoredDirs != nil {
		pkgs = filterGitignoredPackageLocations(ws, pkgs, ignoredDirs)
	}
	pkgs = preferLockfileResolutions(pkgs)
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
	includeMise := shouldIncludeMise(names)
	includeAsdf := shouldIncludeAsdf(names)
	scalibrNames := scalibrEcosystemNames(filterExternalEcosystems(names))

	var plugins []plugin.Plugin

	switch {
	case len(scalibrNames) > 0:
		// SCALIBR ecosystems specified
		var err error
		plugins, err = pl.FromNames(scalibrNames, nil)
		if err != nil {
			return nil, fmt.Errorf("unsupported ecosystem filter (expected names like go, npm, pypi, cargo): %w", err)
		}
		plugins = appendRegisteredPlugins(plugins)
		plugins = plugin.FilterByCapabilities(plugins, cap)
	case names != nil:
		// Only internal ecosystems (user specified something but no SCALIBR names)
	default:
		// "all" case
		var err error
		plugins, err = pl.FromCapabilities(cap, nil)
		if err != nil {
			return nil, fmt.Errorf("failed to enumerate SCALIBR plugins: %w", err)
		}
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
	if includeMise {
		plugins = append(plugins, misex.New())
	}
	if includeAsdf {
		plugins = append(plugins, asdfx.New())
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
		misex.Name,
		asdfx.Name,
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

// miseAliases contains all recognized aliases for the mise ecosystem
// (mise.toml family). The asdf .tool-versions format is a separate ecosystem.
var miseAliases = collections.NewSet(
	"mise", "mise-en-place", "rtx",
)

// isMiseEcosystem checks if a name is an alias for mise scanning.
func isMiseEcosystem(name string) bool {
	return miseAliases.Has(name)
}

// shouldIncludeMise reports whether the internal mise plugin should run.
// If names is nil (meaning all ecosystems), it returns true.
func shouldIncludeMise(names []string) bool {
	if names == nil {
		return true
	}
	return slices.ContainsFunc(names, isMiseEcosystem)
}

// asdfAliases contains all recognized aliases for the asdf ecosystem
// (.tool-versions format), kept distinct from mise to mirror OSV-SCALIBR's
// runtime/asdf vs runtime/mise split.
var asdfAliases = collections.NewSet(
	"asdf", "tool-versions", ".tool-versions",
)

// isAsdfEcosystem checks if a name is an alias for asdf scanning.
func isAsdfEcosystem(name string) bool {
	return asdfAliases.Has(name)
}

// shouldIncludeAsdf reports whether the internal asdf plugin should run.
// If names is nil (meaning all ecosystems), it returns true.
func shouldIncludeAsdf(names []string) bool {
	if names == nil {
		return true
	}
	return slices.ContainsFunc(names, isAsdfEcosystem)
}

// filterExternalEcosystems removes internal ecosystem aliases so upstream scalibr
// plugin resolution does not error on unknown names.
func filterExternalEcosystems(names []string) []string {
	if names == nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, n := range names {
		if isGitHubActionsEcosystem(n) || isDockerfileEcosystem(n) || isMiseEcosystem(n) || isAsdfEcosystem(n) {
			continue
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		return nil
	}
	return out
}

// scalibrEcosystemNames translates Deputy ecosystem names into the OSV-SCALIBR
// plugin group names that upstream plugin resolution understands (cargo ->
// rust, npm -> javascript, pypi -> python, maven -> java). Deputy's canonical
// vocabulary is what every surface emits (purl types, finding ecosystems, CLI
// help), so filters must accept it; a name the registry does not recognize
// passes through verbatim so raw SCALIBR group names (haskell, r, cpp) and
// exact plugin names keep working.
func scalibrEcosystemNames(names []string) []string {
	if names == nil {
		return nil
	}
	out := make([]string, 0, len(names))
	for _, name := range names {
		if prefixes := ecosystem.Parse(name).ScalibrPrefixes(); len(prefixes) > 0 {
			out = append(out, prefixes...)
			continue
		}
		out = append(out, name)
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

// DefaultScanner returns a function that uses the default scanning logic.
// This adapter is useful for dependency injection in tests or custom pipelines.
func DefaultScanner() func(ctx context.Context, ws workspace.FS, ecosystems []string) ([]*extractor.Package, error) {
	return func(ctx context.Context, ws workspace.FS, ecosystems []string) ([]*extractor.Package, error) {
		return ScanPackagesWorking(ctx, ws, ScanOptions{Ecosystems: ecosystems})
	}
}

// manifestLockPairs maps dependency manifest basenames to the lockfile
// basenames that fully resolve them. When both are extracted from the same
// project, the manifest entries carry version requirements (tokio = "1.26"),
// not resolutions, and must yield to the lockfile's exact versions.
var manifestLockPairs = map[string]string{
	"Cargo.toml": "Cargo.lock",
}

// preferLockfileResolutions drops manifest-derived package entries that a
// paired lockfile actually resolves. Matching requirement strings against
// advisories as if they were exact versions produces false positives (and
// misses) whenever the lockfile resolves to a different version. A manifest
// entry yields only when the same package (name and PURL type) was also
// extracted from the paired lockfile in the same or an ancestor directory
// (Cargo workspaces keep one lock at the root for all member crates). The
// per-package containment check matters: an ancestor lockfile can belong to
// a workspace that excludes the manifest's project (a nested standalone
// crate, a vendored manifest), in which case the lockfile extractor never
// emitted the package and dropping the manifest entry would erase the package
// from the inventory entirely. Manifest-only projects likewise keep their
// requirement-derived entries: there is no resolution to prefer, and partial
// inventory beats none.
func preferLockfileResolutions(pkgs []*extractor.Package) []*extractor.Package {
	// lockContents maps a lockfile basename to the directories where that
	// lockfile was extracted, and for each directory the identity keys of the
	// packages the lockfile actually resolved.
	lockContents := make(map[string]map[string]map[string]struct{})
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		for _, loc := range dependency.PackagePaths(pkg) {
			base := path.Base(loc)
			for _, lock := range manifestLockPairs {
				if base != lock {
					continue
				}
				dirs := lockContents[lock]
				if dirs == nil {
					dirs = make(map[string]map[string]struct{})
					lockContents[lock] = dirs
				}
				dir := path.Dir(loc)
				if dirs[dir] == nil {
					dirs[dir] = make(map[string]struct{})
				}
				dirs[dir][packageIdentityKey(pkg)] = struct{}{}
			}
		}
	}
	if len(lockContents) == 0 {
		return pkgs
	}

	// resolved reports whether a manifest location's package is covered by
	// its paired lockfile in the same directory or any ancestor directory.
	// Only a lockfile that contains the package counts: the mere presence of
	// an unrelated ancestor lockfile resolves nothing.
	resolved := func(key, loc string) bool {
		lock, ok := manifestLockPairs[path.Base(loc)]
		if !ok {
			return false
		}
		dirs := lockContents[lock]
		if len(dirs) == 0 {
			return false
		}
		for d := path.Dir(loc); ; d = path.Dir(d) {
			if _, ok := dirs[d][key]; ok {
				return true
			}
			if d == "." || d == "/" {
				return false
			}
		}
	}

	out := make([]*extractor.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			out = append(out, pkg)
			continue
		}
		locations := dependency.PackagePaths(pkg)
		if len(locations) == 0 {
			out = append(out, pkg)
			continue
		}
		key := packageIdentityKey(pkg)
		kept := slices.DeleteFunc(locations, func(loc string) bool {
			return resolved(key, loc)
		})
		if len(kept) == 0 {
			continue
		}
		dependency.SetPackagePaths(pkg, kept)
		out = append(out, pkg)
	}
	return out
}

// packageIdentityKey identifies a package independent of its version, so a
// manifest requirement entry (tokio = "1.26") can be matched against the
// lockfile resolution of the same package (tokio 1.52.3). Name alone is not
// enough: distinct ecosystems can share package names.
func packageIdentityKey(pkg *extractor.Package) string {
	return pkg.PURLType + "\x00" + pkg.Name
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
			dependency.SetPackagePaths(existing, mergeLocations(dependency.PackagePaths(existing), dependency.PackagePaths(pkg)))
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
