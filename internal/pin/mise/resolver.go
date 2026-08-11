package mise

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"unicode"

	pb "deps.dev/api/v3"
	depssemver "deps.dev/util/semver"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/credentials"
	"google.golang.org/grpc/status"

	depgraph "github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/forge"
	forgegithub "github.com/temporalio/deputy/internal/forge/github"
	ghreleases "github.com/temporalio/deputy/internal/forge/github/releases"
	misecfg "github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/releases"
	"github.com/temporalio/deputy/internal/releases/aqua"
	"golang.org/x/mod/module"
	"golang.org/x/mod/semver"
)

// depsDevEndpoint is the deps.dev Insights API endpoint.
const depsDevEndpoint = "api.deps.dev:443"

var (
	// errGoModuleNotFound marks Go tool import paths that could not be mapped
	// to a deps.dev module.
	errGoModuleNotFound = errors.New("go module not found")
	// errGoRuntimeVersionNotFound marks Go runtime selectors that no stable Go
	// release matched.
	errGoRuntimeVersionNotFound = errors.New("go runtime version not found")
)

// Resolver resolves a mise tool's fuzzy version request to an exact version.
// It is an interface so the pin strategy can be tested without network access
// or a host mise binary.
type Resolver interface {
	// Latest returns the newest exact version for toolKey matching prefix.
	// prefix is the requested fuzzy version ("20", "lts", etc.); an empty
	// prefix or "latest" means the newest available version overall.
	Latest(ctx context.Context, toolKey, prefix string) (string, error)
}

// depsDevPackageClient is the narrow deps.dev API surface native package
// resolvers need.
type depsDevPackageClient interface {
	GetPackage(ctx context.Context, in *pb.GetPackageRequest, opts ...grpc.CallOption) (*pb.Package, error)
}

// releaseClient is the narrow interface native runtime resolvers need from an
// upstream release metadata source.
type releaseClient interface {
	List(ctx context.Context) ([]releases.Release, error)
}

// temurinReleaseClient is the narrow interface Java runtime resolution needs
// from Eclipse Temurin release metadata.
type temurinReleaseClient interface {
	ListFeature(ctx context.Context, feature int) ([]releases.Release, error)
}

// javaReleaseClient is the narrow interface Java vendor release resolution
// needs from Mise's Java metadata mirror.
type javaReleaseClient interface {
	List(ctx context.Context) ([]releases.Release, error)
}

// githubReleaseClient is the narrow interface GitHub-release-family mise
// backends need from the GitHub release/tag source.
type githubReleaseClient interface {
	List(ctx context.Context, owner, repo string) ([]releases.Release, error)
}

// githubMatchingTagClient is implemented by GitHub clients that can query tags
// by ref prefix without paginating the entire tag set.
type githubMatchingTagClient interface {
	ListMatchingTags(ctx context.Context, owner, repo, prefix string) ([]releases.Release, error)
}

// goProxyVersionClient is the narrow Go proxy surface needed for branch and
// revision selectors in go:<import path> tools.
type goProxyVersionClient interface {
	FetchInfo(ctx context.Context, modulePath, version string) (depgraph.GoModuleInfo, error)
}

// nativeResolver resolves mise versions using Deputy-owned metadata clients.
type nativeResolver struct {
	once                sync.Once
	mu                  sync.Mutex
	client              depsDevPackageClient
	goReleaseClient     releaseClient
	nodeReleaseClient   releaseClient
	pythonReleaseClient releaseClient
	tfReleaseClient     releaseClient
	gcloudReleaseClient releaseClient
	onePasswordClient   releaseClient
	temurinClient       temurinReleaseClient
	openJDKClient       javaReleaseClient
	javaClients         map[string]javaReleaseClient
	githubReleaseClient githubReleaseClient
	goProxyClient       goProxyVersionClient
	registryClient      miseRegistryClient
	aquaClient          aqua.Client
	conn                *grpc.ClientConn
	latestCache         map[resolverCacheKey]string
	initErr             error
}

// resolverCacheKey identifies one native version-resolution request.
type resolverCacheKey struct {
	toolKey string
	prefix  string
}

// newNativeResolver returns a resolver configured with Deputy's default native
// metadata clients.
func newNativeResolver() *nativeResolver {
	return &nativeResolver{registryClient: newMiseRegistryClient()}
}

// Latest resolves toolKey@prefix using Deputy-owned metadata sources.
func (r *nativeResolver) Latest(ctx context.Context, toolKey, prefix string) (string, error) {
	key := resolverCacheKey{toolKey: strings.TrimSpace(toolKey), prefix: strings.TrimSpace(prefix)}
	if version, ok := r.cachedLatest(key); ok {
		return version, nil
	}
	version, err := r.latest(ctx, toolKey, prefix)
	if err != nil {
		return "", err
	}
	r.cacheLatest(key, version)
	return version, nil
}

// latest resolves toolKey@prefix without consulting the in-run cache.
func (r *nativeResolver) latest(ctx context.Context, toolKey, prefix string) (string, error) {
	backend, name := misecfg.SplitBackend(toolKey)
	if backend == "go" {
		return r.latestGoTool(ctx, toolKey, name, prefix)
	}
	if runtime, ok := nativeRuntimeTool(backend, name); ok {
		return r.latestRuntime(ctx, toolKey, runtime, prefix)
	}
	if runtime, ok := nativeReleaseTool(backend, name); ok {
		return r.latestRuntime(ctx, toolKey, runtime, prefix)
	}
	if backend == "aqua" {
		return r.latestAquaPackage(ctx, toolKey, name, prefix)
	}
	// A bare registry name backed by a GitHub repo (mise resolves these through
	// its registry, usually an aqua backend). Resolve via the canonical aqua
	// recipe so its version_prefix and source apply — otherwise prefixed tags
	// (e.g. jq's "jq-1.8.1") never match a major channel and selection can fall
	// through to stray legacy tags. Falls back to the owner/repo heuristic when
	// the recipe can't be read.
	if backend == "" {
		if repo, ok := githubReleaseRegistryAlias(name); ok {
			return r.latestAquaPackage(ctx, toolKey, repo, prefix)
		}
	}
	if owner, repo, ok := githubReleaseRepo(backend, name); ok {
		return r.latestGitHubRelease(ctx, toolKey, owner, repo, prefix)
	}
	if backend == "" {
		if version, ok, err := r.latestJavaRuntime(ctx, toolKey, name, prefix); ok || err != nil {
			return version, err
		}
		if version, ok, err := r.latestFromMiseRegistry(ctx, name, prefix); err != nil {
			switch {
			case errors.Is(err, errMiseRegistryToolNotFound), errors.Is(err, errMiseRegistryNoNativeBackend):
				return "", fmt.Errorf("native resolution does not support mise tool %q: %w", toolKey, err)
			default:
				return "", fmt.Errorf("mise registry lookup for %q: %w", toolKey, err)
			}
		} else if ok {
			return version, nil
		}
	}
	coord, ok := nativeCoordinateForTool(toolKey)
	if !ok {
		return "", fmt.Errorf("native resolution does not support mise tool %q", toolKey)
	}
	return r.latestPackage(ctx, toolKey, coord, prefix)
}

// cachedLatest returns a cached successful version resolution.
func (r *nativeResolver) cachedLatest(key resolverCacheKey) (string, bool) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.latestCache == nil {
		return "", false
	}
	version, ok := r.latestCache[key]
	return version, ok
}

// cacheLatest stores a successful version resolution.
func (r *nativeResolver) cacheLatest(key resolverCacheKey, version string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.latestCache == nil {
		r.latestCache = map[resolverCacheKey]string{}
	}
	r.latestCache[key] = version
}

// latestPackage resolves a deps.dev-backed mise package backend.
func (r *nativeResolver) latestPackage(ctx context.Context, toolKey string, coord nativeCoordinate, prefix string) (string, error) {
	client, err := r.depsClient()
	if err != nil {
		return "", err
	}
	pkg, err := client.GetPackage(ctx, &pb.GetPackageRequest{
		PackageKey: &pb.PackageKey{
			System: coord.system,
			Name:   coord.name,
		},
	})
	if err != nil {
		return "", fmt.Errorf("deps.dev package lookup for %s: %w", toolKey, err)
	}
	version, err := newestVersion(pkg.GetVersions(), coord.semverSystem, prefix)
	if err != nil {
		return "", fmt.Errorf("resolving %s@%s: %w", toolKey, prefix, err)
	}
	return version, nil
}

// latestJavaRuntime resolves the mise core Java selectors Deputy models
// natively. Numeric shorthand follows Mise's default OpenJDK shorthand vendor;
// explicit vendor-version selectors use Mise's Java metadata mirror.
func (r *nativeResolver) latestJavaRuntime(ctx context.Context, toolKey, name, selector string) (string, bool, error) {
	if !strings.EqualFold(strings.TrimSpace(name), "java") {
		return "", false, nil
	}
	js, ok := nativeJavaSelector(selector)
	if !ok {
		return "", false, nil
	}
	switch js.vendor {
	case "temurin":
		return r.latestTemurinRuntime(ctx, toolKey, selector, js)
	case "openjdk":
		return r.latestOpenJDKRuntime(ctx, toolKey, selector, js)
	default:
		return r.latestMiseJavaRuntime(ctx, toolKey, selector, js)
	}
}

// latestTemurinRuntime resolves a Temurin Java selector through Adoptium
// release-version metadata.
func (r *nativeResolver) latestTemurinRuntime(ctx context.Context, toolKey, selector string, js javaSelector) (string, bool, error) {
	list, err := r.temurinReleases().ListFeature(ctx, js.feature)
	if err != nil {
		return "", true, fmt.Errorf("temurin release metadata lookup for %s: %w", toolKey, err)
	}
	version, err := newestRelease(list, releases.SelectOptions{
		SemverSystem: depssemver.DefaultSystem,
	}, js.prefix)
	if err != nil {
		return "", true, fmt.Errorf("resolving %s@%s from Temurin releases: %w", toolKey, selector, err)
	}
	return "temurin-" + version, true, nil
}

// latestOpenJDKRuntime resolves Java's default numeric shorthand as OpenJDK,
// matching Mise's default java.shorthand_vendor setting.
func (r *nativeResolver) latestOpenJDKRuntime(ctx context.Context, toolKey, selector string, js javaSelector) (string, bool, error) {
	list, err := r.javaVendorReleases(js.vendor).List(ctx)
	if err != nil {
		return "", true, fmt.Errorf("openjdk release metadata lookup for %s: %w", toolKey, err)
	}
	version, err := newestRelease(list, releases.SelectOptions{
		SemverSystem: depssemver.DefaultSystem,
	}, js.prefix)
	if err != nil {
		return "", true, fmt.Errorf("resolving %s@%s from OpenJDK releases: %w", toolKey, selector, err)
	}
	if js.shorthand {
		return version, true, nil
	}
	return "openjdk-" + version, true, nil
}

// latestMiseJavaRuntime resolves an explicit non-Temurin Java vendor-version
// selector through Mise's Java metadata mirror.
func (r *nativeResolver) latestMiseJavaRuntime(ctx context.Context, toolKey, selector string, js javaSelector) (string, bool, error) {
	list, err := r.javaVendorReleases(js.vendor).List(ctx)
	if err != nil {
		return "", true, fmt.Errorf("%s release metadata lookup for %s: %w", js.vendor, toolKey, err)
	}
	version, err := newestRelease(list, releases.SelectOptions{
		SemverSystem: depssemver.DefaultSystem,
	}, js.prefix)
	if err != nil {
		return "", true, fmt.Errorf("resolving %s@%s from %s releases: %w", toolKey, selector, js.vendor, err)
	}
	return js.vendor + "-" + version, true, nil
}

// latestGoTool resolves go:<import path> tools by probing candidate module
// roots in deps.dev.
func (r *nativeResolver) latestGoTool(ctx context.Context, toolKey, importPath, prefix string) (string, error) {
	importPath = strings.TrimSpace(importPath)
	if importPath == "" {
		return "", fmt.Errorf("native resolution does not support empty Go tool import path %q", toolKey)
	}
	candidates := goModuleCandidates(importPath)
	if len(candidates) == 0 {
		return "", fmt.Errorf("invalid Go tool import path %q: %w", importPath, errGoModuleNotFound)
	}
	client, err := r.depsClient()
	if err != nil {
		return "", err
	}
	for _, modulePath := range candidates {
		pkg, err := client.GetPackage(ctx, &pb.GetPackageRequest{
			PackageKey: &pb.PackageKey{
				System: pb.System_GO,
				Name:   modulePath,
			},
		})
		if err != nil {
			if status.Code(err) == codes.NotFound {
				continue
			}
			return "", fmt.Errorf("deps.dev Go package lookup for %s candidate %s: %w", toolKey, modulePath, err)
		}
		version, err := newestVersion(pkg.GetVersions(), depssemver.Go, prefix)
		if err != nil {
			if version, ok, proxyErr := r.latestGoToolProxyQuery(ctx, modulePath, prefix); ok {
				if proxyErr != nil {
					return "", proxyErr
				}
				return version, nil
			}
			return "", fmt.Errorf("resolving %s@%s from Go module %s: %w", toolKey, prefix, modulePath, err)
		}
		return goToolVersionForMise(version), nil
	}
	return "", fmt.Errorf("deps.dev Go package lookup for %s: %w for import path %q", toolKey, errGoModuleNotFound, importPath)
}

// latestGoToolProxyQuery resolves a branch, tag, or revision selector through
// the Go module proxy's .info endpoint.
func (r *nativeResolver) latestGoToolProxyQuery(ctx context.Context, modulePath, selector string) (string, bool, error) {
	query := goProxyQuerySelector(selector)
	if query == "" {
		return "", false, nil
	}
	info, err := r.goProxyVersions().FetchInfo(ctx, modulePath, query)
	if err != nil {
		return "", true, fmt.Errorf("querying Go proxy for %s@%s: %w", modulePath, query, err)
	}
	return goToolVersionForMise(info.Version), true, nil
}

// latestRuntime resolves a core runtime or well-known runtime plugin through
// its native release metadata source.
func (r *nativeResolver) latestRuntime(ctx context.Context, toolKey, runtime, prefix string) (string, error) {
	list, err := r.runtimeReleasesClient(runtime).List(ctx)
	if err != nil {
		return "", fmt.Errorf("%s release metadata lookup for %s: %w", runtime, toolKey, err)
	}
	version, err := newestRelease(list, runtimeSelectOptions(runtime), prefix)
	if err != nil {
		if runtime == "go" && errors.Is(err, releases.ErrNoMatch) {
			return "", fmt.Errorf("%w: %v", errGoRuntimeVersionNotFound, err)
		}
		if runtime == "gcloud" && errors.Is(err, releases.ErrNoMatch) {
			if version, ok := googleCloudSDKVersionFromSelector(prefix); ok {
				return version, nil
			}
		}
		return "", fmt.Errorf("resolving %s@%s: %w", toolKey, prefix, err)
	}
	return version, nil
}

// latestGitHubRelease resolves repo-shaped aqua:, ubi:, and github: tools from
// GitHub releases and tags.
func (r *nativeResolver) latestGitHubRelease(ctx context.Context, toolKey, owner, repo, prefix string) (string, error) {
	return r.latestGitHubReleaseStrip(ctx, toolKey, owner, repo, prefix, "")
}

// latestGitHubReleaseStrip is [latestGitHubRelease] with an extra tag prefix to
// strip during selection (e.g. an aqua recipe's version_prefix like "cli-").
func (r *nativeResolver) latestGitHubReleaseStrip(ctx context.Context, toolKey, owner, repo, prefix, versionPrefix string) (string, error) {
	list, err := r.githubReleaseList(ctx, owner, repo, prefix)
	if err != nil {
		return "", fmt.Errorf("GitHub release metadata lookup for %s: %w", toolKey, err)
	}
	if strings.EqualFold(owner, "ClickHouse") && strings.EqualFold(repo, "ClickHouse") {
		version, err := newestClickHouseRelease(list, prefix)
		if err != nil {
			return "", fmt.Errorf("resolving %s@%s from GitHub releases for %s/%s: %w", toolKey, prefix, owner, repo, err)
		}
		return version, nil
	}
	opts := githubReleaseSelectOptions(owner, repo)
	if versionPrefix != "" {
		opts.StripPrefixes = append(opts.StripPrefixes, versionPrefix)
	}
	version, err := newestRelease(list, opts, prefix)
	if err != nil {
		return "", fmt.Errorf("resolving %s@%s from GitHub releases for %s/%s: %w", toolKey, prefix, owner, repo, err)
	}
	return version, nil
}

// aquaRegistry returns the configured aqua registry client or Deputy's default.
func (r *nativeResolver) aquaRegistry() aqua.Client {
	if r.aquaClient != nil {
		return r.aquaClient
	}
	return aqua.NewClient()
}

// latestAquaPackage resolves an aqua-backed tool by reading its canonical aqua
// registry recipe to learn the GitHub version source, rather than assuming the
// spec name is itself a GitHub repo. Packages with no enumerable GitHub source
// (e.g. bare http downloads such as 1password/cli) are not natively resolvable
// and return [releases.ErrNoMatch] so an allowed host mise binary can take over.
// If the recipe cannot be read, it degrades to the owner/repo heuristic.
func (r *nativeResolver) latestAquaPackage(ctx context.Context, toolKey, name, prefix string) (string, error) {
	pkg, err := r.aquaRegistry().Lookup(ctx, name)
	if err != nil {
		if owner, repo, ok := githubReleaseRepo("aqua", name); ok {
			return r.latestGitHubReleaseStrip(ctx, toolKey, owner, repo, prefix, "")
		}
		return "", fmt.Errorf("aqua registry lookup for %q: %w", toolKey, err)
	}
	owner, repo, ok := pkg.GitHubRepo()
	if !ok {
		return "", fmt.Errorf("%w: aqua package %q has no GitHub version source (type %q)", releases.ErrNoMatch, name, pkg.Type)
	}
	return r.latestGitHubReleaseStrip(ctx, toolKey, owner, repo, prefix, pkg.VersionPrefix)
}

// githubReleaseList returns release metadata, using targeted tag-prefix lookup
// when the source has a known tag shape.
func (r *nativeResolver) githubReleaseList(ctx context.Context, owner, repo, prefix string) ([]releases.Release, error) {
	client := r.githubReleasesClient(ctx)
	if tagPrefix := githubReleaseTagQueryPrefix(owner, repo, prefix); tagPrefix != "" {
		if matching, ok := client.(githubMatchingTagClient); ok {
			return matching.ListMatchingTags(ctx, owner, repo, tagPrefix)
		}
	}
	return client.List(ctx, owner, repo)
}

// githubReleaseSelectOptions returns source-specific normalization for
// GitHub-release-family tools whose tags include product prefixes.
func githubReleaseSelectOptions(owner, repo string) releases.SelectOptions {
	opts := releases.SelectOptions{
		SemverSystem:  depssemver.DefaultSystem,
		StripPrefixes: []string{"v"},
	}
	switch strings.ToLower(owner + "/" + repo) {
	case "apache/maven":
		opts.StripPrefixes = append(opts.StripPrefixes, "maven-")
	case "yarnpkg/berry":
		opts.StripPrefixes = append(opts.StripPrefixes, "@yarnpkg/cli/")
	}
	return opts
}

// githubReleaseTagQueryPrefix returns the GitHub tag ref prefix for sources
// whose relevant tags can be queried narrowly.
func githubReleaseTagQueryPrefix(owner, repo, prefix string) string {
	prefix = strings.TrimSpace(prefixSelector(prefix))
	if prefix == "" || strings.EqualFold(prefix, "latest") {
		return ""
	}
	switch strings.ToLower(owner + "/" + repo) {
	case "apache/maven":
		return "maven-" + strings.TrimPrefix(prefix, "maven-")
	case "yarnpkg/berry":
		return "@yarnpkg/cli/" + strings.TrimPrefix(prefix, "@yarnpkg/cli/")
	case "clickhouse/clickhouse":
		return "v" + strings.TrimPrefix(prefix, "v")
	default:
		return ""
	}
}

// newestClickHouseRelease selects the newest stable ClickHouse release. The
// project encodes stability in tag suffixes such as "-stable", which are not
// semver prereleases.
func newestClickHouseRelease(list []releases.Release, prefix string) (string, error) {
	prefix = prefixSelector(prefix)
	sys := depssemver.DefaultSystem
	var best string
	var bestComparable string
	for _, release := range list {
		if !release.Stable {
			continue
		}
		version := strings.TrimPrefix(strings.TrimSpace(release.Version), "v")
		if !strings.HasSuffix(version, "-stable") {
			continue
		}
		comparable := strings.TrimSuffix(version, "-stable")
		if !misecfg.IsConcreteVersion(comparable) || !versionMatchesPrefix(comparable, prefix) {
			continue
		}
		if best == "" || sys.Compare(comparable, bestComparable) > 0 {
			best = version
			bestComparable = comparable
		}
	}
	if best == "" {
		if prefix == "" {
			return "", fmt.Errorf("%w: no stable versions found", releases.ErrNoMatch)
		}
		return "", fmt.Errorf("%w: no stable version matching %q found", releases.ErrNoMatch, prefix)
	}
	return best, nil
}

// goReleasesClient returns the injected Go release client or the default
// go.dev client.
func (r *nativeResolver) goReleasesClient() releaseClient {
	if r.goReleaseClient != nil {
		return r.goReleaseClient
	}
	return releases.NewGoClient()
}

// runtimeReleasesClient returns the injected or default release client for a
// native core runtime.
func (r *nativeResolver) runtimeReleasesClient(runtime string) releaseClient {
	switch runtime {
	case "go":
		return r.goReleasesClient()
	case "node":
		if r.nodeReleaseClient != nil {
			return r.nodeReleaseClient
		}
		return releases.NewNodeClient()
	case "python":
		if r.pythonReleaseClient != nil {
			return r.pythonReleaseClient
		}
		return releases.NewPythonClient()
	case "terraform":
		if r.tfReleaseClient != nil {
			return r.tfReleaseClient
		}
		return releases.NewHashiCorpClient("terraform")
	case "gcloud":
		if r.gcloudReleaseClient != nil {
			return r.gcloudReleaseClient
		}
		return releases.NewGoogleCloudSDKClient()
	case "1password-cli":
		if r.onePasswordClient != nil {
			return r.onePasswordClient
		}
		return releases.NewOnePasswordCLIClient()
	default:
		return emptyReleaseClient{}
	}
}

// temurinReleases returns the injected Temurin release client or the default
// Adoptium-backed client.
func (r *nativeResolver) temurinReleases() temurinReleaseClient {
	if r.temurinClient != nil {
		return r.temurinClient
	}
	return releases.NewTemurinClient()
}

// javaVendorReleases returns the injected release client for vendor or the
// default Mise Java metadata client.
func (r *nativeResolver) javaVendorReleases(vendor string) javaReleaseClient {
	vendor = strings.ToLower(strings.TrimSpace(vendor))
	if vendor == "openjdk" && r.openJDKClient != nil {
		return r.openJDKClient
	}
	if r.javaClients != nil {
		if client := r.javaClients[vendor]; client != nil {
			return client
		}
	}
	return releases.NewMiseJavaClient(vendor)
}

// githubReleasesClient returns the injected GitHub release client or constructs
// one with Deputy's shared GitHub transport.
func (r *nativeResolver) githubReleasesClient(ctx context.Context) githubReleaseClient {
	if r.githubReleaseClient != nil {
		return r.githubReleaseClient
	}
	return ghreleases.New(forgegithub.NewClient(ctx))
}

// goProxyVersions returns the injected Go proxy client or Deputy's default Go
// proxy metadata client.
func (r *nativeResolver) goProxyVersions() goProxyVersionClient {
	if r.goProxyClient != nil {
		return r.goProxyClient
	}
	return depgraph.NewGoProxyClient("")
}

// depsClient lazily creates the deps.dev API client used by registry and Go
// module resolution.
func (r *nativeResolver) depsClient() (depsDevPackageClient, error) {
	r.once.Do(func() {
		if r.client != nil {
			return
		}
		creds := credentials.NewClientTLSFromCert(nil, "")
		conn, err := grpc.NewClient(depsDevEndpoint, grpc.WithTransportCredentials(creds))
		if err != nil {
			r.initErr = fmt.Errorf("connecting to deps.dev: %w", err)
			return
		}
		r.conn = conn
		r.client = pb.NewInsightsClient(conn)
	})
	if r.initErr != nil {
		return nil, r.initErr
	}
	return r.client, nil
}

// Close releases the lazily-created deps.dev gRPC connection, if one was opened.
// It is safe to call on a resolver that never dialed and safe to call more than
// once. Callers invoke it after all resolution has completed.
func (r *nativeResolver) Close() error {
	r.mu.Lock()
	defer r.mu.Unlock()
	if r.conn == nil {
		return nil
	}
	err := r.conn.Close()
	r.conn = nil
	return err
}

// latestFromMiseRegistry resolves a bare mise registry tool through the first
// backend Deputy can model natively.
func (r *nativeResolver) latestFromMiseRegistry(ctx context.Context, name, prefix string) (string, bool, error) {
	client := r.registry()
	backends, err := client.Backends(ctx, name)
	if err != nil {
		return "", false, err
	}
	for _, full := range backends {
		backend, backendName := misecfg.SplitBackend(full)
		if runtime, ok := nativeReleaseTool(backend, backendName); ok {
			version, err := r.latestRuntime(ctx, full, runtime, prefix)
			return version, true, err
		}
		if backend == "aqua" {
			version, err := r.latestAquaPackage(ctx, full, backendName, prefix)
			if err == nil {
				return version, true, nil
			}
			if !errors.Is(err, releases.ErrNoMatch) {
				return "", true, err
			}
			continue // no GitHub version source for this aqua package; try the next backend
		}
		if owner, repo, ok := githubReleaseRepo(backend, backendName); ok {
			version, err := r.latestGitHubRelease(ctx, full, owner, repo, prefix)
			return version, true, err
		}
		if backend == "go" {
			version, err := r.latestGoTool(ctx, full, backendName, prefix)
			return version, true, err
		}
		if runtime, ok := nativeRuntimeTool(backend, backendName); ok {
			version, err := r.latestRuntime(ctx, full, runtime, prefix)
			return version, true, err
		}
		if coord, ok := nativeCoordinateForTool(full); ok {
			version, err := r.latestPackage(ctx, full, coord, prefix)
			return version, true, err
		}
	}
	return "", false, errMiseRegistryNoNativeBackend
}

// registry returns the configured mise registry client or Deputy's default
// GitHub-hosted registry client.
func (r *nativeResolver) registry() miseRegistryClient {
	if r.registryClient != nil {
		return r.registryClient
	}
	return newMiseRegistryClient()
}

// nativeCoordinate is the deps.dev coordinate for a registry-backed mise tool.
type nativeCoordinate struct {
	system       pb.System
	name         string
	semverSystem depssemver.System
}

// nativeSupportsTool reports whether Deputy has a native resolver path for
// toolKey.
func nativeSupportsTool(toolKey string) bool {
	if _, ok := nativeCoordinateForTool(toolKey); ok {
		return true
	}
	backend, name := misecfg.SplitBackend(toolKey)
	if _, ok := nativeRuntimeTool(backend, name); ok || backend == "go" && strings.TrimSpace(name) != "" {
		return true
	}
	if _, ok := nativeReleaseTool(backend, name); ok {
		return true
	}
	_, _, ok := githubReleaseRepo(backend, name)
	return ok
}

// nativeRuntimeTool maps core mise runtime aliases to Deputy's native runtime
// release clients.
//
// Native mise resolution is intentionally tiered:
//   - deps.dev package ecosystems: npm, cargo, pip/pipx, gem, dotnet.
//   - Go module tools: go:<import path>, with deps.dev module-root probing.
//   - Core runtimes and well-known asdf runtime plugins: go, node, python, and
//     terraform from their canonical release metadata sources.
//   - GitHub-release-family tools: aqua:, ubi:, and github: owner/repo specs,
//     with shared GitHub release/tag metadata. aqua: is resolved canonically
//     via its registry recipe (see [nativeResolver.latestAquaPackage]).
//
// asdf:/vfox: are deliberately NOT resolved natively: their version listing is
// defined by arbitrary plugin code (vfox plugins are Lua "Available" hooks that
// fetch and scrape upstream pages), and executing untrusted third-party plugin
// code would violate Deputy's no-code-execution invariant — unlike aqua, whose
// registry is pure declarative data Deputy can fetch and parse safely.
//
// TODO(deputy): broaden coverage where it can be done as DATA, not code — e.g.
// statically recognizing common asdf plugin shapes. Arbitrary plugin execution
// stays out of scope; an explicitly allowed host mise binary is the parity
// fallback for plugin-defined backends.
func nativeRuntimeTool(backend, name string) (string, bool) {
	tool := strings.ToLower(strings.TrimSpace(name))
	switch backend {
	case "", "core":
		return nativeRuntimeAlias(tool)
	case "asdf":
		return nativeAsdfRuntimeAlias(tool)
	default:
		return "", false
	}
}

// nativeRuntimeAlias maps mise core runtime names to Deputy runtime resolver
// identifiers.
func nativeRuntimeAlias(tool string) (string, bool) {
	switch tool {
	case "go", "golang":
		return "go", true
	case "node", "nodejs":
		return "node", true
	case "python":
		return "python", true
	case "terraform":
		return "terraform", true
	case "gcloud":
		return "gcloud", true
	default:
		return "", false
	}
}

// nativeAsdfRuntimeAlias maps common asdf plugin names to the same native
// runtime resolvers used for mise core runtimes.
func nativeAsdfRuntimeAlias(plugin string) (string, bool) {
	switch plugin {
	case "golang":
		return "go", true
	case "nodejs":
		return "node", true
	case "python":
		return "python", true
	case "terraform":
		return "terraform", true
	default:
		return "", false
	}
}

// nativeReleaseTool maps non-runtime tool aliases to native release metadata
// clients.
func nativeReleaseTool(backend, name string) (string, bool) {
	tool := strings.ToLower(strings.TrimSpace(name))
	switch backend {
	case "":
		switch tool {
		case "1password", "1password-cli", "op":
			return "1password-cli", true
		default:
			return "", false
		}
	case "aqua":
		if strings.EqualFold(strings.TrimSpace(name), "1password/cli") {
			return "1password-cli", true
		}
		return "", false
	default:
		return "", false
	}
}

// githubReleaseRepo extracts the owner/repo coordinate for repo-shaped
// GitHub-release-family backends.
func githubReleaseRepo(backend, name string) (owner, repo string, ok bool) {
	switch backend {
	case "":
		name, ok = githubReleaseRegistryAlias(name)
		if !ok {
			return "", "", false
		}
	case "aqua", "ubi", "github":
	default:
		return "", "", false
	}
	owner, repo = forge.SplitOwnerRepo(name)
	// A dot in the owner segment means an explicit non-GitHub host
	// (e.g. "gitlab.com/owner/repo"); GitHub owners never contain dots. Refuse
	// rather than resolve a non-GitHub forge against GitHub. ShouldSkip reports
	// these to the user; see [nonGitHubForge].
	if strings.Contains(owner, ".") {
		return "", "", false
	}
	return owner, repo, owner != "" && repo != ""
}

// githubReleaseRegistryAlias maps a curated subset of bare mise registry
// aliases to their first-party GitHub release repository.
func githubReleaseRegistryAlias(name string) (string, bool) {
	repo, ok := githubReleaseRegistryAliases[strings.ToLower(strings.TrimSpace(name))]
	return repo, ok
}

// githubReleaseRegistryAliases is the small offline set of bare mise registry
// names Deputy can classify without network access, mainly for pin check and
// aliases whose registry file lives under a different canonical name. Mutating
// pin operations can also read mise's registry/<tool>.toml source dynamically.
var githubReleaseRegistryAliases = map[string]string{
	"buf":           "bufbuild/buf",
	"clickhouse":    "ClickHouse/ClickHouse",
	"fd":            "sharkdp/fd",
	"gh":            "cli/cli",
	"golangci-lint": "golangci/golangci-lint",
	"helm":          "helm/helm",
	"jq":            "jqlang/jq",
	"protoc":        "protocolbuffers/protobuf",
	"rg":            "BurntSushi/ripgrep",
	"ripgrep":       "BurntSushi/ripgrep",
	"shellcheck":    "koalaman/shellcheck",
	"shfmt":         "mvdan/sh",
	"uv":            "astral-sh/uv",
	"yq":            "mikefarah/yq",
}

// nativeCoordinateForTool maps registry-backed mise tools to deps.dev package
// coordinates.
func nativeCoordinateForTool(toolKey string) (nativeCoordinate, bool) {
	backend, name := misecfg.SplitBackend(toolKey)
	name = strings.TrimSpace(name)
	if name == "" {
		return nativeCoordinate{}, false
	}
	switch backend {
	case "npm":
		return nativeCoordinate{system: pb.System_NPM, name: name, semverSystem: depssemver.NPM}, true
	case "cargo":
		return nativeCoordinate{system: pb.System_CARGO, name: name, semverSystem: depssemver.Cargo}, true
	case "pip", "pipx":
		return nativeCoordinate{system: pb.System_PYPI, name: strings.ToLower(name), semverSystem: depssemver.PyPI}, true
	case "gem":
		return nativeCoordinate{system: pb.System_RUBYGEMS, name: name, semverSystem: depssemver.RubyGems}, true
	case "dotnet":
		return nativeCoordinate{system: pb.System_NUGET, name: name, semverSystem: depssemver.NuGet}, true
	default:
		return nativeCoordinate{}, false
	}
}

// goModuleCandidates returns candidate Go module roots from longest to shortest
// for a go:<import path> tool.
func goModuleCandidates(importPath string) []string {
	importPath = strings.Trim(strings.TrimSpace(importPath), "/")
	if importPath == "" || strings.ContainsAny(importPath, " \t\r\n") {
		return nil
	}
	parts := strings.Split(importPath, "/")
	if len(parts) < 2 || parts[0] == "" || !strings.Contains(parts[0], ".") {
		return nil
	}
	minParts := 2
	switch parts[0] {
	case "github.com", "gitlab.com", "bitbucket.org":
		minParts = 3
	}
	if len(parts) < minParts {
		return nil
	}
	candidates := make([]string, 0, len(parts)-minParts+1)
	for n := len(parts); n >= minParts; n-- {
		candidates = append(candidates, strings.Join(parts[:n], "/"))
	}
	return candidates
}

// goProxyQuerySelector returns the raw Go version query to send to a Go proxy
// for branch-like selectors.
func goProxyQuerySelector(selector string) string {
	selector = strings.TrimSpace(prefixSelector(selector))
	if selector == "" || strings.EqualFold(selector, "latest") || strings.HasPrefix(selector, "sub-") {
		return ""
	}
	if strings.ContainsAny(selector, "^~*<>= ") {
		return ""
	}
	if semver.IsValid(selector) || strings.ContainsFunc(selector, unicode.IsLetter) {
		return selector
	}
	return ""
}

// goToolVersionForMise normalizes Go module tags for mise's Go backend while
// preserving pseudo-versions, which Go requires with the leading "v".
func goToolVersionForMise(version string) string {
	version = strings.TrimSpace(version)
	if module.IsPseudoVersion(version) {
		return version
	}
	return strings.TrimPrefix(version, "v")
}

// googleCloudSDKVersionFromSelector normalizes historical Google Cloud SDK
// release selectors. The SDK release train uses versions like 529.0.0, and mise
// resolves "529" to "529.0.0".
func googleCloudSDKVersionFromSelector(selector string) (string, bool) {
	selector = strings.TrimSpace(prefixSelector(selector))
	if selector == "" || strings.EqualFold(selector, "latest") {
		return "", false
	}
	components, err := numericComponents(selector)
	if err != nil || len(components) > 3 || components[0] < 100 {
		return "", false
	}
	for len(components) < 3 {
		components = append(components, 0)
	}
	return fmt.Sprintf("%d.%d.%d", components[0], components[1], components[2]), true
}

// newestVersion selects the newest deps.dev package version matching a mise
// selector, including prefix: and sub- scopes.
func newestVersion(versions []*pb.Package_Version, sys depssemver.System, prefix string) (string, error) {
	if sub, base, ok := subSelector(prefix); ok {
		baseVersion, err := newestVersion(versions, sys, base)
		if err != nil {
			return "", err
		}
		derived, err := subtractVersion(baseVersion, sub)
		if err != nil {
			return "", err
		}
		return newestVersion(versions, sys, derived)
	}
	prefix = prefixSelector(prefix)
	prefix = strings.TrimSpace(prefix)
	allowPrerelease := strings.Contains(prefix, "-")
	if prefix == "" || strings.EqualFold(prefix, "latest") {
		for _, version := range versions {
			v := versionString(version)
			if version.GetIsDefault() && usableVersion(v, allowPrerelease) {
				return v, nil
			}
		}
	}

	var best string
	for _, version := range versions {
		v := versionString(version)
		if !usableVersion(v, allowPrerelease) || !versionMatchesPrefix(v, prefix) {
			continue
		}
		if best == "" || sys.Compare(v, best) > 0 {
			best = v
		}
	}
	if best == "" {
		if prefix == "" {
			return "", fmt.Errorf("no concrete versions found")
		}
		return "", fmt.Errorf("no concrete version matching %q found", prefix)
	}
	return best, nil
}

// versionString extracts a trimmed version string from a deps.dev version
// record.
func versionString(version *pb.Package_Version) string {
	if version == nil || version.GetVersionKey() == nil {
		return ""
	}
	return strings.TrimSpace(version.GetVersionKey().GetVersion())
}

// usableVersion reports whether version is concrete enough for pinning and, by
// default, excludes prereleases.
func usableVersion(version string, allowPrerelease bool) bool {
	if !misecfg.IsConcreteVersion(version) {
		return false
	}
	return allowPrerelease || !isPrerelease(version)
}

// isPrerelease recognizes common prerelease markers across semver-like release
// streams.
func isPrerelease(version string) bool {
	v := strings.ToLower(strings.TrimPrefix(strings.TrimSpace(version), "v"))
	if i := strings.IndexByte(v, '+'); i >= 0 {
		v = v[:i]
	}
	return strings.Contains(v, "-") ||
		strings.Contains(v, ".pre") ||
		strings.Contains(v, ".rc") ||
		strings.Contains(v, ".alpha") ||
		strings.Contains(v, ".beta")
}

// versionMatchesPrefix reports whether a candidate release satisfies a fuzzy
// request, which is what narrows a release list before the newest survivor is
// pinned. An empty request and "latest" name no version and so admit every
// candidate; the version line itself is [misecfg.SelectorMatches], the one
// reading of mise's matching rule, so the release Deputy pins is the release
// mise would install.
//
// Only the prerelease boundary is local: a release list may carry qualifiers
// such as "1.22-rc1" that a request for 1.22 still selects, and filtering a
// candidate list is not the same job as deciding whether a declaration has
// gone stale.
func versionMatchesPrefix(version, prefix string) bool {
	prefix = strings.TrimSpace(prefix)
	if prefix == "" || strings.EqualFold(prefix, "latest") {
		return true
	}
	if misecfg.SelectorMatches(prefix, version) {
		return true
	}
	v := strings.TrimPrefix(strings.TrimSpace(version), "v")
	return strings.HasPrefix(v, strings.TrimPrefix(prefix, "v")+"-")
}

// newestRelease selects the newest release matching a mise selector from a
// generic release list.
func newestRelease(list []releases.Release, opts releases.SelectOptions, prefix string) (string, error) {
	if sub, base, ok := subSelector(prefix); ok {
		baseVersion, err := newestRelease(list, opts, base)
		if err != nil {
			return "", err
		}
		derived, err := subtractVersion(baseVersion, sub)
		if err != nil {
			return "", err
		}
		return newestRelease(list, opts, derived)
	}
	prefix = prefixSelector(prefix)
	if strings.EqualFold(strings.TrimSpace(prefix), "lts") {
		opts.Prefix = ""
		opts.Channel = "lts"
		return releases.Newest(list, opts)
	}
	opts.Prefix = prefix
	return releases.Newest(list, opts)
}

// runtimeSelectOptions returns release ordering and normalization rules for a
// native core runtime.
func runtimeSelectOptions(runtime string) releases.SelectOptions {
	switch runtime {
	case "go":
		return releases.SelectOptions{SemverSystem: depssemver.Go, StripPrefixes: []string{"go", "v"}}
	case "node":
		return releases.SelectOptions{SemverSystem: depssemver.NPM, StripPrefixes: []string{"v"}}
	case "python":
		return releases.SelectOptions{SemverSystem: depssemver.PyPI}
	case "terraform":
		return releases.SelectOptions{SemverSystem: depssemver.DefaultSystem}
	default:
		return releases.SelectOptions{SemverSystem: depssemver.DefaultSystem}
	}
}

// prefixSelector normalizes mise's prefix:<PREFIX> scope to the underlying
// fuzzy prefix.
func prefixSelector(selector string) string {
	selector = strings.TrimSpace(selector)
	if prefix, ok := strings.CutPrefix(selector, "prefix:"); ok {
		return strings.TrimSpace(prefix)
	}
	return selector
}

// subSelector parses mise's sub-<PARTIAL_VERSION>:<ORIG_VERSION> scope.
func subSelector(selector string) (sub, base string, ok bool) {
	selector = strings.TrimSpace(selector)
	if !strings.HasPrefix(selector, "sub-") {
		return "", "", false
	}
	rest := strings.TrimPrefix(selector, "sub-")
	sub, base, found := strings.Cut(rest, ":")
	sub = strings.TrimSpace(sub)
	base = strings.TrimSpace(base)
	if !found || sub == "" || base == "" {
		return "", "", false
	}
	return sub, base, true
}

// javaSelector describes the native Java release stream implied by a mise Java
// selector.
type javaSelector struct {
	vendor    string
	prefix    string
	feature   int
	shorthand bool
}

// nativeJavaSelector extracts the Java vendor and version prefix Deputy can
// resolve natively. Numeric selectors are Mise's default OpenJDK shorthand.
func nativeJavaSelector(selector string) (javaSelector, bool) {
	selector = strings.TrimSpace(prefixSelector(selector))
	if selector == "" {
		return javaSelector{}, false
	}
	if feature, ok := leadingJavaFeature(selector); ok {
		return javaSelector{vendor: "openjdk", prefix: selector, feature: feature, shorthand: true}, true
	}
	if strings.EqualFold(selector, "temurin") {
		return javaSelector{vendor: "temurin"}, true
	}
	if strings.EqualFold(selector, "openjdk") {
		return javaSelector{vendor: "openjdk"}, true
	}
	if vendor, rest, ok := splitJavaVendorVersion(selector); ok {
		feature, ok := leadingJavaFeature(rest)
		if !ok {
			return javaSelector{}, false
		}
		return javaSelector{vendor: vendor, prefix: rest, feature: feature}, true
	}
	return javaSelector{}, false
}

// splitJavaVendorVersion splits explicit mise Java vendor-version selectors
// such as "corretto-21" and "graalvm-community-21".
func splitJavaVendorVersion(selector string) (vendor, version string, ok bool) {
	selector = strings.TrimSpace(selector)
	for i := strings.LastIndexByte(selector, '-'); i > 0; i = strings.LastIndexByte(selector[:i], '-') {
		vendor = strings.ToLower(strings.TrimSpace(selector[:i]))
		version = strings.TrimSpace(selector[i+1:])
		if vendor == "" || version == "" {
			continue
		}
		if _, ok := leadingJavaFeature(version); ok {
			return vendor, version, true
		}
	}
	return "", "", false
}

// leadingJavaFeature returns the first numeric component of a Java version
// selector.
func leadingJavaFeature(selector string) (int, bool) {
	components, err := numericComponents(selector)
	if err != nil {
		return 0, false
	}
	return components[0], true
}

// subtractVersion subtracts a partial version from the same leading components
// of a concrete version, matching mise's sub- scope semantics.
func subtractVersion(version, sub string) (string, error) {
	components, err := numericComponents(version)
	if err != nil {
		return "", err
	}
	decrement, err := numericComponents(sub)
	if err != nil {
		return "", err
	}
	if len(decrement) > len(components) {
		return "", fmt.Errorf("cannot subtract %q from version %q", sub, version)
	}
	out := append([]int(nil), components[:len(decrement)]...)
	for i, dec := range decrement {
		out[i] -= dec
		if out[i] < 0 {
			return "", fmt.Errorf("cannot subtract %q from version %q", sub, version)
		}
	}
	parts := make([]string, len(out))
	for i, part := range out {
		parts[i] = fmt.Sprint(part)
	}
	return strings.Join(parts, "."), nil
}

// numericComponents extracts the leading numeric version components from a
// release string, ignoring common go/v prefixes and prerelease suffixes.
func numericComponents(version string) ([]int, error) {
	version = strings.TrimSpace(version)
	version = strings.TrimPrefix(strings.TrimPrefix(version, "go"), "v")
	var components []int
	for part := range strings.SplitSeq(version, ".") {
		n := 0
		digits := 0
		for _, r := range part {
			if r < '0' || r > '9' {
				break
			}
			// Guard against overflow from absurdly long numeric runs in a
			// (user-authored) selector; real version components are tiny.
			if digits >= 9 {
				return nil, fmt.Errorf("version %q has an oversized numeric component", version)
			}
			n = n*10 + int(r-'0')
			digits++
		}
		if digits == 0 {
			break
		}
		components = append(components, n)
	}
	if len(components) == 0 {
		return nil, fmt.Errorf("version %q has no numeric components", version)
	}
	return components, nil
}

// emptyReleaseClient is a defensive fallback for unsupported runtime ids.
type emptyReleaseClient struct{}

// List reports a configuration error for impossible native runtime paths.
func (emptyReleaseClient) List(context.Context) ([]releases.Release, error) {
	return nil, fmt.Errorf("release client is not configured")
}

// hostFallbackResolver composes native metadata resolution with an explicit
// host mise fallback.
type hostFallbackResolver struct {
	native Resolver
	host   Resolver
}

// newResolverWithHostFallback builds a resolver that tries native metadata
// first and uses an explicit mise executable only where fallback is allowed.
func newResolverWithHostFallback(misePath string) (Resolver, error) {
	host, err := newHostMiseResolver(misePath)
	if err != nil {
		return nil, err
	}
	return hostFallbackResolver{native: newNativeResolver(), host: host}, nil
}

// Close releases resources held by the wrapped resolvers.
func (r hostFallbackResolver) Close() error {
	return errors.Join(closeResolver(r.native), closeResolver(r.host))
}

// closeResolver closes a resolver when it holds releasable resources; resolvers
// that do not implement io.Closer are a no-op.
func closeResolver(r Resolver) error {
	if c, ok := r.(io.Closer); ok {
		return c.Close()
	}
	return nil
}

// Latest resolves with native metadata when Deputy supports the tool and only
// falls back to the host binary for unsupported tools or explicitly allowed
// native miss cases.
func (r hostFallbackResolver) Latest(ctx context.Context, toolKey, prefix string) (string, error) {
	var nativeErr error
	if nativeSupportsTool(toolKey) || canLookupMiseRegistryTool(toolKey) {
		version, err := r.native.Latest(ctx, toolKey, prefix)
		if err == nil {
			return version, nil
		}
		if !nativeErrorAllowsHostFallback(toolKey, err) {
			return "", err
		}
		nativeErr = err
	}

	version, err := r.host.Latest(ctx, toolKey, prefix)
	if err != nil {
		if nativeErr != nil {
			return "", fmt.Errorf("native resolution failed for %q (%v); host mise fallback failed: %w", toolKey, nativeErr, err)
		}
		return "", fmt.Errorf("native resolution does not support mise tool %q; host mise fallback failed: %w", toolKey, err)
	}
	return version, nil
}

// nativeErrorAllowsHostFallback reports whether a native miss is a semantic
// gap that a host mise binary may resolve, rather than a network or metadata
// error Deputy should surface.
func nativeErrorAllowsHostFallback(toolKey string, err error) bool {
	backend, name := misecfg.SplitBackend(toolKey)
	if backend == "go" && errors.Is(err, errGoModuleNotFound) {
		return true
	}
	if backend == "" && strings.EqualFold(strings.TrimSpace(name), "java") && errors.Is(err, releases.ErrNoMatch) {
		return true
	}
	if backend == "" && (errors.Is(err, errMiseRegistryToolNotFound) || errors.Is(err, errMiseRegistryNoNativeBackend)) {
		return true
	}
	_, _, githubBacked := githubReleaseRepo(backend, name)
	return githubBacked && errors.Is(err, releases.ErrNoMatch)
}

// canLookupMiseRegistryTool reports whether toolKey is a safe bare registry
// name that native resolution may look up remotely.
func canLookupMiseRegistryTool(toolKey string) bool {
	backend, name := misecfg.SplitBackend(toolKey)
	if backend != "" {
		return false
	}
	_, ok := miseRegistryToolFile(name)
	return ok
}

// hostMiseResolver resolves versions by invoking an explicitly configured mise
// executable path.
type hostMiseResolver struct {
	path string
}

// newHostMiseResolver validates an allowed host mise executable path.
func newHostMiseResolver(path string) (*hostMiseResolver, error) {
	path = strings.TrimSpace(path)
	if path == "" {
		return nil, fmt.Errorf("mise executable path is empty")
	}
	if !filepath.IsAbs(path) {
		return nil, fmt.Errorf("mise executable path must be absolute: %s", path)
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("stat mise executable: %w", err)
	}
	if info.IsDir() {
		return nil, fmt.Errorf("mise executable path is a directory: %s", path)
	}
	if runtime.GOOS != "windows" && info.Mode().Perm()&0o111 == 0 {
		return nil, fmt.Errorf("mise executable path is not executable: %s", path)
	}
	return &hostMiseResolver{path: path}, nil
}

// Latest invokes `mise latest` and returns its single concrete stdout version.
func (r *hostMiseResolver) Latest(ctx context.Context, toolKey, prefix string) (string, error) {
	arg := toolKey
	if p := strings.TrimSpace(prefix); p != "" && !strings.EqualFold(p, "latest") {
		arg = toolKey + "@" + p
	}
	var stdout, stderr bytes.Buffer
	cmd := exec.CommandContext(ctx, r.path, "latest", arg)
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	if err != nil {
		if msg := strings.TrimSpace(stderr.String()); msg != "" {
			return "", fmt.Errorf("%s latest %s: %w: %s", r.path, arg, err, msg)
		}
		if msg := strings.TrimSpace(stdout.String()); msg != "" {
			return "", fmt.Errorf("%s latest %s: %w: %s", r.path, arg, err, msg)
		}
		return "", fmt.Errorf("%s latest %s: %w", r.path, arg, err)
	}
	version, err := parseHostMiseVersion(stdout.String())
	if err != nil {
		return "", fmt.Errorf("%s latest %s: %w", r.path, arg, err)
	}
	return version, nil
}

// parseHostMiseVersion accepts exactly one non-empty concrete version line from
// host mise stdout.
func parseHostMiseVersion(output string) (string, error) {
	var version string
	for line := range strings.Lines(output) {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		if version != "" {
			return "", fmt.Errorf("returned multiple stdout lines")
		}
		version = line
	}
	if version == "" {
		return "", fmt.Errorf("returned no version")
	}
	if !misecfg.IsConcreteVersion(version) {
		return "", fmt.Errorf("returned non-concrete version %q", version)
	}
	return version, nil
}
