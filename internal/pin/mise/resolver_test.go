package mise

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	pb "deps.dev/api/v3"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/status"

	depgraph "github.com/temporalio/deputy/internal/dependency/graph"
	"github.com/temporalio/deputy/internal/releases"
	"github.com/temporalio/deputy/internal/releases/aqua"
)

type trackingResolver struct {
	version string
	err     error
	calls   int
}

func (f *trackingResolver) Latest(context.Context, string, string) (string, error) {
	f.calls++
	return f.version, f.err
}

// closingResolver is a Resolver that also records Close calls.
type closingResolver struct {
	trackingResolver
	closes   int
	closeErr error
}

func (f *closingResolver) Close() error {
	f.closes++
	return f.closeErr
}

func TestNativeResolverCloseIdempotentWithoutDial(t *testing.T) {
	r := newNativeResolver()
	// Never dialed: Close is a no-op and is safe to call repeatedly.
	if err := r.Close(); err != nil {
		t.Errorf("Close (no dial) = %v, want nil", err)
	}
	if err := r.Close(); err != nil {
		t.Errorf("second Close = %v, want nil", err)
	}
}

func TestStrategyCloseClosesResolver(t *testing.T) {
	cr := &closingResolver{}
	s := NewStrategyWithResolver(cr)
	if err := s.Close(); err != nil {
		t.Fatalf("Strategy.Close = %v", err)
	}
	if cr.closes != 1 {
		t.Errorf("resolver Close calls = %d, want 1", cr.closes)
	}
}

func TestStrategyCloseNonCloserResolver(t *testing.T) {
	// A resolver that does not implement io.Closer must not cause Close to fail.
	if err := NewStrategyWithResolver(&trackingResolver{}).Close(); err != nil {
		t.Errorf("Strategy.Close with non-closer resolver = %v, want nil", err)
	}
}

func TestHostFallbackResolverCloseClosesBoth(t *testing.T) {
	native := &closingResolver{}
	host := &closingResolver{}
	r := hostFallbackResolver{native: native, host: host}
	if err := r.Close(); err != nil {
		t.Fatalf("hostFallbackResolver.Close = %v", err)
	}
	if native.closes != 1 || host.closes != 1 {
		t.Errorf("close calls native=%d host=%d, want 1/1", native.closes, host.closes)
	}
}

type fakePackageClient struct {
	pkg      *pb.Package
	err      error
	packages map[string]*pb.Package
	errs     map[string]error
	requests []*pb.GetPackageRequest
}

func (f *fakePackageClient) GetPackage(_ context.Context, req *pb.GetPackageRequest, _ ...grpc.CallOption) (*pb.Package, error) {
	f.requests = append(f.requests, req)
	if f.packages != nil || f.errs != nil {
		name := req.GetPackageKey().GetName()
		if err := f.errs[name]; err != nil {
			return nil, err
		}
		if pkg := f.packages[name]; pkg != nil {
			return pkg, nil
		}
		return nil, status.Error(codes.NotFound, "not found")
	}
	return f.pkg, f.err
}

type fakeReleaseClient struct {
	releases []releases.Release
	err      error
	calls    int
}

func (f *fakeReleaseClient) List(context.Context) ([]releases.Release, error) {
	f.calls++
	return f.releases, f.err
}

type fakeGitHubReleaseClient struct {
	releases []releases.Release
	err      error
	calls    int
	owner    string
	repo     string
}

func (f *fakeGitHubReleaseClient) List(_ context.Context, owner, repo string) ([]releases.Release, error) {
	f.calls++
	f.owner = owner
	f.repo = repo
	return f.releases, f.err
}

type fakeGoProxyVersionClient struct {
	info       depgraph.GoModuleInfo
	err        error
	calls      int
	modulePath string
	version    string
}

func (f *fakeGoProxyVersionClient) FetchInfo(_ context.Context, modulePath, version string) (depgraph.GoModuleInfo, error) {
	f.calls++
	f.modulePath = modulePath
	f.version = version
	return f.info, f.err
}

type fakeTemurinReleaseClient struct {
	releases []releases.Release
	err      error
	calls    int
	feature  int
}

func (f *fakeTemurinReleaseClient) ListFeature(_ context.Context, feature int) ([]releases.Release, error) {
	f.calls++
	f.feature = feature
	return f.releases, f.err
}

// fakeAquaClient resolves aqua package names to canned recipes for tests,
// returning aqua.ErrNotFound for names not present in pkgs (unless err is set).
type fakeAquaClient struct {
	pkgs  map[string]*aqua.Package
	err   error
	calls int
}

func (f *fakeAquaClient) Lookup(_ context.Context, name string) (*aqua.Package, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	if p, ok := f.pkgs[name]; ok {
		return p, nil
	}
	return nil, fmt.Errorf("%w: %s", aqua.ErrNotFound, name)
}

type fakeJavaReleaseClient struct {
	releases []releases.Release
	err      error
	calls    int
}

func (f *fakeJavaReleaseClient) List(context.Context) ([]releases.Release, error) {
	f.calls++
	return f.releases, f.err
}

// fakeMiseRegistryClient returns registry backends keyed by bare tool name.
type fakeMiseRegistryClient struct {
	backends map[string][]string
	err      error
	calls    int
}

// Backends implements miseRegistryClient.
func (f *fakeMiseRegistryClient) Backends(_ context.Context, name string) ([]string, error) {
	f.calls++
	if f.err != nil {
		return nil, f.err
	}
	backends, ok := f.backends[name]
	if !ok {
		return nil, errMiseRegistryToolNotFound
	}
	return append([]string(nil), backends...), nil
}

func TestNativeResolverLatestRegistryBackend(t *testing.T) {
	client := &fakePackageClient{
		pkg: packageVersions(pb.System_NPM, "prettier",
			pkgVersion("2.8.8", false),
			pkgVersion("3.0.0-beta.1", false),
			pkgVersion("3.1.0", false),
			pkgVersion("3.3.0", false),
		),
	}
	resolver := &nativeResolver{client: client}

	got, err := resolver.Latest(t.Context(), "npm:prettier", "3")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "3.3.0" {
		t.Errorf("Latest = %q, want 3.3.0", got)
	}
	if len(client.requests) != 1 {
		t.Fatalf("got %d requests, want 1", len(client.requests))
	}
	key := client.requests[0].GetPackageKey()
	if key.GetSystem() != pb.System_NPM || key.GetName() != "prettier" {
		t.Errorf("request key = (%s, %q), want (NPM, prettier)", key.GetSystem(), key.GetName())
	}
}

func TestNewNativeResolverConfiguresRegistryClient(t *testing.T) {
	if newNativeResolver().registryClient == nil {
		t.Fatal("registryClient is nil")
	}
}

func TestNativeResolverLatestUsesDefaultVersion(t *testing.T) {
	client := &fakePackageClient{
		pkg: packageVersions(pb.System_RUBYGEMS, "rails",
			pkgVersion("7.2.2", true),
			pkgVersion("8.0.0.beta1", false),
		),
	}
	resolver := &nativeResolver{client: client}

	got, err := resolver.Latest(t.Context(), "gem:rails", "latest")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "7.2.2" {
		t.Errorf("Latest = %q, want 7.2.2", got)
	}
}

func TestNativeResolverLatestCachesSuccess(t *testing.T) {
	client := &fakeReleaseClient{
		releases: []releases.Release{
			{Version: "v22.17.1", Stable: true},
		},
	}
	resolver := &nativeResolver{nodeReleaseClient: client}

	for range 2 {
		got, err := resolver.Latest(t.Context(), "node", "22")
		if err != nil {
			t.Fatalf("Latest: %v", err)
		}
		if got != "22.17.1" {
			t.Errorf("Latest = %q, want 22.17.1", got)
		}
	}
	if client.calls != 1 {
		t.Errorf("release client calls = %d, want 1", client.calls)
	}
}

func TestNativeResolverNormalizesPyPIName(t *testing.T) {
	client := &fakePackageClient{pkg: packageVersions(pb.System_PYPI, "black", pkgVersion("25.1.0", true))}
	resolver := &nativeResolver{client: client}

	if _, err := resolver.Latest(t.Context(), "pipx:Black", "latest"); err != nil {
		t.Fatalf("Latest: %v", err)
	}
	key := client.requests[0].GetPackageKey()
	if key.GetSystem() != pb.System_PYPI || key.GetName() != "black" {
		t.Errorf("request key = (%s, %q), want (PYPI, black)", key.GetSystem(), key.GetName())
	}
}

func TestNativeResolverLatestGoRuntime(t *testing.T) {
	client := &fakeReleaseClient{
		releases: []releases.Release{
			{Version: "go1.26rc1", Stable: false},
			{Version: "go1.25.1", Stable: true},
			{Version: "go1.24.9", Stable: true},
			{Version: "go1.24.8", Stable: true},
		},
	}
	resolver := &nativeResolver{goReleaseClient: client}

	tests := []struct {
		tool   string
		prefix string
		want   string
	}{
		{tool: "go", prefix: "1.24", want: "1.24.9"},
		{tool: "golang", prefix: "latest", want: "1.25.1"},
		{tool: "core:go", prefix: "go1.24", want: "1.24.9"},
	}
	for _, tt := range tests {
		t.Run(tt.tool+"@"+tt.prefix, func(t *testing.T) {
			got, err := resolver.Latest(t.Context(), tt.tool, tt.prefix)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestTemurinJavaRuntime(t *testing.T) {
	client := &fakeTemurinReleaseClient{
		releases: []releases.Release{
			{Version: "21.0.11+10.0.LTS", Stable: true, Channel: "lts"},
			{Version: "21.0.12-beta+1", Stable: false},
			{Version: "21.0.10+7.0.LTS", Stable: true, Channel: "lts"},
		},
	}
	resolver := &nativeResolver{temurinClient: client}

	got, err := resolver.Latest(t.Context(), "java", "temurin-21")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "temurin-21.0.11+10.0.LTS" {
		t.Errorf("Latest = %q, want temurin-21.0.11+10.0.LTS", got)
	}
	if client.feature != 21 {
		t.Errorf("feature = %d, want 21", client.feature)
	}
}

func TestNativeResolverLatestTemurinJavaRuntimeLatestVendor(t *testing.T) {
	client := &fakeTemurinReleaseClient{
		releases: []releases.Release{
			{Version: "26.0.1+8", Stable: true},
			{Version: "25.0.1+8", Stable: true},
		},
	}
	resolver := &nativeResolver{temurinClient: client}

	got, err := resolver.Latest(t.Context(), "java", "temurin")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "temurin-26.0.1+8" {
		t.Errorf("Latest = %q, want temurin-26.0.1+8", got)
	}
	if client.feature != 0 {
		t.Errorf("feature = %d, want 0", client.feature)
	}
}

func TestNativeResolverLatestOpenJDKJavaRuntime(t *testing.T) {
	client := &fakeJavaReleaseClient{
		releases: []releases.Release{
			{Version: "21.0.2", Stable: true},
			{Version: "21.0.1", Stable: true},
			{Version: "22.0.0-ea", Stable: false},
		},
	}
	resolver := &nativeResolver{openJDKClient: client}

	tests := []struct {
		name   string
		prefix string
		want   string
	}{
		{name: "java", prefix: "21", want: "21.0.2"},
		{name: "java", prefix: "openjdk-21", want: "openjdk-21.0.2"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got, err := resolver.Latest(t.Context(), tt.name, tt.prefix)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
	if client.calls != len(tests) {
		t.Errorf("calls = %d, want %d", client.calls, len(tests))
	}
}

func TestNativeResolverLatestExplicitJavaVendorRuntime(t *testing.T) {
	client := &fakeJavaReleaseClient{
		releases: []releases.Release{
			{Version: "21.0.11.10.1", Stable: true},
			{Version: "21.0.10.9.1", Stable: true},
			{Version: "22.0.0-ea", Stable: false},
		},
	}
	resolver := &nativeResolver{javaClients: map[string]javaReleaseClient{
		"corretto": client,
	}}

	got, err := resolver.Latest(t.Context(), "java", "corretto-21")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "corretto-21.0.11.10.1" {
		t.Errorf("Latest = %q, want corretto-21.0.11.10.1", got)
	}
	if client.calls != 1 {
		t.Errorf("calls = %d, want 1", client.calls)
	}
}

func TestNativeResolverLatestCoreRuntime(t *testing.T) {
	resolver := &nativeResolver{
		goReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{
				{Version: "go1.25.1", Stable: true},
				{Version: "go1.24.9", Stable: true},
			},
		},
		nodeReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{
				{Version: "v24.1.0", Stable: true},
				{Version: "v22.17.1", Stable: true, Channel: "lts"},
				{Version: "v22.16.0", Stable: true, Channel: "lts"},
				{Version: "v20.20.2", Stable: true, Channel: "lts"},
			},
		},
		pythonReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{
				{Version: "3.14.2", Stable: true},
				{Version: "3.13.7", Stable: true},
				{Version: "3.12.11", Stable: true},
			},
		},
		tfReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{
				{Version: "1.14.1", Stable: true},
				{Version: "1.13.5", Stable: true},
				{Version: "1.15.0-beta1", Stable: false},
			},
		},
		gcloudReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{
				{Version: "571.0.0", Stable: true},
			},
		},
	}

	tests := []struct {
		tool   string
		prefix string
		want   string
	}{
		{tool: "node", prefix: "22", want: "22.17.1"},
		{tool: "nodejs", prefix: "lts", want: "22.17.1"},
		{tool: "core:node", prefix: "sub-2:lts", want: "20.20.2"},
		{tool: "python", prefix: "sub-0.1:latest", want: "3.13.7"},
		{tool: "terraform", prefix: "1", want: "1.14.1"},
		{tool: "gcloud", prefix: "latest", want: "571.0.0"},
		{tool: "gcloud", prefix: "529", want: "529.0.0"},
		{tool: "asdf:nodejs", prefix: "lts", want: "22.17.1"},
		{tool: "asdf:python", prefix: "3.13", want: "3.13.7"},
		{tool: "asdf:golang", prefix: "1.24", want: "1.24.9"},
		{tool: "asdf:terraform", prefix: "1", want: "1.14.1"},
	}
	for _, tt := range tests {
		t.Run(tt.tool+"@"+tt.prefix, func(t *testing.T) {
			got, err := resolver.Latest(t.Context(), tt.tool, tt.prefix)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestOnePasswordCLI(t *testing.T) {
	client := &fakeReleaseClient{
		releases: []releases.Release{
			{Version: "2.34.0", Stable: true},
		},
	}
	resolver := &nativeResolver{onePasswordClient: client}

	tests := []struct {
		tool string
		want string
	}{
		{tool: "op", want: "2.34.0"},
		{tool: "1password", want: "2.34.0"},
		{tool: "aqua:1password/cli", want: "2.34.0"},
	}
	for _, tt := range tests {
		t.Run(tt.tool, func(t *testing.T) {
			got, err := resolver.Latest(t.Context(), tt.tool, "2")
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestGoRuntimeNoMatch(t *testing.T) {
	resolver := &nativeResolver{
		goReleaseClient: &fakeReleaseClient{
			releases: []releases.Release{{Version: "go1.25.1", Stable: true}},
		},
	}

	_, err := resolver.Latest(t.Context(), "go", "1.24")
	if !errors.Is(err, errGoRuntimeVersionNotFound) {
		t.Fatalf("Latest error = %v, want %v", err, errGoRuntimeVersionNotFound)
	}
}

func TestNativeResolverLatestRegistryScopes(t *testing.T) {
	client := &fakePackageClient{
		pkg: packageVersions(pb.System_NPM, "prettier",
			pkgVersion("2.8.8", false),
			pkgVersion("3.0.0", false),
			pkgVersion("3.1.1", false),
			pkgVersion("4.0.0", true),
		),
	}
	resolver := &nativeResolver{client: client}

	tests := []struct {
		prefix string
		want   string
	}{
		{prefix: "prefix:3", want: "3.1.1"},
		{prefix: "sub-1:latest", want: "3.1.1"},
	}
	for _, tt := range tests {
		t.Run(tt.prefix, func(t *testing.T) {
			got, err := resolver.Latest(t.Context(), "npm:prettier", tt.prefix)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestGoToolProbesModuleCandidates(t *testing.T) {
	client := &fakePackageClient{
		packages: map[string]*pb.Package{
			"golang.org/x/tools": packageVersions(pb.System_GO, "golang.org/x/tools",
				pkgVersion("v0.35.0", false),
				pkgVersion("v0.36.0", true),
			),
		},
	}
	resolver := &nativeResolver{client: client}

	got, err := resolver.Latest(t.Context(), "go:golang.org/x/tools/cmd/goimports", "0")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "0.36.0" {
		t.Errorf("Latest = %q, want 0.36.0", got)
	}
	wantRequests := []string{
		"golang.org/x/tools/cmd/goimports",
		"golang.org/x/tools/cmd",
		"golang.org/x/tools",
	}
	if gotRequests := requestNames(client.requests); !slices.Equal(gotRequests, wantRequests) {
		t.Errorf("request names = %v, want %v", gotRequests, wantRequests)
	}
}

func TestNativeResolverLatestGoToolResolvesBranchViaGoProxy(t *testing.T) {
	client := &fakePackageClient{
		packages: map[string]*pb.Package{
			"sigs.k8s.io/controller-runtime/tools/setup-envtest": packageVersions(pb.System_GO, "sigs.k8s.io/controller-runtime/tools/setup-envtest",
				pkgVersion("v0.24.1", true),
			),
		},
	}
	proxy := &fakeGoProxyVersionClient{
		info: depgraph.GoModuleInfo{Version: "v0.0.0-20250308055145-5fe7bb3edc86"},
	}
	resolver := &nativeResolver{
		client:        client,
		goProxyClient: proxy,
	}

	got, err := resolver.Latest(t.Context(), "go:sigs.k8s.io/controller-runtime/tools/setup-envtest", "release-0.19")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "v0.0.0-20250308055145-5fe7bb3edc86" {
		t.Errorf("Latest = %q, want v0.0.0-20250308055145-5fe7bb3edc86", got)
	}
	if proxy.modulePath != "sigs.k8s.io/controller-runtime/tools/setup-envtest" || proxy.version != "release-0.19" {
		t.Errorf("proxy query = %s@%s, want sigs.k8s.io/controller-runtime/tools/setup-envtest@release-0.19", proxy.modulePath, proxy.version)
	}
}

func TestNativeResolverLatestGitHubReleaseFamily(t *testing.T) {
	client := &fakeGitHubReleaseClient{
		releases: []releases.Release{
			{Version: "v1.23.0", Stable: true},
			{Version: "v1.23.1", Stable: true},
			{Version: "v1.24.0-rc.1", Stable: false},
		},
	}
	resolver := &nativeResolver{githubReleaseClient: client}

	got, err := resolver.Latest(t.Context(), "github:cludden/protoc-gen-go-temporal", "1.23")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.23.1" {
		t.Errorf("Latest = %q, want 1.23.1", got)
	}
	if client.owner != "cludden" || client.repo != "protoc-gen-go-temporal" {
		t.Errorf("repo = %s/%s, want cludden/protoc-gen-go-temporal", client.owner, client.repo)
	}
}

func TestNativeResolverLatestAquaUsesRepoPrefixOnly(t *testing.T) {
	client := &fakeGitHubReleaseClient{
		releases: []releases.Release{
			{Version: "v33.0", Stable: true},
			{Version: "v33.1", Stable: true},
		},
	}
	resolver := &nativeResolver{githubReleaseClient: client}

	got, err := resolver.Latest(t.Context(), "aqua:protocolbuffers/protobuf/protoc", "33")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "33.1" {
		t.Errorf("Latest = %q, want 33.1", got)
	}
	if client.owner != "protocolbuffers" || client.repo != "protobuf" {
		t.Errorf("repo = %s/%s, want protocolbuffers/protobuf", client.owner, client.repo)
	}
}

func TestNativeResolverLatestAquaUsesRecipeRepo(t *testing.T) {
	// The aqua recipe's repo — not the spec name — is the version source.
	gh := &fakeGitHubReleaseClient{releases: []releases.Release{
		{Version: "v2.1.0", Stable: true},
		{Version: "v2.2.0", Stable: true},
	}}
	resolver := &nativeResolver{
		githubReleaseClient: gh,
		aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
			"some/alias": {Type: "github_release", RepoOwner: "real-owner", RepoName: "real-tool"},
		}},
	}

	got, err := resolver.Latest(t.Context(), "aqua:some/alias", "2")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "2.2.0" {
		t.Errorf("Latest = %q, want 2.2.0", got)
	}
	if gh.owner != "real-owner" || gh.repo != "real-tool" {
		t.Errorf("listed %s/%s, want real-owner/real-tool (recipe repo, not spec name)", gh.owner, gh.repo)
	}
}

func TestNativeResolverLatestAquaVersionPrefix(t *testing.T) {
	gh := &fakeGitHubReleaseClient{releases: []releases.Release{
		{Version: "cli-1.4.0", Stable: true},
		{Version: "cli-1.5.0", Stable: true},
	}}
	resolver := &nativeResolver{
		githubReleaseClient: gh,
		aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
			"acme/tool": {Type: "github_release", RepoOwner: "acme", RepoName: "tool", VersionPrefix: "cli-"},
		}},
	}

	got, err := resolver.Latest(t.Context(), "aqua:acme/tool", "1")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.5.0" {
		t.Errorf("Latest = %q, want 1.5.0 (cli- prefix stripped)", got)
	}
}

func TestNativeResolverLatestAquaNoGitHubSource(t *testing.T) {
	// A recipe with no repo (e.g. type: http like 1password/cli) has no
	// enumerable version source: resolution returns ErrNoMatch so a host
	// fallback can take over.
	resolver := &nativeResolver{
		aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
			"vendor/tool": {Type: "http"},
		}},
	}

	if _, err := resolver.Latest(t.Context(), "aqua:vendor/tool", "1"); !errors.Is(err, releases.ErrNoMatch) {
		t.Errorf("err = %v, want releases.ErrNoMatch", err)
	}
}

func TestNativeResolverLatestAquaRegistryErrorFallsBack(t *testing.T) {
	// When the recipe can't be read, resolution degrades to the owner/repo
	// heuristic (the spec name is treated as the GitHub repo).
	gh := &fakeGitHubReleaseClient{releases: []releases.Release{
		{Version: "v3.0.0", Stable: true},
	}}
	resolver := &nativeResolver{
		githubReleaseClient: gh,
		aquaClient:          &fakeAquaClient{err: errors.New("registry unreachable")},
	}

	got, err := resolver.Latest(t.Context(), "aqua:acme/widget", "3")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "3.0.0" {
		t.Errorf("Latest = %q, want 3.0.0", got)
	}
	if gh.owner != "acme" || gh.repo != "widget" {
		t.Errorf("listed %s/%s, want acme/widget (heuristic fallback)", gh.owner, gh.repo)
	}
}

func TestNativeResolverLatestGitHubReleaseTagPrefixes(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		prefix   string
		releases []releases.Release
		want     string
	}{
		{
			name:   "maven",
			tool:   "aqua:apache/maven",
			prefix: "3",
			releases: []releases.Release{
				{Version: "maven-3.9.16", Stable: true},
				{Version: "maven-4.0.0-rc-5", Stable: true},
			},
			want: "3.9.16",
		},
		{
			name:   "yarn",
			tool:   "aqua:yarnpkg/berry",
			prefix: "4",
			releases: []releases.Release{
				{Version: "@yarnpkg/types/4.0.1", Stable: true},
				{Version: "@yarnpkg/cli/4.9.4", Stable: true},
				{Version: "@yarnpkg/cli/4.10.0-rc.1", Stable: true},
			},
			want: "4.9.4",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			client := &fakeGitHubReleaseClient{releases: tt.releases}
			resolver := &nativeResolver{
				githubReleaseClient: client,
				// Inject canonical aqua recipes so resolution is hermetic
				// (no real aqua-registry network call).
				aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
					"apache/maven":  {Type: "github_release", RepoOwner: "apache", RepoName: "maven"},
					"yarnpkg/berry": {Type: "github_release", RepoOwner: "yarnpkg", RepoName: "berry"},
				}},
			}

			got, err := resolver.Latest(t.Context(), tt.tool, tt.prefix)
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != tt.want {
				t.Errorf("Latest = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestClickHouseStableRelease(t *testing.T) {
	client := &fakeGitHubReleaseClient{
		releases: []releases.Release{
			{Version: "v25.12.11.4-stable", Stable: true},
			{Version: "v25.12.12.1-new", Stable: true},
			{Version: "v25.10.1.1-stable", Stable: true},
			{Version: "v26.1.1.1-stable", Stable: true},
		},
	}
	resolver := &nativeResolver{githubReleaseClient: client}

	got, err := resolver.Latest(t.Context(), "github:ClickHouse/ClickHouse", "25")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "25.12.11.4-stable" {
		t.Errorf("Latest = %q, want 25.12.11.4-stable", got)
	}
}

func TestGitHubReleaseTagQueryPrefix(t *testing.T) {
	tests := []struct {
		owner  string
		repo   string
		prefix string
		want   string
	}{
		{owner: "apache", repo: "maven", prefix: "3", want: "maven-3"},
		{owner: "yarnpkg", repo: "berry", prefix: "4", want: "@yarnpkg/cli/4"},
		{owner: "ClickHouse", repo: "ClickHouse", prefix: "25", want: "v25"},
		{owner: "cli", repo: "cli", prefix: "2"},
		{owner: "apache", repo: "maven", prefix: "latest"},
	}
	for _, tt := range tests {
		t.Run(tt.owner+"/"+tt.repo+"@"+tt.prefix, func(t *testing.T) {
			if got := githubReleaseTagQueryPrefix(tt.owner, tt.repo, tt.prefix); got != tt.want {
				t.Errorf("githubReleaseTagQueryPrefix = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeResolverLatestBareGitHubReleaseAlias(t *testing.T) {
	client := &fakeGitHubReleaseClient{
		releases: []releases.Release{
			{Version: "v33.0", Stable: true},
			{Version: "v33.1", Stable: true},
			{Version: "v34.0-rc.1", Stable: false},
		},
	}
	resolver := &nativeResolver{
		githubReleaseClient: client,
		aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
			"protocolbuffers/protobuf": {Type: "github_release", RepoOwner: "protocolbuffers", RepoName: "protobuf"},
		}},
	}

	got, err := resolver.Latest(t.Context(), "protoc", "33")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "33.1" {
		t.Errorf("Latest = %q, want 33.1", got)
	}
	if client.owner != "protocolbuffers" || client.repo != "protobuf" {
		t.Errorf("repo = %s/%s, want protocolbuffers/protobuf", client.owner, client.repo)
	}
}

// TestNativeResolverLatestJqPrefixedTagsRegression is a regression test for a
// real bug: jq's GitHub tags are prefixed ("jq-1.8.1") and include release
// candidates glued to the version ("jq-1.8.2rc1") plus a stray legacy tag
// ("1.6rc2"). Resolving a bare "jq" must (1) apply the aqua recipe's "jq-"
// version_prefix so the real releases match the major channel, and (2) exclude
// the rc tags — selecting 1.8.1, never a downgrade to an rc or a stray tag.
func TestNativeResolverLatestJqPrefixedTagsRegression(t *testing.T) {
	gh := &fakeGitHubReleaseClient{releases: []releases.Release{
		// Tags are reported Stable=true by the GitHub client; the rc's must be
		// filtered by prerelease detection, not the stable flag.
		{Version: "jq-1.8.2rc1", Stable: true},
		{Version: "jq-1.8.1", Stable: true},
		{Version: "jq-1.8.0", Stable: true},
		{Version: "jq-1.7.1", Stable: true},
		{Version: "jq-1.7rc2", Stable: true},
		{Version: "1.6rc2", Stable: true},
	}}
	resolver := &nativeResolver{
		githubReleaseClient: gh,
		aquaClient: &fakeAquaClient{pkgs: map[string]*aqua.Package{
			"jqlang/jq": {Type: "github_release", RepoOwner: "jqlang", RepoName: "jq", VersionPrefix: "jq-"},
		}},
	}

	got, err := resolver.Latest(t.Context(), "jq", "1")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.8.1" {
		t.Errorf("Latest(jq, 1) = %q, want 1.8.1 (no rc, no legacy-tag downgrade)", got)
	}
	if gh.owner != "jqlang" || gh.repo != "jq" {
		t.Errorf("listed %s/%s, want jqlang/jq", gh.owner, gh.repo)
	}
}

func TestNativeResolverLatestBareToolFromMiseRegistry(t *testing.T) {
	registry := &fakeMiseRegistryClient{backends: map[string][]string{
		"custom-tool": {
			"asdf:example/asdf-custom-tool",
			"aqua:owner/project/custom-tool",
		},
	}}
	client := &fakeGitHubReleaseClient{
		releases: []releases.Release{
			{Version: "v1.2.0", Stable: true},
			{Version: "v1.2.1", Stable: true},
			{Version: "v1.3.0-beta.1", Stable: false},
		},
	}
	resolver := &nativeResolver{
		githubReleaseClient: client,
		registryClient:      registry,
	}

	got, err := resolver.Latest(t.Context(), "custom-tool", "1.2")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.2.1" {
		t.Errorf("Latest = %q, want 1.2.1", got)
	}
	if registry.calls != 1 {
		t.Errorf("registry calls = %d, want 1", registry.calls)
	}
	if client.owner != "owner" || client.repo != "project" {
		t.Errorf("repo = %s/%s, want owner/project", client.owner, client.repo)
	}
}

func TestNativeResolverLatestBareToolFromMiseRegistryPackageBackend(t *testing.T) {
	registry := &fakeMiseRegistryClient{backends: map[string][]string{
		"poetry": {
			"vfox:mise-plugins/vfox-poetry",
			"pipx:poetry",
		},
	}}
	client := &fakePackageClient{
		pkg: packageVersions(pb.System_PYPI, "poetry",
			pkgVersion("1.8.4", false),
			pkgVersion("1.8.5", true),
			pkgVersion("2.0.0", true),
		),
	}
	resolver := &nativeResolver{client: client, registryClient: registry}

	got, err := resolver.Latest(t.Context(), "poetry", "1.8")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.8.5" {
		t.Errorf("Latest = %q, want 1.8.5", got)
	}
	if registry.calls != 1 {
		t.Errorf("registry calls = %d, want 1", registry.calls)
	}
	key := client.requests[0].GetPackageKey()
	if key.GetSystem() != pb.System_PYPI || key.GetName() != "poetry" {
		t.Errorf("request key = (%s, %q), want (PYPI, poetry)", key.GetSystem(), key.GetName())
	}
}

func TestNativeResolverLatestBareToolFromMiseRegistryNoNativeBackend(t *testing.T) {
	resolver := &nativeResolver{registryClient: &fakeMiseRegistryClient{backends: map[string][]string{
		"java": {"core:java"},
	}}}

	_, err := resolver.Latest(t.Context(), "java", "zulu")
	if !errors.Is(err, errMiseRegistryNoNativeBackend) {
		t.Fatalf("Latest error = %v, want %v", err, errMiseRegistryNoNativeBackend)
	}
}

func TestNativeResolverUnsupportedTool(t *testing.T) {
	resolver := &nativeResolver{client: &fakePackageClient{}}
	if _, err := resolver.Latest(t.Context(), "asdf:custom-tool", "20"); err == nil {
		t.Fatal("Latest returned nil error, want unsupported-tool error")
	}
}

func TestNativeSupportsToolCoverage(t *testing.T) {
	supported := []string{
		"npm:prettier",
		"cargo:ripgrep",
		"pip:black",
		"pipx:black",
		"gem:rails",
		"dotnet:dotnet-ef",
		"op",
		"1password",
		"go",
		"golang",
		"core:go",
		"node",
		"nodejs",
		"core:node",
		"python",
		"terraform",
		"gcloud",
		"asdf:nodejs",
		"asdf:python",
		"asdf:golang",
		"asdf:terraform",
		"go:golang.org/x/tools/cmd/goimports",
		"aqua:1password/cli",
		"aqua:protocolbuffers/protobuf/protoc",
		"ubi:BurntSushi/ripgrep",
		"github:cli/cli",
		"buf",
		"clickhouse",
		"fd",
		"gh",
		"golangci-lint",
		"helm",
		"jq",
		"protoc",
		"rg",
		"ripgrep",
		"shellcheck",
		"shfmt",
		"uv",
		"yq",
	}
	for _, tool := range supported {
		t.Run(tool, func(t *testing.T) {
			if !nativeSupportsTool(tool) {
				t.Fatalf("nativeSupportsTool(%q) = false, want true", tool)
			}
		})
	}

	unsupported := []string{
		"aqua:bad",
		"ubi:bad",
		"asdf:custom-tool",
		"vfox:nodejs",
		"spm:swift-format",
		"github:bad",
		"core:protoc",
		"http:https://example.com/tool.tar.gz",
	}
	for _, tool := range unsupported {
		t.Run(tool, func(t *testing.T) {
			if nativeSupportsTool(tool) {
				t.Fatalf("nativeSupportsTool(%q) = true, want false", tool)
			}
		})
	}
}

func TestNativeCoordinateForToolBackendCoverage(t *testing.T) {
	supported := []struct {
		tool   string
		system pb.System
	}{
		{tool: "npm:prettier", system: pb.System_NPM},
		{tool: "cargo:ripgrep", system: pb.System_CARGO},
		{tool: "pip:black", system: pb.System_PYPI},
		{tool: "pipx:black", system: pb.System_PYPI},
		{tool: "gem:rails", system: pb.System_RUBYGEMS},
		{tool: "dotnet:dotnet-ef", system: pb.System_NUGET},
	}
	for _, tt := range supported {
		t.Run(tt.tool, func(t *testing.T) {
			got, ok := nativeCoordinateForTool(tt.tool)
			if !ok {
				t.Fatalf("nativeCoordinateForTool(%q) unsupported, want supported", tt.tool)
			}
			if got.system != tt.system {
				t.Errorf("system = %s, want %s", got.system, tt.system)
			}
		})
	}

	unsupported := []string{
		"node",
		"python",
		"asdf:nodejs",
		"vfox:nodejs",
		"spm:swift-format",
		"http:https://example.com/tool.tar.gz",
	}
	for _, tool := range unsupported {
		t.Run(tool, func(t *testing.T) {
			if got, ok := nativeCoordinateForTool(tool); ok {
				t.Fatalf("nativeCoordinateForTool(%q) = %+v, want unsupported", tool, got)
			}
		})
	}
}

func TestGoModuleCandidates(t *testing.T) {
	tests := []struct {
		importPath string
		want       []string
	}{
		{
			importPath: "golang.org/x/tools/cmd/goimports",
			want: []string{
				"golang.org/x/tools/cmd/goimports",
				"golang.org/x/tools/cmd",
				"golang.org/x/tools",
				"golang.org/x",
			},
		},
		{
			importPath: "github.com/acme/tool/v2/cmd/tool",
			want: []string{
				"github.com/acme/tool/v2/cmd/tool",
				"github.com/acme/tool/v2/cmd",
				"github.com/acme/tool/v2",
				"github.com/acme/tool",
			},
		},
		{importPath: "goimports", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.importPath, func(t *testing.T) {
			got := goModuleCandidates(tt.importPath)
			if !slices.Equal(got, tt.want) {
				t.Errorf("goModuleCandidates(%q) = %v, want %v", tt.importPath, got, tt.want)
			}
		})
	}
}

func TestGoProxyQuerySelector(t *testing.T) {
	tests := []struct {
		selector string
		want     string
	}{
		{selector: "release-0.19", want: "release-0.19"},
		{selector: "main", want: "main"},
		{selector: "v0.0.0-20250308055145-5fe7bb3edc86", want: "v0.0.0-20250308055145-5fe7bb3edc86"},
		{selector: "1.13"},
		{selector: "latest"},
		{selector: "sub-1:latest"},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			if got := goProxyQuerySelector(tt.selector); got != tt.want {
				t.Errorf("goProxyQuerySelector(%q) = %q, want %q", tt.selector, got, tt.want)
			}
		})
	}
}

func TestGoogleCloudSDKVersionFromSelector(t *testing.T) {
	tests := []struct {
		selector string
		want     string
		wantOK   bool
	}{
		{selector: "529", want: "529.0.0", wantOK: true},
		{selector: "529.1", want: "529.1.0", wantOK: true},
		{selector: "529.1.2", want: "529.1.2", wantOK: true},
		{selector: "2"},
		{selector: "latest"},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got, ok := googleCloudSDKVersionFromSelector(tt.selector)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("googleCloudSDKVersionFromSelector(%q) = (%q, %t), want (%q, %t)", tt.selector, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

func TestNativeResolverNoMatchingVersion(t *testing.T) {
	client := &fakePackageClient{pkg: packageVersions(pb.System_CARGO, "ripgrep", pkgVersion("13.0.0", false))}
	resolver := &nativeResolver{client: client}

	if _, err := resolver.Latest(t.Context(), "cargo:ripgrep", "14"); err == nil {
		t.Fatal("Latest returned nil error, want no-match error")
	}
}

func TestHostMiseResolverRequiresAbsolutePath(t *testing.T) {
	if _, err := newHostMiseResolver("mise"); err == nil {
		t.Fatal("newHostMiseResolver returned nil error, want absolute-path error")
	}
}

func TestResolverWithHostFallback(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX shell script")
	}
	dir := t.TempDir()
	misePath := filepath.Join(dir, "mise")
	if err := os.WriteFile(misePath, []byte("#!/bin/sh\nprintf '20.11.0\\n'\n"), 0o755); err != nil {
		t.Fatalf("write fake mise: %v", err)
	}
	resolver, err := newResolverWithHostFallback(misePath)
	if err != nil {
		t.Fatalf("newResolverWithHostFallback: %v", err)
	}

	got, err := resolver.Latest(t.Context(), "asdf:custom-tool", "20")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "20.11.0" {
		t.Errorf("Latest = %q, want 20.11.0", got)
	}
}

func TestResolverWithHostFallbackKeepsNativeAuthoritative(t *testing.T) {
	native := &trackingResolver{version: "3.3.0"}
	host := &trackingResolver{version: "9.9.9"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "npm:prettier", "3")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "3.3.0" {
		t.Errorf("Latest = %q, want native resolver result 3.3.0", got)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 0 {
		t.Errorf("host calls = %d, want 0", host.calls)
	}
}

func TestResolverWithHostFallbackDoesNotMaskNativeErrors(t *testing.T) {
	nativeErr := errors.New("native metadata unavailable")
	native := &trackingResolver{err: nativeErr}
	host := &trackingResolver{version: "9.9.9"}
	resolver := hostFallbackResolver{native: native, host: host}

	_, err := resolver.Latest(t.Context(), "npm:prettier", "3")
	if !errors.Is(err, nativeErr) {
		t.Fatalf("Latest error = %v, want native error %v", err, nativeErr)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 0 {
		t.Errorf("host calls = %d, want 0", host.calls)
	}
}

func TestResolverWithHostFallbackUsesHostForNonNativeBackends(t *testing.T) {
	tools := []string{
		"aqua:bad",
		"ubi:bad",
		"asdf:custom-tool",
		"vfox:nodejs",
		"spm:swift-format",
		"github:bad",
		"http:https://example.com/tool.tar.gz",
	}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			native := &trackingResolver{version: "native"}
			host := &trackingResolver{version: "1.2.3"}
			resolver := hostFallbackResolver{native: native, host: host}

			got, err := resolver.Latest(t.Context(), tool, "1")
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != "1.2.3" {
				t.Errorf("Latest = %q, want host result 1.2.3", got)
			}
			if native.calls != 0 {
				t.Errorf("native calls = %d, want 0", native.calls)
			}
			if host.calls != 1 {
				t.Errorf("host calls = %d, want 1", host.calls)
			}
		})
	}
}

func TestResolverWithHostFallbackKeepsGoNativeAuthoritative(t *testing.T) {
	tools := []string{
		"go",
		"golang",
		"core:go",
		"node",
		"nodejs",
		"core:node",
		"python",
		"terraform",
		"gcloud",
		"op",
		"aqua:1password/cli",
		"asdf:nodejs",
		"asdf:python",
		"asdf:golang",
		"asdf:terraform",
		"go:golang.org/x/tools/cmd/goimports",
		"aqua:protocolbuffers/protobuf/protoc",
		"ubi:BurntSushi/ripgrep",
		"github:cli/cli",
		"buf",
		"clickhouse",
		"fd",
		"gh",
		"golangci-lint",
		"helm",
		"jq",
		"protoc",
		"rg",
		"ripgrep",
		"shellcheck",
		"shfmt",
		"uv",
		"yq",
	}
	for _, tool := range tools {
		t.Run(tool, func(t *testing.T) {
			native := &trackingResolver{version: "native"}
			host := &trackingResolver{version: "host"}
			resolver := hostFallbackResolver{native: native, host: host}

			got, err := resolver.Latest(t.Context(), tool, "1")
			if err != nil {
				t.Fatalf("Latest: %v", err)
			}
			if got != "native" {
				t.Errorf("Latest = %q, want native", got)
			}
			if native.calls != 1 {
				t.Errorf("native calls = %d, want 1", native.calls)
			}
			if host.calls != 0 {
				t.Errorf("host calls = %d, want 0", host.calls)
			}
		})
	}
}

func TestResolverWithHostFallbackTriesNativeMiseRegistry(t *testing.T) {
	native := &nativeResolver{
		githubReleaseClient: &fakeGitHubReleaseClient{releases: []releases.Release{
			{Version: "v1.2.1", Stable: true},
		}},
		registryClient: &fakeMiseRegistryClient{backends: map[string][]string{
			"custom-tool": {"aqua:owner/project/custom-tool"},
		}},
	}
	host := &trackingResolver{version: "host"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "custom-tool", "1.2")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.2.1" {
		t.Errorf("Latest = %q, want 1.2.1", got)
	}
	if host.calls != 0 {
		t.Errorf("host calls = %d, want 0", host.calls)
	}
}

func TestResolverWithHostFallbackUsesHostForNonNativeRegistryEntry(t *testing.T) {
	native := &nativeResolver{registryClient: &fakeMiseRegistryClient{backends: map[string][]string{
		"java": {"core:java"},
	}}}
	host := &trackingResolver{version: "temurin-21.0.11+10.0.LTS"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "java", "zulu")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "temurin-21.0.11+10.0.LTS" {
		t.Errorf("Latest = %q, want temurin-21.0.11+10.0.LTS", got)
	}
	if host.calls != 1 {
		t.Errorf("host calls = %d, want 1", host.calls)
	}
}

func TestResolverWithHostFallbackCanHandleTemurinNoMatch(t *testing.T) {
	native := &trackingResolver{err: releases.ErrNoMatch}
	host := &trackingResolver{version: "temurin-21.0.11+10.0.LTS"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "java", "temurin-21")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "temurin-21.0.11+10.0.LTS" {
		t.Errorf("Latest = %q, want temurin-21.0.11+10.0.LTS", got)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 1 {
		t.Errorf("host calls = %d, want 1", host.calls)
	}
}

func TestVersionSelectors(t *testing.T) {
	tests := []struct {
		version string
		sub     string
		want    string
	}{
		{version: "22.17.1", sub: "2", want: "20"},
		{version: "3.14.2", sub: "0.1", want: "3.13"},
		{version: "go1.25.4", sub: "0.1", want: "1.24"},
	}
	for _, tt := range tests {
		t.Run(tt.version+"-"+tt.sub, func(t *testing.T) {
			got, err := subtractVersion(tt.version, tt.sub)
			if err != nil {
				t.Fatalf("subtractVersion: %v", err)
			}
			if got != tt.want {
				t.Errorf("subtractVersion = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestNativeJavaSelector(t *testing.T) {
	tests := []struct {
		selector    string
		wantVendor  string
		wantPrefix  string
		wantFeature int
		wantShort   bool
		wantOK      bool
	}{
		{selector: "21", wantVendor: "openjdk", wantPrefix: "21", wantFeature: 21, wantShort: true, wantOK: true},
		{selector: "21.0.2", wantVendor: "openjdk", wantPrefix: "21.0.2", wantFeature: 21, wantShort: true, wantOK: true},
		{selector: "openjdk-21", wantVendor: "openjdk", wantPrefix: "21", wantFeature: 21, wantOK: true},
		{selector: "temurin", wantVendor: "temurin", wantPrefix: "", wantFeature: 0, wantOK: true},
		{selector: "temurin-21", wantVendor: "temurin", wantPrefix: "21", wantFeature: 21, wantOK: true},
		{selector: "corretto-21", wantVendor: "corretto", wantPrefix: "21", wantFeature: 21, wantOK: true},
		{selector: "graalvm-community-21", wantVendor: "graalvm-community", wantPrefix: "21", wantFeature: 21, wantOK: true},
		{selector: "prefix:temurin-17.0", wantVendor: "temurin", wantPrefix: "17.0", wantFeature: 17, wantOK: true},
		{selector: "zulu", wantOK: false},
	}
	for _, tt := range tests {
		t.Run(tt.selector, func(t *testing.T) {
			got, gotOK := nativeJavaSelector(tt.selector)
			if got.vendor != tt.wantVendor ||
				got.prefix != tt.wantPrefix ||
				got.feature != tt.wantFeature ||
				got.shorthand != tt.wantShort ||
				gotOK != tt.wantOK {
				t.Errorf("nativeJavaSelector(%q) = (%+v, %t), want (%s, %q, %d, %t, %t)", tt.selector, got, gotOK, tt.wantVendor, tt.wantPrefix, tt.wantFeature, tt.wantShort, tt.wantOK)
			}
		})
	}
}

func TestResolverWithHostFallbackCanHandleUnknownGoModuleTool(t *testing.T) {
	native := &trackingResolver{err: errGoModuleNotFound}
	host := &trackingResolver{version: "1.2.3"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "go:example.com/missing/cmd/tool", "1")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.2.3" {
		t.Errorf("Latest = %q, want host result 1.2.3", got)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 1 {
		t.Errorf("host calls = %d, want 1", host.calls)
	}
}

func TestResolverWithHostFallbackCanHandleGitHubReleaseNoMatch(t *testing.T) {
	native := &trackingResolver{err: releases.ErrNoMatch}
	host := &trackingResolver{version: "1.2.3"}
	resolver := hostFallbackResolver{native: native, host: host}

	got, err := resolver.Latest(t.Context(), "github:owner/repo", "1")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.2.3" {
		t.Errorf("Latest = %q, want host result 1.2.3", got)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 1 {
		t.Errorf("host calls = %d, want 1", host.calls)
	}
}

func TestResolverWithHostFallbackDoesNotMaskGoRuntimeErrors(t *testing.T) {
	native := &trackingResolver{err: errGoRuntimeVersionNotFound}
	host := &trackingResolver{version: "9.9.9"}
	resolver := hostFallbackResolver{native: native, host: host}

	_, err := resolver.Latest(t.Context(), "go", "1.24")
	if !errors.Is(err, errGoRuntimeVersionNotFound) {
		t.Fatalf("Latest error = %v, want %v", err, errGoRuntimeVersionNotFound)
	}
	if native.calls != 1 {
		t.Errorf("native calls = %d, want 1", native.calls)
	}
	if host.calls != 0 {
		t.Errorf("host calls = %d, want 0", host.calls)
	}
}

func TestHostMiseResolverIgnoresStderrWarnings(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX shell script")
	}
	dir := t.TempDir()
	misePath := filepath.Join(dir, "mise")
	script := "#!/bin/sh\nprintf 'mise WARN update available\\n' >&2\nprintf '1.2.3\\n'\n"
	if err := os.WriteFile(misePath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mise: %v", err)
	}
	resolver, err := newHostMiseResolver(misePath)
	if err != nil {
		t.Fatalf("newHostMiseResolver: %v", err)
	}

	got, err := resolver.Latest(t.Context(), "node", "20")
	if err != nil {
		t.Fatalf("Latest: %v", err)
	}
	if got != "1.2.3" {
		t.Errorf("Latest = %q, want 1.2.3", got)
	}
}

func TestHostMiseResolverRejectsUnexpectedStdout(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("test uses a POSIX shell script")
	}
	dir := t.TempDir()
	misePath := filepath.Join(dir, "mise")
	script := "#!/bin/sh\nprintf 'mise WARN update available\\n1.2.3\\n'\n"
	if err := os.WriteFile(misePath, []byte(script), 0o755); err != nil {
		t.Fatalf("write fake mise: %v", err)
	}
	resolver, err := newHostMiseResolver(misePath)
	if err != nil {
		t.Fatalf("newHostMiseResolver: %v", err)
	}

	if _, err := resolver.Latest(t.Context(), "node", "20"); err == nil || !strings.Contains(err.Error(), "multiple stdout lines") {
		t.Fatalf("Latest error = %v, want multiple stdout lines error", err)
	}
}

func TestNativeResolverParityWithMise(t *testing.T) {
	misePath := os.Getenv("DEPUTY_MISE_PARITY_BIN")
	if misePath == "" {
		t.Skip("set DEPUTY_MISE_PARITY_BIN to an absolute mise executable path to run live parity checks")
	}
	host, err := newHostMiseResolver(misePath)
	if err != nil {
		t.Fatalf("newHostMiseResolver: %v", err)
	}
	native := newNativeResolver()

	tests := []struct {
		tool   string
		prefix string
	}{
		{tool: "npm:prettier", prefix: "3"},
		{tool: "cargo:ripgrep", prefix: "14"},
		{tool: "pipx:black", prefix: "25"},
		{tool: "gem:rails", prefix: "7"},
		{tool: "go", prefix: "1.25"},
		{tool: "java", prefix: "21"},
		{tool: "java", prefix: "temurin-21"},
		{tool: "github:cludden/protoc-gen-go-temporal", prefix: "1"},
		{tool: "ubi:BurntSushi/ripgrep", prefix: "15"},
		{tool: "go:golang.org/x/tools/cmd/goimports", prefix: "0"},
	}
	for _, tt := range tests {
		t.Run(tt.tool+"@"+tt.prefix, func(t *testing.T) {
			nativeVersion, nativeErr := native.Latest(t.Context(), tt.tool, tt.prefix)
			hostVersion, hostErr := host.Latest(t.Context(), tt.tool, tt.prefix)
			if hostErr != nil {
				t.Skipf("host mise cannot resolve this case: %v", hostErr)
			}
			if nativeErr != nil {
				t.Fatalf("native=%q err=%v; mise=%q err=%v", nativeVersion, nativeErr, hostVersion, hostErr)
			}
			t.Logf("native and mise resolved %s@%s to %s", tt.tool, tt.prefix, nativeVersion)
			if strings.TrimPrefix(nativeVersion, "v") != strings.TrimPrefix(hostVersion, "v") {
				t.Fatalf("native = %q, mise = %q", nativeVersion, hostVersion)
			}
		})
	}
}

func requestNames(requests []*pb.GetPackageRequest) []string {
	names := make([]string, 0, len(requests))
	for _, req := range requests {
		names = append(names, req.GetPackageKey().GetName())
	}
	return names
}

func packageVersions(system pb.System, name string, versions ...*pb.Package_Version) *pb.Package {
	for _, version := range versions {
		version.GetVersionKey().System = system
		version.GetVersionKey().Name = name
	}
	return &pb.Package{
		PackageKey: &pb.PackageKey{System: system, Name: name},
		Versions:   versions,
	}
}

func pkgVersion(version string, isDefault bool) *pb.Package_Version {
	return &pb.Package_Version{
		VersionKey: &pb.VersionKey{Version: version},
		IsDefault:  isDefault,
	}
}
