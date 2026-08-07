package advisorysource

import (
	"context"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	pluginv1 "github.com/temporalio/deputy/gen/deputy/plugin/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"pluginrpc.com/pluginrpc"
)

// fakeAdvisoryClient is an in-memory AdvisorySourceServiceClient for testing the
// plugin adapter without spawning a subprocess.
type fakeAdvisoryClient struct {
	resp *pluginv1.AdvisoryQueryResponse
	got  *pluginv1.AdvisoryQueryRequest
}

func (f *fakeAdvisoryClient) Info(_ context.Context, _ *pluginv1.AdvisorySourceInfoRequest, _ ...pluginrpc.CallOption) (*pluginv1.AdvisorySourceInfoResponse, error) {
	return &pluginv1.AdvisorySourceInfoResponse{Info: &pluginv1.AdvisorySourceInfo{Name: "ghsa-feed"}}, nil
}

func (f *fakeAdvisoryClient) Query(_ context.Context, req *pluginv1.AdvisoryQueryRequest, _ ...pluginrpc.CallOption) (*pluginv1.AdvisoryQueryResponse, error) {
	f.got = req
	return f.resp, nil
}

// TestPluginSourceQueryIsProtoOneToOne verifies the plugin adapter passes proto
// packages through unchanged and returns the plugin's proto findings verbatim,
// only stamping provenance: no domain conversion at the boundary.
func TestPluginSourceQueryIsProtoOneToOne(t *testing.T) {
	fake := &fakeAdvisoryClient{
		resp: &pluginv1.AdvisoryQueryResponse{
			Findings: []*vulnerabilityv1.Finding{
				{AdvisoryId: "GHSA-xxxx", Package: &dependencyv1.Package{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Purl: "pkg:npm/lodash@4.17.20", Direct: true}, Affected: true},
			},
			Advisories: map[string]*vulnerabilityv1.Advisory{"GHSA-xxxx": {Id: "GHSA-xxxx"}},
		},
	}
	src := &pluginSource{
		programName: "deputy-advisory-source-ghsa",
		client:      fake,
		info:        &pluginv1.AdvisorySourceInfo{Name: "ghsa-feed"},
	}

	pkgs := []*dependencyv1.Package{{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Purl: "pkg:npm/lodash@4.17.20", Direct: true}}
	res, err := src.Query(t.Context(), pkgs)
	if err != nil {
		t.Fatal(err)
	}
	// Packages forwarded verbatim (1:1, no conversion).
	if len(fake.got.GetPackages()) != 1 || fake.got.GetPackages()[0].GetPurl() != "pkg:npm/lodash@4.17.20" {
		t.Fatalf("plugin received %+v, want the package unchanged", fake.got.GetPackages())
	}
	if len(res.Findings) != 1 {
		t.Fatalf("findings = %d, want 1", len(res.Findings))
	}
	f := res.Findings[0]
	if f.GetAdvisoryId() != "GHSA-xxxx" || !f.GetPackage().GetDirect() {
		t.Errorf("finding not passed through 1:1: %+v", f)
	}
	if !slices.Contains(f.GetSources(), "ghsa-feed") {
		t.Errorf("provenance not stamped: sources = %v", f.GetSources())
	}
}

// compile-time proof the plugin adapter satisfies the Source contract.
var _ Source = (*pluginSource)(nil)

// TestPluginSourceEndToEnd builds the example advisory-source plugin and drives
// it over the real pluginrpc subprocess transport, proving the SDK server and
// host client interoperate 1:1 with proto types.
func TestPluginSourceEndToEnd(t *testing.T) {
	if testing.Short() {
		t.Skip("builds and spawns a plugin subprocess")
	}
	if _, err := exec.LookPath("go"); err != nil {
		t.Skip("go toolchain not available")
	}

	bin := filepath.Join(t.TempDir(), "deputy-advisory-source-static")
	build := exec.Command("go", "build", "-o", bin, "github.com/temporalio/deputy/examples/advisory-source-plugins/static")
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("build example plugin: %v\n%s", err, out)
	}

	ctx := t.Context()
	src, err := NewPluginSource(ctx, bin)
	if err != nil {
		t.Fatalf("NewPluginSource: %v", err)
	}
	if src.Info().GetName() != "static-example" {
		t.Fatalf("plugin Info name = %q, want static-example", src.Info().GetName())
	}

	res, err := src.Query(ctx, []*dependencyv1.Package{
		{Name: "evil-package", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/evil-package@1.0.0"},
		{Name: "safe-package", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/safe-package@1.0.0"},
	})
	if err != nil {
		t.Fatalf("Query: %v", err)
	}
	if len(res.Findings) != 1 || res.Findings[0].GetAdvisoryId() != "MAL-EXAMPLE-0001" {
		t.Fatalf("findings = %+v, want one MAL-EXAMPLE-0001", res.Findings)
	}
	if !slices.Contains(res.Findings[0].GetSources(), "static-example") {
		t.Errorf("provenance not stamped: %v", res.Findings[0].GetSources())
	}
	if adv := res.Advisories["MAL-EXAMPLE-0001"]; adv == nil || adv.GetKind() != vulnerabilityv1.FindingKind_FINDING_KIND_MALWARE {
		t.Errorf("advisory kind = %v, want MALWARE", adv.GetKind())
	}

	// The scan wiring: DEPUTY_ADVISORY_SOURCES loads the plugin into the
	// default registry alongside the built-in OSV source.
	t.Setenv(EnvAdvisorySources, bin)
	configured, err := materializeSources(ctx, allSourceConfigs())
	if err != nil {
		t.Fatalf("materializeSources: %v", err)
	}
	if len(configured) != 1 || configured[0].Info().GetName() != "static-example" {
		t.Fatalf("configured sources = %+v, want the static example plugin", configured)
	}
	reg := NewDefaultRegistry(ctx, nil)
	names := make([]string, 0, len(reg.sources))
	for _, s := range reg.sources {
		names = append(names, s.Info().GetName())
	}
	if !slices.Contains(names, SourceNameOSV) || !slices.Contains(names, "static-example") {
		t.Fatalf("default registry sources = %v, want osv + static-example", names)
	}
}

func TestParseProgramList(t *testing.T) {
	tests := []struct {
		name string
		in   string
		want []string
	}{
		{"empty", "", nil},
		{"single", "deputy-advisory-source-x", []string{"deputy-advisory-source-x"}},
		{"comma separated with whitespace", " a , b ,, c ", []string{"a", "b", "c"}},
		{"paths", "/usr/local/bin/deputy-advisory-source-x,./rel/plugin", []string{"/usr/local/bin/deputy-advisory-source-x", "./rel/plugin"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := parseProgramList(tt.in); !slices.Equal(got, tt.want) {
				t.Fatalf("parseProgramList(%q) = %v, want %v", tt.in, got, tt.want)
			}
		})
	}
}
