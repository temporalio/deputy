package inventory

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/plugin"
)

// TestScalibrEcosystemNames pins the filter vocabulary contract: Deputy's
// canonical ecosystem names (the ones every output emits) translate to the
// OSV-SCALIBR group names upstream plugin resolution understands, and names
// outside the registry pass through verbatim.
func TestScalibrEcosystemNames(t *testing.T) {
	tests := []struct {
		name  string
		input []string
		want  []string
	}{
		{name: "nil stays nil", input: nil, want: nil},
		{name: "cargo translates to rust", input: []string{"cargo"}, want: []string{"rust"}},
		{name: "npm translates to javascript", input: []string{"npm"}, want: []string{"javascript"}},
		{name: "pypi translates to python", input: []string{"pypi"}, want: []string{"python"}},
		{name: "maven translates to java", input: []string{"maven"}, want: []string{"java"}},
		{name: "hex expands to both beam prefixes", input: []string{"hex"}, want: []string{"elixir", "erlang"}},
		{name: "aliases resolve", input: []string{"golang", "rust"}, want: []string{"go", "rust"}},
		{name: "scalibr-only groups pass through", input: []string{"haskell", "r", "cpp"}, want: []string{"cpp", "haskell", "r"}},
		{name: "duplicates collapse", input: []string{"cargo", "rust", "crates.io"}, want: []string{"rust"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := scalibrEcosystemNames(tt.input)
			if !slices.Equal(got, tt.want) {
				t.Errorf("scalibrEcosystemNames(%v) = %v, want %v", tt.input, got, tt.want)
			}
		})
	}
}

// TestResolvePluginsAcceptsCanonicalEcosystemNames pins the end-to-end filter
// contract: the names Deputy advertises in CLI help and emits in results
// (cargo, npm, pypi) must resolve to plugins instead of erroring with
// scalibr's unknown-plugin failure.
func TestResolvePluginsAcceptsCanonicalEcosystemNames(t *testing.T) {
	cap := &plugin.Capabilities{OS: plugin.OSLinux}
	for _, eco := range []string{"cargo", "npm", "pypi", "maven", "rubygems", "nuget", "hex", "pub", "cocoapods", "packagist"} {
		t.Run(eco, func(t *testing.T) {
			plugins, err := resolvePlugins(ScanOptions{Ecosystems: []string{eco}}, cap)
			if err != nil {
				t.Fatalf("resolvePlugins(%q): %v", eco, err)
			}
			if len(plugins) == 0 {
				t.Fatalf("resolvePlugins(%q) returned no plugins", eco)
			}
		})
	}
}
