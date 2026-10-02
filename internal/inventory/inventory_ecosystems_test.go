package inventory

import (
	"slices"
	"testing"

	"github.com/google/osv-scalibr/plugin"

	"github.com/temporalio/deputy/internal/ecosystem"
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
// contract: every canonical ecosystem name Deputy advertises in CLI help and
// emits in results (ecosystem.All()) must resolve to plugins instead of
// erroring with scalibr's unknown-plugin failure. Ranging over the registry
// keeps newly added ecosystems covered automatically.
func TestResolvePluginsAcceptsCanonicalEcosystemNames(t *testing.T) {
	all := ecosystem.All()
	// Sanity floor: 13 canonical ecosystems today; an empty or shrunken
	// registry would silently hollow out this test.
	if len(all) < 13 {
		t.Fatalf("ecosystem.All() returned %d ecosystems, want at least 13", len(all))
	}

	cap := &plugin.Capabilities{OS: plugin.OSLinux}
	for _, eco := range all {
		t.Run(string(eco), func(t *testing.T) {
			plugins, err := resolvePlugins(ScanOptions{Ecosystems: []string{string(eco)}}, cap)
			if err != nil {
				t.Fatalf("resolvePlugins(%q): %v", eco, err)
			}
			if len(plugins) == 0 {
				t.Fatalf("resolvePlugins(%q) returned no plugins", eco)
			}
		})
	}
}

// TestEveryCanonicalEcosystemResolvesToPlugins derives the filter contract from
// the canonical vocabulary instead of restating part of it: every name Deputy
// accepts as an ecosystem has to reach a scanner, whether it gets there through
// a SCALIBR plugin group or through one of Deputy's own extractors.
//
// The listed form of this test could not have caught the defect it now guards.
// Callers that canonicalize before filtering (every MCP tool does) turned
// "haskell", "r", and "cpp" into "hackage", "cran", and "conancenter", which
// are the right Deputy tokens and not SCALIBR plugin groups, so a scan filtered
// to any of them failed with unknown plugin instead of scanning.
func TestEveryCanonicalEcosystemResolvesToPlugins(t *testing.T) {
	cap := &plugin.Capabilities{OS: plugin.OSLinux}
	for _, token := range ecosystem.CanonicalEcosystems() {
		t.Run(token, func(t *testing.T) {
			plugins, err := resolvePlugins(ScanOptions{Ecosystems: []string{token}}, cap)
			if err != nil {
				t.Fatalf("resolvePlugins(%q): %v", token, err)
			}
			if len(plugins) == 0 {
				t.Fatalf("resolvePlugins(%q) returned no plugins", token)
			}
		})
	}
}

// TestScalibrGroupNamesSurviveCanonicalization pins the round trip that broke:
// a raw SCALIBR group name that is also an ecosystem alias must still select
// that group's plugins after canonicalization, because the two spellings name
// one thing and a caller may send either.
func TestScalibrGroupNamesSurviveCanonicalization(t *testing.T) {
	tests := []struct {
		name      string
		spellings []string
		want      []string
	}{
		{name: "haskell", spellings: []string{"haskell", "hackage", "Hackage", "cabal", "stack"}, want: []string{"haskell"}},
		{name: "r", spellings: []string{"r", "cran", "CRAN", "renv"}, want: []string{"r"}},
		{name: "cpp", spellings: []string{"cpp", "c++", "conan", "conancenter", "ConanCenter"}, want: []string{"cpp"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			for _, spelling := range tt.spellings {
				canonical := ecosystem.CanonicalOrRaw(spelling)
				got := scalibrEcosystemNames([]string{canonical})
				if !slices.Equal(got, tt.want) {
					t.Errorf("scalibrEcosystemNames(Canonical(%q)=%q) = %v, want %v", spelling, canonical, got, tt.want)
				}
			}
		})
	}
}

// TestEverySpellingOfAnEcosystemResolvesToTheSamePlugins pins the filter to the
// vocabulary, not to a copy of part of it. Every string that names an ecosystem
// (its canonical token, its display name, and each alias, taken from
// ecosystem.Spellings) has to reach the same scanners, because a caller that
// spells an ecosystem the way Deputy itself renders it is naming the same
// ecosystem.
//
// The internal plugins are where this broke. Their routing kept a hand-written
// alias set beside the registry's, so "GitHub Actions", the display form this
// PR's own contract emits, and the "github-action" and "githubaction" aliases
// reached neither the internal plugin nor a SCALIBR group, and the scan failed
// with an unknown-plugin error instead of scanning workflows.
func TestEverySpellingOfAnEcosystemResolvesToTheSamePlugins(t *testing.T) {
	cap := &plugin.Capabilities{OS: plugin.OSLinux}
	for _, token := range ecosystem.CanonicalEcosystems() {
		eco := ecosystem.Ecosystem(token)
		spellings := ecosystem.Spellings(eco)
		if len(spellings) == 0 {
			t.Fatalf("ecosystem %q reports no spellings", token)
		}
		want, err := resolvePlugins(ScanOptions{Ecosystems: []string{token}}, cap)
		if err != nil {
			t.Fatalf("resolvePlugins(%q): %v", token, err)
		}
		for _, spelling := range spellings {
			t.Run(token+"/"+spelling, func(t *testing.T) {
				got, err := resolvePlugins(ScanOptions{Ecosystems: []string{spelling}}, cap)
				if err != nil {
					t.Fatalf("resolvePlugins(%q): %v", spelling, err)
				}
				if !slices.Equal(pluginNames(got), pluginNames(want)) {
					t.Errorf("resolvePlugins(%q) = %v, want the plugins %q resolves to: %v",
						spelling, pluginNames(got), token, pluginNames(want))
				}
			})
		}
	}
}

// pluginNames returns the sorted plugin names, so two resolutions of one
// ecosystem are compared by what they scan rather than by plugin order.
func pluginNames(plugins []plugin.Plugin) []string {
	names := make([]string, 0, len(plugins))
	for _, p := range plugins {
		names = append(names, p.Name())
	}
	slices.Sort(names)
	return names
}
