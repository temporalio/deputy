package ecosystem

import (
	"testing"

	pb "deps.dev/api/v3"
)

func TestParse(t *testing.T) {
	tests := []struct {
		input string
		want  Ecosystem
	}{
		// Go variants
		{"go", Go},
		{"Go", Go},
		{"golang", Go},
		{"GOLANG", Go},
		{"  go  ", Go},

		// NPM variants
		{"npm", NPM},
		{"NPM", NPM},
		{"javascript", NPM},
		{"node", NPM},
		{"nodejs", NPM},

		// PyPI variants
		{"pypi", PyPI},
		{"PyPI", PyPI},
		{"python", PyPI},
		{"pip", PyPI},

		// Maven variants
		{"maven", Maven},
		{"java", Maven},

		// RubyGems variants
		{"rubygems", RubyGems},
		{"ruby", RubyGems},
		{"gem", RubyGems},

		// Cargo variants
		{"cargo", Cargo},
		{"rust", Cargo},
		{"crates", Cargo},
		{"crates.io", Cargo},

		// NuGet variants
		{"nuget", NuGet},
		{"dotnet", NuGet},
		{".net", NuGet},

		// Hex variants
		{"hex", Hex},
		{"hexpm", Hex},
		{"elixir", Hex},

		// Pub variants
		{"pub", Pub},
		{"dart", Pub},
		{"flutter", Pub},

		// CocoaPods variants
		{"cocoapods", CocoaPods},
		{"pod", CocoaPods},
		{"swift", CocoaPods},

		// Packagist variants
		{"packagist", Packagist},
		{"composer", Packagist},
		{"php", Packagist},

		// Unknown
		{"unknown", Unknown},
		{"", Unknown},
		{"foobar", Unknown},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := Parse(tt.input)
			if got != tt.want {
				t.Errorf("Parse(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestOSVName(t *testing.T) {
	tests := []struct {
		eco  Ecosystem
		want string
	}{
		{Go, "Go"},
		{NPM, "npm"},
		{PyPI, "PyPI"},
		{Maven, "Maven"},
		{RubyGems, "RubyGems"},
		{Cargo, "crates.io"},
		{NuGet, "NuGet"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := tt.eco.OSVName()
			if got != tt.want {
				t.Errorf("%s.OSVName() = %q, want %q", tt.eco, got, tt.want)
			}
		})
	}
}

func TestDepsDevSystem(t *testing.T) {
	tests := []struct {
		eco  Ecosystem
		want pb.System
	}{
		{Go, pb.System_GO},
		{NPM, pb.System_NPM},
		{PyPI, pb.System_PYPI},
		{Maven, pb.System_MAVEN},
		{RubyGems, pb.System_RUBYGEMS},
		{Cargo, pb.System_CARGO},
		{NuGet, pb.System_NUGET},
		{Unknown, pb.System_SYSTEM_UNSPECIFIED},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := tt.eco.DepsDevSystem()
			if got != tt.want {
				t.Errorf("%s.DepsDevSystem() = %v, want %v", tt.eco, got, tt.want)
			}
		})
	}
}

func TestPackageKeyField(t *testing.T) {
	if Go.PackageKeyField() != "module" {
		t.Errorf("Go.PackageKeyField() = %q, want %q", Go.PackageKeyField(), "module")
	}
	if NPM.PackageKeyField() != "package" {
		t.Errorf("NPM.PackageKeyField() = %q, want %q", NPM.PackageKeyField(), "package")
	}
}

func TestNormalizeVersion(t *testing.T) {
	tests := []struct {
		eco     Ecosystem
		version string
		want    string
	}{
		{Go, "1.2.3", "v1.2.3"},
		{Go, "v1.2.3", "v1.2.3"},
		{Go, "  1.2.3  ", "v1.2.3"},
		{NPM, "1.2.3", "1.2.3"},
		{NPM, "v1.2.3", "v1.2.3"},
		{Go, "", ""},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco)+"/"+tt.version, func(t *testing.T) {
			got := tt.eco.NormalizeVersion(tt.version)
			if got != tt.want {
				t.Errorf("%s.NormalizeVersion(%q) = %q, want %q", tt.eco, tt.version, got, tt.want)
			}
		})
	}
}

func TestNormalizeName(t *testing.T) {
	tests := []struct {
		eco  Ecosystem
		name string
		want string
	}{
		{PyPI, "Requests", "requests"},
		{PyPI, "  Django  ", "django"},
		{NPM, "React", "React"},
		{Go, "github.com/Foo/Bar", "github.com/Foo/Bar"},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco)+"/"+tt.name, func(t *testing.T) {
			got := tt.eco.NormalizeName(tt.name)
			if got != tt.want {
				t.Errorf("%s.NormalizeName(%q) = %q, want %q", tt.eco, tt.name, got, tt.want)
			}
		})
	}
}

func TestIsSupported(t *testing.T) {
	if !Go.IsSupported() {
		t.Error("Go.IsSupported() = false, want true")
	}
	if Unknown.IsSupported() {
		t.Error("Unknown.IsSupported() = true, want false")
	}
	if Ecosystem("").IsSupported() {
		t.Error(`Ecosystem("").IsSupported() = true, want false`)
	}
}

func TestScalibrPrefixes(t *testing.T) {
	// Test that each supported ecosystem returns valid SCALIBR prefixes.
	// These prefixes must match the first path segment of actual OSV-SCALIBR
	// plugin names (e.g., "go/gomod" has prefix "go").
	tests := []struct {
		eco  Ecosystem
		want []string
	}{
		{Go, []string{"go"}},
		{NPM, []string{"javascript"}},
		{PyPI, []string{"python"}},
		{Maven, []string{"java"}},
		{RubyGems, []string{"ruby"}},
		{Cargo, []string{"rust"}},
		{NuGet, []string{"dotnet"}},
		{Hex, []string{"elixir", "erlang"}},
		{Pub, []string{"dart"}},
		{CocoaPods, []string{"swift"}},
		{Packagist, []string{"php"}},
		{Unknown, nil},
	}

	for _, tt := range tests {
		t.Run(string(tt.eco), func(t *testing.T) {
			got := tt.eco.ScalibrPrefixes()
			if len(got) != len(tt.want) {
				t.Fatalf("%s.ScalibrPrefixes() = %v, want %v", tt.eco, got, tt.want)
			}
			for i, prefix := range got {
				if prefix != tt.want[i] {
					t.Errorf("%s.ScalibrPrefixes()[%d] = %q, want %q", tt.eco, i, prefix, tt.want[i])
				}
			}
		})
	}
}

func TestAllScalibrPrefixes(t *testing.T) {
	prefixes := AllScalibrPrefixes()

	// Build a set for O(1) lookup
	seen := make(map[string]struct{}, len(prefixes))
	for _, p := range prefixes {
		seen[p] = struct{}{}
	}

	// Verify all supported ecosystem prefixes are included
	for _, eco := range All() {
		for _, prefix := range eco.ScalibrPrefixes() {
			if _, ok := seen[prefix]; !ok {
				t.Errorf("AllScalibrPrefixes() missing prefix %q for ecosystem %s", prefix, eco)
			}
		}
	}

	// Verify extra prefixes for ecosystems Deputy supports via other mechanisms
	extras := []string{"github", "haskell", "r", "cpp"}
	for _, extra := range extras {
		if _, ok := seen[extra]; !ok {
			t.Errorf("AllScalibrPrefixes() missing extra prefix %q", extra)
		}
	}

	// Verify no duplicates
	if len(seen) != len(prefixes) {
		t.Errorf("AllScalibrPrefixes() contains duplicates: got %d items, %d unique", len(prefixes), len(seen))
	}
}

func TestScalibrPrefixesMatchPluginNames(t *testing.T) {
	// Verify that ScalibrPrefixes returns values that correctly match
	// actual OSV-SCALIBR plugin naming conventions. Plugin names follow
	// the pattern "prefix/name" (e.g., "go/gomod", "javascript/packagejson").
	//
	// This test documents the expected plugin name patterns for each ecosystem.
	expectedPluginPatterns := map[Ecosystem][]string{
		Go:        {"go/gomod", "go/gobinary"},
		NPM:       {"javascript/packagejson", "javascript/packagelockjson"},
		PyPI:      {"python/requirements", "python/pipfilelock"},
		Maven:     {"java/pomxml", "java/gradlelockfile"},
		RubyGems:  {"ruby/gemfilelock"},
		Cargo:     {"rust/cargolock"},
		NuGet:     {"dotnet/packageslock"},
		Hex:       {"elixir/mixlock", "erlang/rebarlock"},
		Pub:       {"dart/pubspeclock"},
		CocoaPods: {"swift/podfilelock"},
		Packagist: {"php/composerlock"},
	}

	for eco, patterns := range expectedPluginPatterns {
		prefixes := eco.ScalibrPrefixes()
		if len(prefixes) == 0 {
			t.Errorf("%s.ScalibrPrefixes() returned empty, expected prefixes for %v", eco, patterns)
			continue
		}

		// Verify each expected plugin pattern starts with one of the ecosystem's prefixes
		for _, pattern := range patterns {
			matched := false
			for _, prefix := range prefixes {
				if len(pattern) > len(prefix) && pattern[:len(prefix)+1] == prefix+"/" {
					matched = true
					break
				}
			}
			if !matched {
				t.Errorf("%s.ScalibrPrefixes() = %v does not match expected plugin %q", eco, prefixes, pattern)
			}
		}
	}
}
