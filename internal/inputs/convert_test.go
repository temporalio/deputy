package inputs

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"

	"github.com/temporalio/deputy/internal/analysis/osv"
	"github.com/temporalio/deputy/internal/compare"
	"github.com/temporalio/deputy/internal/inventory/manifests"
	"github.com/temporalio/deputy/internal/purlx"
)

// Test that Convert includes all packages and determines directness
// using go.mod in the current working directory.
func TestConvert_AllPackages(t *testing.T) {
	goMod := `module example.com/app

require (
    github.com/golang-jwt/jwt/v4 v4.5.1
    github.com/indirect/pkg v1.2.3 // indirect
)`
	deps := compare.GetDirectDependenciesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "github.com/golang-jwt/jwt/v4", Version: "v4.5.1", PURLType: scalpurl.TypeGolang},
		{Name: "github.com/indirect/pkg", Version: "v1.2.3", PURLType: scalpurl.TypeGolang},
	}

	inputs := Convert(pkgs, Options{GoDirect: deps})
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}

	var directFound, indirectFound bool
	for _, in := range inputs {
		switch in.Name {
		case "github.com/golang-jwt/jwt/v4":
			if !in.IsDirect {
				t.Errorf("expected jwt dependency to be direct")
			}
			directFound = true
		case "github.com/indirect/pkg":
			if in.IsDirect {
				t.Errorf("expected indirect/pkg to be indirect")
			}
			indirectFound = true
		}
	}
	if !directFound || !indirectFound {
		t.Fatalf("missing expected inputs: %+v", inputs)
	}
}

func TestConvert_GitHubActions_WorkflowUsesAreDirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "actions/download-artifact",
			Version:  "v4",
			PURLType: purlx.TypeGitHubActions,
			Location: extractor.LocationFromPath(".github/workflows/build.yaml"),
		},
	}

	inputs := Convert(pkgs, Options{})
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if !inputs[0].IsDirect {
		t.Fatalf("expected GitHub Actions workflow dependency to be direct, got %+v", inputs[0])
	}
	if len(inputs[0].ManifestRefs) != 1 {
		t.Fatalf("expected 1 manifest ref, got %+v", inputs[0].ManifestRefs)
	}
	ref := &inputs[0].ManifestRefs[0]
	if ref.Manager != purlx.TypeGitHubActions || ref.Path != ".github/workflows/build.yaml" {
		t.Fatalf("manifest ref = {Manager:%q Path:%q}, want {Manager:%q Path:%q}", ref.Manager, ref.Path, purlx.TypeGitHubActions, ".github/workflows/build.yaml")
	}
}

func TestConvert_GitHubActions_ActionManifestUsesAreDirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "actions/checkout",
			Version:  "v4",
			PURLType: purlx.TypeGitHubActions,
			Location: extractor.LocationFromPath("tools/action/action.yml"),
		},
	}

	inputs := Convert(pkgs, Options{})
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if !inputs[0].IsDirect {
		t.Fatalf("expected GitHub Actions action.yml dependency to be direct, got %+v", inputs[0])
	}
	if len(inputs[0].ManifestRefs) != 1 {
		t.Fatalf("expected 1 manifest ref, got %+v", inputs[0].ManifestRefs)
	}
	ref := &inputs[0].ManifestRefs[0]
	if ref.Manager != purlx.TypeGitHubActions || ref.Path != "tools/action/action.yml" {
		t.Fatalf("manifest ref = {Manager:%q Path:%q}, want {Manager:%q Path:%q}", ref.Manager, ref.Path, purlx.TypeGitHubActions, "tools/action/action.yml")
	}
}

// Ensure gopkg.in modules retain their original import path and directness.
func TestConvert_GopkgInPreserved(t *testing.T) {
	goMod := `module example.com/app

require (
    gopkg.in/yaml.v3 v3.0.1
    gopkg.in/indirect.v3 v3.0.0 // indirect
)`
	deps := compare.GetDirectDependenciesFromGoMod([]byte(goMod))

	pkgs := []*extractor.Package{
		{Name: "gopkg.in/yaml.v3", Version: "v3.0.1", PURLType: scalpurl.TypeGolang},
		{Name: "gopkg.in/indirect.v3", Version: "v3.0.0", PURLType: scalpurl.TypeGolang},
	}

	inputs := Convert(pkgs, Options{GoDirect: deps})
	if len(inputs) != 2 {
		t.Fatalf("expected 2 inputs, got %d", len(inputs))
	}

	for _, in := range inputs {
		switch in.Name {
		case "gopkg.in/yaml.v3":
			if !in.IsDirect {
				t.Errorf("expected yaml to be direct")
			}
		case "gopkg.in/indirect.v3":
			if in.IsDirect {
				t.Errorf("expected indirect to be indirect")
			}
		default:
			t.Errorf("unexpected package %s", in.Name)
		}
	}
}

func TestConvert_NPMDirectDetection(t *testing.T) {
	files := map[string]string{
		"web/package.json": `{
		  "name": "web",
		  "dependencies": {
		    "react": "18.2.0"
		  },
		  "devDependencies": {
		    "typescript": "5.1.0"
		  }
		}`,
	}
	resolver := ResolverFunc(func(rel string) ([]byte, error) {
		if data, ok := files[filepath.ToSlash(rel)]; ok {
			return []byte(data), nil
		}
		return nil, fmt.Errorf("not found: %s", rel)
	})

	pkgs := []*extractor.Package{
		{
			Name:     "react",
			Version:  "18.2.0",
			PURLType: scalpurl.TypeNPM,
			Location: extractor.LocationFromPath("web/package-lock.json"),
		},
		{
			Name:     "typescript",
			Version:  "5.1.0",
			PURLType: scalpurl.TypeNPM,
			Location: extractor.LocationFromPath("web/package-lock.json"),
		},
		{
			Name:     "left-pad",
			Version:  "1.3.0",
			PURLType: scalpurl.TypeNPM,
			Location: extractor.LocationFromPath("web/package-lock.json"),
		},
	}

	inputs := Convert(pkgs, Options{Resolver: resolver})
	if len(inputs) != 3 {
		t.Fatalf("expected 3 inputs, got %d", len(inputs))
	}

	lookup := map[string]osv.PkgInput{}
	for _, in := range inputs {
		lookup[in.Name] = in
	}

	if !lookup["react"].IsDirect {
		t.Fatalf("react should be direct due to dependencies")
	}
	if len(lookup["react"].ManifestRefs) == 0 || lookup["react"].ManifestRefs[0].Manager != "npm" {
		t.Fatalf("react manifest reference missing or incorrect: %+v", lookup["react"].ManifestRefs)
	}
	if !containsGroup(lookup["react"].ManifestRefs[0].Groups, "dependencies") {
		t.Fatalf("react expected dependencies group: %+v", lookup["react"].ManifestRefs[0].Groups)
	}
	if lookup["typescript"].IsDirect {
		t.Fatalf("typescript dev dependency should be indirect")
	}
	if !containsGroup(lookup["typescript"].ManifestRefs[0].Groups, "devDependencies") {
		t.Fatalf("typescript expected devDependencies group: %+v", lookup["typescript"].ManifestRefs[0].Groups)
	}
	if lookup["left-pad"].IsDirect {
		t.Fatalf("left-pad should remain indirect")
	}
}

func TestConvert_UVLockDirectDetection(t *testing.T) {
	uvLock := `version = 1

[[package]]
name = "runtime-one"
version = "1.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "runtime-two"
version = "2.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "optional-one"
version = "0.1.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "pytest"
version = "7.0.0"
source = { registry = "https://pypi.org/simple" }

[[package]]
name = "project"
version = "0.0.1"
source = { virtual = "." }
dependencies = [
    { name = "runtime-one" },
    { name = "runtime-two" },
]
[package.optional-dependencies]
extras = [
    { name = "optional-one" },
]
[package.dev-dependencies]
dev = [
    { name = "pytest" },
]
`
	resolver := ResolverFunc(func(rel string) ([]byte, error) {
		if filepath.ToSlash(rel) == "uv.lock" {
			return []byte(uvLock), nil
		}
		return nil, fmt.Errorf("not found")
	})

	pkgs := []*extractor.Package{
		{Name: "runtime-one", Version: "1.0.0", PURLType: scalpurl.TypePyPi, Location: extractor.LocationFromPath("uv.lock")},
		{Name: "optional-one", Version: "0.1.0", PURLType: scalpurl.TypePyPi, Location: extractor.LocationFromPath("uv.lock")},
		{Name: "pytest", Version: "7.0.0", PURLType: scalpurl.TypePyPi, Location: extractor.LocationFromPath("uv.lock")},
		{Name: "transitive", Version: "0.0.1", PURLType: scalpurl.TypePyPi, Location: extractor.LocationFromPath("uv.lock")},
	}

	inputs := Convert(pkgs, Options{Resolver: resolver})
	if len(inputs) != 4 {
		t.Fatalf("expected 4 inputs, got %d", len(inputs))
	}
	lookup := map[string]osv.PkgInput{}
	for _, in := range inputs {
		lookup[in.Name] = in
	}
	if !lookup["runtime-one"].IsDirect {
		t.Fatalf("runtime-one should be direct from uv.lock")
	}
	if lookup["optional-one"].IsDirect {
		t.Fatalf("optional-one should not be direct (optional group)")
	}
	if groups := lookup["optional-one"].ManifestRefs[0].Groups; len(groups) == 0 || groups[0] != "extras" {
		t.Fatalf("expected optional-one groups to include extras, got %+v", lookup["optional-one"].ManifestRefs)
	}
	if lookup["pytest"].IsDirect {
		t.Fatalf("pytest (dev) should not be direct")
	}
	if len(lookup["runtime-one"].ManifestRefs) == 0 || lookup["runtime-one"].ManifestRefs[0].Manager != "uv" {
		t.Fatalf("runtime-one manifest ref should point to uv.lock")
	}
}

func TestConvert_CargoDirectDetection(t *testing.T) {
	cargoToml := `[package]
name = "demo"
version = "0.1.0"

[dependencies]
tokio = "1.0"
bytes = { version = "1.0" }

[dev-dependencies]
criterion = "0.5"

[build-dependencies]
cc = "1.0"

[workspace.dependencies]
serde = "1.0"

[target."cfg(unix)".dependencies]
libc = "0.2"
`
	resolver := ResolverFunc(func(rel string) ([]byte, error) {
		if filepath.ToSlash(rel) == "Cargo.toml" {
			return []byte(cargoToml), nil
		}
		return nil, fmt.Errorf("not found: %s", rel)
	})
	pkgs := []*extractor.Package{
		{Name: "tokio", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Location: extractor.LocationFromPath("Cargo.lock")},
		{Name: "criterion", Version: "0.5.0", PURLType: scalpurl.TypeCargo, Location: extractor.LocationFromPath("Cargo.lock")},
		{Name: "serde", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Location: extractor.LocationFromPath("Cargo.lock")},
		{Name: "cc", Version: "1.0.0", PURLType: scalpurl.TypeCargo, Location: extractor.LocationFromPath("Cargo.lock")},
		{Name: "libc", Version: "0.2.0", PURLType: scalpurl.TypeCargo, Location: extractor.LocationFromPath("Cargo.lock")},
	}
	inputs := Convert(pkgs, Options{Resolver: resolver})
	if len(inputs) != 5 {
		t.Fatalf("expected 5 inputs, got %d", len(inputs))
	}
	lookup := map[string]osv.PkgInput{}
	for _, in := range inputs {
		lookup[strings.ToLower(in.Name)] = in
	}
	if !lookup["tokio"].IsDirect {
		t.Fatalf("tokio should be marked direct from dependencies")
	}
	if lookup["criterion"].IsDirect {
		t.Fatalf("criterion is a dev-dependency and should remain indirect")
	}
	if !lookup["serde"].IsDirect {
		t.Fatalf("serde should be direct via workspace.dependencies")
	}
	if lookup["cc"].IsDirect {
		t.Fatalf("build dependency cc should not be direct")
	}
	if !lookup["libc"].IsDirect {
		t.Fatalf("target-specific dependency libc should be direct")
	}
}

func TestConvert_PythonRequirementsMarkedDirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{
			Name:     "requests",
			Version:  "2.32.0",
			PURLType: scalpurl.TypePyPi,
			Location: extractor.LocationFromPath("requirements.txt"),
		},
	}
	inputs := Convert(pkgs, Options{})
	if len(inputs) != 1 {
		t.Fatalf("expected 1 input, got %d", len(inputs))
	}
	if !inputs[0].IsDirect {
		t.Fatalf("expected python requirement to be marked direct")
	}
	if len(inputs[0].ManifestRefs) != 1 || inputs[0].ManifestRefs[0].Manager != "pip" {
		t.Fatalf("expected manifest ref for pip, got %+v", inputs[0].ManifestRefs)
	}
}

func containsGroup(groups []string, want string) bool {
	return slices.Contains(groups, want)
}

func TestDetectManager(t *testing.T) {
	tests := []struct {
		location     string
		purlType     string
		wantManager  string
		wantManifest string
		wantOk       bool
	}{
		// Go
		{"go.mod", "", "go", "go.mod", true},
		{"subdir/go.mod", "", "go", "subdir/go.mod", true},

		// npm ecosystem
		{"package-lock.json", "", "npm", "package.json", true},
		{"web/package-lock.json", "", "npm", "web/package.json", true},
		{"npm-shrinkwrap.json", "", "npm", "package.json", true},
		{"yarn.lock", "", "yarn", "package.json", true},
		{"app/yarn.lock", "", "yarn", "app/package.json", true},
		{"pnpm-lock.yaml", "", "pnpm", "package.json", true},
		{"pnpm-lock.yml", "", "pnpm", "package.json", true},
		{"package.json", "npm", "npm", "package.json", true},
		{"package.json", "", "", "", false}, // without purlType hint

		// Python
		{"requirements.txt", "", "pip", "requirements.txt", true},
		{"Pipfile.lock", "", "pipenv", "Pipfile", true},
		{"poetry.lock", "", "poetry", "pyproject.toml", true},
		{"uv.lock", "", "uv", "uv.lock", true},

		// Ruby
		{"Gemfile.lock", "", "gem", "Gemfile", true},
		{"gems.locked", "", "gem", "Gemfile", true},
		{"myapp.gemspec", "", "gem", "myapp.gemspec", true},
		{"lib/foo.gemspec", "", "gem", "lib/foo.gemspec", true},

		// PHP
		{"composer.lock", "", "composer", "composer.json", true},

		// Rust
		{"Cargo.toml", "", "cargo", "Cargo.toml", true},
		{"Cargo.lock", "", "cargo", "Cargo.toml", true},
		{"sub/Cargo.lock", "", "cargo", "sub/Cargo.toml", true},

		// GitHub Actions
		{".github/workflows/ci.yml", "", purlx.TypeGitHubActions, ".github/workflows/ci.yml", true},
		{".github/workflows/ci.yaml", "", purlx.TypeGitHubActions, ".github/workflows/ci.yaml", true},
		{".github/workflows/build.YML", "", purlx.TypeGitHubActions, ".github/workflows/build.YML", true},
		{"action.yml", "", purlx.TypeGitHubActions, "action.yml", true},
		{"action.yaml", "", purlx.TypeGitHubActions, "action.yaml", true},
		{"tools/my-action/action.yml", "", purlx.TypeGitHubActions, "tools/my-action/action.yml", true},

		// Unknown
		{"random.txt", "", "", "", false},
		{"Makefile", "", "", "", false},
	}

	for _, tt := range tests {
		t.Run(tt.location, func(t *testing.T) {
			manager, manifest, ok := manifests.DetectManager(tt.location, tt.purlType)
			if ok != tt.wantOk {
				t.Errorf("detectManager(%q, %q) ok = %v, want %v", tt.location, tt.purlType, ok, tt.wantOk)
			}
			if manager != tt.wantManager {
				t.Errorf("detectManager(%q, %q) manager = %q, want %q", tt.location, tt.purlType, manager, tt.wantManager)
			}
			if manifest != tt.wantManifest {
				t.Errorf("detectManager(%q, %q) manifest = %q, want %q", tt.location, tt.purlType, manifest, tt.wantManifest)
			}
		})
	}
}

func TestAppendUnique(t *testing.T) {
	tests := []struct {
		name string
		dst  []string
		src  []string
		want []string
	}{
		{"nil dst", nil, []string{"a", "b"}, []string{"a", "b"}},
		{"nil src", []string{"a"}, nil, []string{"a"}},
		{"both nil", nil, nil, nil},
		{"no duplicates", []string{"a"}, []string{"b", "c"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"a", "b"}, []string{"b", "c"}, []string{"a", "b", "c"}},
		{"empty strings filtered", []string{"a"}, []string{"", "  ", "b"}, []string{"a", "b"}},
		{"whitespace trimmed", []string{"a"}, []string{" b "}, []string{"a", "b"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUnique(tt.dst, tt.src...)
			if !slices.Equal(got, tt.want) {
				t.Errorf("appendUnique(%v, %v) = %v, want %v", tt.dst, tt.src, got, tt.want)
			}
		})
	}
}

func TestSortedUnique(t *testing.T) {
	tests := []struct {
		name   string
		values []string
		want   []string
	}{
		{"nil", nil, nil},
		{"empty", []string{}, []string{}},
		{"single", []string{"a"}, []string{"a"}},
		{"already sorted unique", []string{"a", "b", "c"}, []string{"a", "b", "c"}},
		{"unsorted", []string{"c", "a", "b"}, []string{"a", "b", "c"}},
		{"with duplicates", []string{"b", "a", "b", "c", "a"}, []string{"a", "b", "c"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := sortedUnique(tt.values)
			if !slices.Equal(got, tt.want) {
				t.Errorf("sortedUnique(%v) = %v, want %v", tt.values, got, tt.want)
			}
		})
	}
}

func TestHasRuntimeDependencyGroup(t *testing.T) {
	tests := []struct {
		groups []string
		want   bool
	}{
		{nil, false},
		{[]string{}, false},
		{[]string{"devDependencies"}, false},
		{[]string{"dependencies"}, true},
		{[]string{"DEPENDENCIES"}, true},   // case insensitive
		{[]string{" dependencies "}, true}, // whitespace trimmed
		{[]string{"devDependencies", "dependencies"}, true},
	}

	for _, tt := range tests {
		t.Run(fmt.Sprintf("%v", tt.groups), func(t *testing.T) {
			got := manifests.HasRuntimeDependencyGroup(tt.groups)
			if got != tt.want {
				t.Errorf("hasRuntimeDependencyGroup(%v) = %v, want %v", tt.groups, got, tt.want)
			}
		})
	}
}

func TestMarksDirectByDefault(t *testing.T) {
	tests := []struct {
		manager string
		want    bool
	}{
		{"pip", true},
		{"PIP", true},
		{"pipenv", true},
		{"poetry", true},
		{"gem", true},
		{"npm", false},
		{"yarn", false},
		{"go", false},
		{"cargo", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.manager, func(t *testing.T) {
			got := manifests.MarksDirectByDefault(tt.manager)
			if got != tt.want {
				t.Errorf("marksDirectByDefault(%q) = %v, want %v", tt.manager, got, tt.want)
			}
		})
	}
}

func TestNormalizePythonName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"requests", "requests"},
		{"Requests", "requests"},
		{"django_rest_framework", "django-rest-framework"},
		{"  Flask  ", "flask"},
		{"PyYAML", "pyyaml"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizePythonName(tt.input)
			if got != tt.want {
				t.Errorf("normalizePythonName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestNormalizeCrateName(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"tokio", "tokio"},
		{"Tokio", "tokio"},
		{"  serde  ", "serde"},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			got := normalizeCrateName(tt.input)
			if got != tt.want {
				t.Errorf("normalizeCrateName(%q) = %q, want %q", tt.input, got, tt.want)
			}
		})
	}
}

func TestCanonicalPackageKeyFromInput(t *testing.T) {
	tests := []struct {
		name  string
		input osv.PkgInput
		want  string
	}{
		{
			name:  "empty name",
			input: osv.PkgInput{QueryKey: osv.QueryKey{Name: "", Version: "1.0.0"}},
			want:  "",
		},
		{
			name:  "go package",
			input: osv.PkgInput{QueryKey: osv.QueryKey{Name: "github.com/foo/bar", Version: "v1.0.0", Ecosystem: "Go"}},
			want:  "go|github.com/foo/bar|v1.0.0",
		},
		{
			name:  "go package with v2 suffix",
			input: osv.PkgInput{QueryKey: osv.QueryKey{Name: "github.com/foo/bar/v2", Version: "v2.1.0", Ecosystem: "Go"}},
			want:  "go|github.com/foo/bar|v2.1.0",
		},
		{
			name:  "npm package",
			input: osv.PkgInput{QueryKey: osv.QueryKey{Name: "lodash", Version: "4.17.0", Ecosystem: "npm"}},
			want:  "npm|lodash|4.17.0",
		},
		{
			name:  "no ecosystem",
			input: osv.PkgInput{QueryKey: osv.QueryKey{Name: "unknown-pkg", Version: "1.0.0"}},
			want:  "unknown-pkg|1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := canonicalKey(tt.input)
			if got != tt.want {
				t.Errorf("canonicalKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestBuildDirectMap(t *testing.T) {
	tests := []struct {
		name   string
		inputs []osv.PkgInput
		want   map[string]bool
	}{
		{
			name:   "nil inputs",
			inputs: nil,
			want:   nil,
		},
		{
			name:   "empty inputs",
			inputs: []osv.PkgInput{},
			want:   nil,
		},
		{
			name: "no direct deps",
			inputs: []osv.PkgInput{
				{QueryKey: osv.QueryKey{Name: "foo", Version: "1.0.0", Ecosystem: "npm"}, PackageContext: osv.PackageContext{IsDirect: false}},
			},
			want: nil,
		},
		{
			name: "with direct deps",
			inputs: []osv.PkgInput{
				{QueryKey: osv.QueryKey{Name: "foo", Version: "1.0.0", Ecosystem: "npm"}, PackageContext: osv.PackageContext{IsDirect: true}},
				{QueryKey: osv.QueryKey{Name: "bar", Version: "2.0.0", Ecosystem: "npm"}, PackageContext: osv.PackageContext{IsDirect: false}},
			},
			want: map[string]bool{"npm|foo|1.0.0": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := BuildDirectMap(tt.inputs)
			if tt.want == nil && got != nil {
				t.Errorf("BuildDirectMap() = %v, want nil", got)
				return
			}
			if tt.want != nil {
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("BuildDirectMap()[%q] = %v, want %v", k, got[k], v)
					}
				}
			}
		})
	}
}

func TestMergeDirectMaps(t *testing.T) {
	tests := []struct {
		name string
		maps []map[string]bool
		want map[string]bool
	}{
		{
			name: "all nil",
			maps: []map[string]bool{nil, nil},
			want: nil,
		},
		{
			name: "merge two maps",
			maps: []map[string]bool{
				{"a": true},
				{"b": true},
			},
			want: map[string]bool{"a": true, "b": true},
		},
		{
			name: "false values not included",
			maps: []map[string]bool{
				{"a": true, "b": false},
			},
			want: map[string]bool{"a": true},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := MergeDirectMaps(tt.maps...)
			if tt.want == nil && got != nil {
				t.Errorf("MergeDirectMaps() = %v, want nil", got)
				return
			}
			if tt.want != nil {
				for k, v := range tt.want {
					if got[k] != v {
						t.Errorf("MergeDirectMaps()[%q] = %v, want %v", k, got[k], v)
					}
				}
			}
		})
	}
}

func TestConvert_EdgeCases(t *testing.T) {
	t.Run("nil packages", func(t *testing.T) {
		inputs := Convert(nil, Options{})
		if inputs != nil {
			t.Errorf("expected nil for nil input, got %v", inputs)
		}
	})

	t.Run("empty packages", func(t *testing.T) {
		inputs := Convert([]*extractor.Package{}, Options{})
		if inputs != nil {
			t.Errorf("expected nil for empty input, got %v", inputs)
		}
	})

	t.Run("nil package in slice", func(t *testing.T) {
		pkgs := []*extractor.Package{nil, {Name: "foo", Version: "1.0.0"}}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Errorf("expected 1 input, got %d", len(inputs))
		}
	})

	t.Run("empty name filtered", func(t *testing.T) {
		pkgs := []*extractor.Package{{Name: "", Version: "1.0.0"}, {Name: "foo", Version: "1.0.0"}}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Errorf("expected 1 input, got %d", len(inputs))
		}
	})

	t.Run("deduplication", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{Name: "foo", Version: "1.0.0", PURLType: scalpurl.TypeNPM},
			{Name: "foo", Version: "1.0.0", PURLType: scalpurl.TypeNPM},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Errorf("expected 1 deduplicated input, got %d", len(inputs))
		}
	})

	t.Run("golang ecosystem normalization", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{Name: "github.com/foo/bar", Version: "v1.0.0", PURLType: "golang"},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Fatalf("expected 1 input, got %d", len(inputs))
		}
		if inputs[0].Ecosystem != "Go" {
			t.Errorf("expected ecosystem Go, got %s", inputs[0].Ecosystem)
		}
	})

	t.Run("github ecosystem normalization", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{Name: "actions/checkout", Version: "v4", PURLType: "github"},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Fatalf("expected 1 input, got %d", len(inputs))
		}
		if inputs[0].Ecosystem != "GitHub Actions" {
			t.Errorf("expected ecosystem GitHub Actions, got %s", inputs[0].Ecosystem)
		}
	})
}

func TestAppendGroupLabel(t *testing.T) {
	tests := []struct {
		name     string
		existing []string
		label    string
		want     []string
	}{
		{"add to nil", nil, "dev", []string{"dev"}},
		{"add new label", []string{"prod"}, "dev", []string{"prod", "dev"}},
		{"skip duplicate same case", []string{"dev"}, "dev", []string{"dev"}},
		{"skip duplicate different case", []string{"DEV"}, "dev", []string{"DEV"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendGroupLabel(tt.existing, tt.label)
			if !slices.Equal(got, tt.want) {
				t.Errorf("appendGroupLabel(%v, %q) = %v, want %v", tt.existing, tt.label, got, tt.want)
			}
		})
	}
}

func TestConvert_LayerDetails(t *testing.T) {
	t.Run("preserves layer details from SCALIBR package", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{
				Name:     "openssl",
				Version:  "1.1.1k",
				PURLType: "deb",
				LayerMetadata: &extractor.LayerMetadata{
					Index:          2,
					DiffID:         "sha256:abc123",
					ChainID:        "sha256:def456",
					Command:        "RUN apt-get install openssl",
					BaseImageIndex: 1,
				},
			},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Fatalf("expected 1 input, got %d", len(inputs))
		}
		if inputs[0].LayerDetails == nil {
			t.Fatal("expected LayerDetails to be preserved, got nil")
		}
		ld := inputs[0].LayerDetails
		if ld.Index != 2 {
			t.Errorf("LayerDetails.Index = %d, want 2", ld.Index)
		}
		if ld.DiffId != "sha256:abc123" {
			t.Errorf("LayerDetails.DiffId = %q, want sha256:abc123", ld.DiffId)
		}
		if ld.ChainId != "sha256:def456" {
			t.Errorf("LayerDetails.ChainId = %q, want sha256:def456", ld.ChainId)
		}
		if ld.Command != "RUN apt-get install openssl" {
			t.Errorf("LayerDetails.Command = %q, want RUN apt-get install openssl", ld.Command)
		}
		if !ld.InBaseImage {
			t.Error("LayerDetails.InBaseImage = false, want true")
		}
	})

	t.Run("nil layer details remains nil", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{
				Name:          "lodash",
				Version:       "4.17.21",
				PURLType:      scalpurl.TypeNPM,
				LayerMetadata: nil,
			},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Fatalf("expected 1 input, got %d", len(inputs))
		}
		if inputs[0].LayerDetails != nil {
			t.Error("expected LayerDetails to be nil for non-container package")
		}
	})

	t.Run("first layer details wins on dedup", func(t *testing.T) {
		pkgs := []*extractor.Package{
			{
				Name:     "curl",
				Version:  "7.80.0",
				PURLType: "deb",
				LayerMetadata: &extractor.LayerMetadata{
					Index:          1,
					BaseImageIndex: 1,
				},
			},
			{
				Name:     "curl",
				Version:  "7.80.0",
				PURLType: "deb",
				LayerMetadata: &extractor.LayerMetadata{
					Index:          5,
					BaseImageIndex: 0,
				},
			},
		}
		inputs := Convert(pkgs, Options{})
		if len(inputs) != 1 {
			t.Fatalf("expected 1 deduplicated input, got %d", len(inputs))
		}
		if inputs[0].LayerDetails == nil {
			t.Fatal("expected LayerDetails to be preserved")
		}
		// First package's layer details should be kept
		if inputs[0].LayerDetails.Index != 1 {
			t.Errorf("expected first layer Index (1), got %d", inputs[0].LayerDetails.Index)
		}
		if !inputs[0].LayerDetails.InBaseImage {
			t.Error("expected first InBaseImage (true)")
		}
	})
}
