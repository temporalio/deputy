package mise

import (
	"maps"
	"reflect"
	"testing"
)

func TestIsConfigPath(t *testing.T) {
	tests := []struct {
		path   string
		want   Format
		wantOK bool
	}{
		{"mise.toml", FormatTOML, true},
		{".mise.toml", FormatTOML, true},
		{"mise.local.toml", FormatTOML, true},
		{"mise.test.toml", FormatTOML, true},
		{"mise.test.local.toml", FormatTOML, true},
		{".mise.production.toml", FormatTOML, true},
		{".mise.production.local.toml", FormatTOML, true},
		{"sub/dir/mise.toml", FormatTOML, true},
		{".tool-versions", FormatToolVersions, true},
		{"repo/.tool-versions", FormatToolVersions, true},
		{".config/mise/config.toml", FormatTOML, true},
		{".config/mise/config.local.toml", FormatTOML, true},
		{".config/mise/config.test.toml", FormatTOML, true},
		{".config/mise/config.test.local.toml", FormatTOML, true},
		{"a/b/.config/mise/config.toml", FormatTOML, true},
		{"a/b/.config/mise/config.prod.toml", FormatTOML, true},
		{".config/mise.toml", FormatTOML, true},
		{"mise/config.toml", FormatTOML, true},
		{"mise/config.local.toml", FormatTOML, true},
		{"mise/config.dev.toml", FormatTOML, true},
		{".mise/config.qa.local.toml", FormatTOML, true},
		{".mise/config.toml", FormatTOML, true},
		{".config/mise/conf.d/rust.toml", FormatTOML, true},
		{"mise.foo.bar.toml", "", false},
		{".config/mise/config.foo.bar.baz.toml", "", false},
		{"go.mod", "", false},
		{"config.toml", "", false},
		{"random.toml", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got, ok := IsConfigPath(tt.path)
			if ok != tt.wantOK || got != tt.want {
				t.Fatalf("IsConfigPath(%q) = (%q, %v), want (%q, %v)", tt.path, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestLockfilePath pins the mapping against mise's real behavior, captured
// with `mise lock --dry-run` (which prints the lockfile it targets) on mise
// 2026.7.3 for each layout below.
func TestLockfilePath(t *testing.T) {
	tests := map[string]string{
		// Flat configs: the lock is named for the config, minus a leading dot.
		"mise.toml":             "mise.lock",
		".mise.toml":            "mise.lock",
		"a/b/mise.toml":         "a/b/mise.lock",
		"a/b/.mise.toml":        "a/b/mise.lock",
		"mise.production.toml":  "mise.production.lock",
		".mise.production.toml": "mise.production.lock",
		"mise.local.toml":       "mise.local.lock",
		".mise.local.toml":      "mise.local.lock",
		"sub/proj/.mise.toml":   "sub/proj/mise.lock",
		".config/mise.toml":     ".config/mise.lock",
		"./mise.toml":           "mise.lock",
		"/abs/path/.mise.toml":  "/abs/path/mise.lock",
		"a\\b\\.mise.toml":      "a/b/mise.lock",
		// A config.toml inside a mise directory is named for the directory,
		// carrying over any env/local segments from the config's basename.
		".config/mise/config.toml":                  ".config/mise/mise.lock",
		"mise/config.toml":                          "mise/mise.lock",
		"a/.config/mise/config.toml":                "a/.config/mise/mise.lock",
		".mise/config.toml":                         ".mise/mise.lock",
		"a/.mise/config.toml":                       "a/.mise/mise.lock",
		".config/mise/config.production.toml":       ".config/mise/mise.production.lock",
		".mise/config.production.toml":              ".mise/mise.production.lock",
		"mise/config.production.toml":               "mise/mise.production.lock",
		".config/mise/config.local.toml":            ".config/mise/mise.local.lock",
		".mise/config.local.toml":                   ".mise/mise.local.lock",
		".config/mise/config.production.local.toml": ".config/mise/mise.production.local.lock",
		// A basename that merely starts with "config" is not the directory's
		// config file, so it keeps its own name.
		".config/mise/configuration.toml": ".config/mise/configuration.lock",
		// conf.d drop-ins share the enclosing mise directory's lockfile.
		".config/mise/conf.d/tools.toml": ".config/mise/mise.lock",
		"mise/conf.d/10-tools.toml":      "mise/mise.lock",
		// Non-TOML configs are never locked.
		".tool-versions": "",
		"mise.json":      "",
		".toml":          "",
	}
	for in, want := range tests {
		if got := LockfilePath(in); got != want {
			t.Errorf("LockfilePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSplitBackend(t *testing.T) {
	tests := []struct {
		key, backend, name string
	}{
		{"node", "", "node"},
		{"npm:prettier", "npm", "prettier"},
		{"cargo:ripgrep", "cargo", "ripgrep"},
		{"conda:python", "conda", "python"},
		{"forgejo:owner/repo", "forgejo", "owner/repo"},
		{"gitlab:owner/repo", "gitlab", "owner/repo"},
		{"s3:bucket/key", "s3", "bucket/key"},
		{"pipx:black", "pipx", "black"},
		{"go:golang.org/x/tools/cmd/goimports", "go", "golang.org/x/tools/cmd/goimports"},
		{"unknownbackend:thing", "", "unknownbackend:thing"},
		// Trailing tool-option groups are stripped from the name.
		{"ubi:cli/cli[exe=gh]", "ubi", "cli/cli"},
		{"ubi:owner/repo[exe=foo,matching=musl]", "ubi", "owner/repo"},
		{"github:cli/cli[provider=github]", "github", "cli/cli"},
		{"node[arch=arm64]", "", "node"},
	}
	for _, tt := range tests {
		b, n := SplitBackend(tt.key)
		if b != tt.backend || n != tt.name {
			t.Errorf("SplitBackend(%q) = (%q,%q), want (%q,%q)", tt.key, b, n, tt.backend, tt.name)
		}
	}
}

func TestToolOptions(t *testing.T) {
	tests := []struct {
		key  string
		want map[string]string
	}{
		{"ubi:cli/cli", nil},
		{"ubi:cli/cli[exe=gh]", map[string]string{"exe": "gh"}},
		{"ubi:owner/repo[exe=foo,matching=musl]", map[string]string{"exe": "foo", "matching": "musl"}},
		{"ubi:owner/repo[provider=gitlab]", map[string]string{"provider": "gitlab"}},
		{"ubi:owner/repo[verbose]", map[string]string{"verbose": ""}},
		{"ubi:owner/repo[]", nil},
	}
	for _, tt := range tests {
		got := ToolOptions(tt.key)
		if !maps.Equal(got, tt.want) {
			t.Errorf("ToolOptions(%q) = %v, want %v", tt.key, got, tt.want)
		}
	}
}

func TestIsExactVersion(t *testing.T) {
	exact := []string{"22.5.0", "v1.24.3", "1.9.5", "3.12.0-rc1", "20.11.0+build", "temurin-21.0.5+11.0.LTS", "2024.8.7"}
	fuzzy := []string{"20", "1.7", "latest", "lts", "stable", "", "^1.2.3", "~2.0", ">=1.0", "1.x", "node", "ref:abc123", "prefix:20", "sub-2", "temurin-21", "33.1"}
	for _, v := range exact {
		if !IsExactVersion(v) {
			t.Errorf("IsExactVersion(%q) = false, want true", v)
		}
	}
	for _, v := range fuzzy {
		if IsExactVersion(v) {
			t.Errorf("IsExactVersion(%q) = true, want false", v)
		}
	}
}

func TestIsConcreteVersion(t *testing.T) {
	// Concrete: a real resolved version (>= major.minor), including partial-but-
	// final forms like protobuf "33.1" that IsExactVersion rejects.
	concrete := []string{"22.5.0", "33.1", "3.12.13", "v1.2", "temurin-21.0.5+11.0.LTS", "2025.1.1"}
	notConcrete := []string{
		"", "20", "latest", "lts", "system", "^1.2.3", ">=1.0", "ref:abc", "prefix:20", "node",
		// A checkout is not a release, however version-shaped its path.
		"path:/opt/go-1.24.3", "file:../go-1.24.3",
	}
	for _, v := range concrete {
		if !IsConcreteVersion(v) {
			t.Errorf("IsConcreteVersion(%q) = false, want true", v)
		}
	}
	for _, v := range notConcrete {
		if IsConcreteVersion(v) {
			t.Errorf("IsConcreteVersion(%q) = true, want false", v)
		}
	}
}

func TestBackendPURL(t *testing.T) {
	tests := []struct {
		backend, tool, version, want string
	}{
		{"npm", "lodash", "4.17.20", "pkg:npm/lodash@4.17.20"},
		{"npm", "@vue/cli", "5.0.0", "pkg:npm/%40vue/cli@5.0.0"},
		{"cargo", "ripgrep", "14.1.1", "pkg:cargo/ripgrep@14.1.1"},
		{"pipx", "black", "24.3.0", "pkg:pypi/black@24.3.0"},
		{"pipx", "Django", "5.0.0", "pkg:pypi/django@5.0.0"}, // PyPI case-insensitive -> lowercased
		{"pip", "Ansible", "9.0.0", "pkg:pypi/ansible@9.0.0"},
		{"gem", "rails", "7.1.0", "pkg:gem/rails@7.1.0"},
		{"dotnet", "dotnet-ef", "8.0.0", "pkg:nuget/dotnet-ef@8.0.0"},
		{"aqua", "BurntSushi/ripgrep", "14.1.1", ""}, // no registry mapping
		{"", "node", "20.11.0", ""},                  // core runtime, no mapping
		{"go", "x/tools", "1.0.0", ""},               // go module paths intentionally unmapped
	}
	for _, tt := range tests {
		if got := BackendPURL(tt.backend, tt.tool, tt.version); got != tt.want {
			t.Errorf("BackendPURL(%q,%q,%q) = %q, want %q", tt.backend, tt.tool, tt.version, got, tt.want)
		}
	}
}

func TestScanPURL(t *testing.T) {
	// Round-trip case: derived purely from a pkg:mise PURL name (as it appears
	// in an SBOM component), no metadata needed.
	if got := ScanPURL("mise", "npm:lodash", "4.17.20"); got != "pkg:npm/lodash@4.17.20" {
		t.Errorf("ScanPURL(mise, npm:lodash) = %q", got)
	}
	if got := ScanPURL("asdf", "nodejs", "20.11.0"); got != "" {
		t.Errorf("ScanPURL(asdf runtime) = %q, want empty", got)
	}
	if got := ScanPURL("mise", "node", "20.11.0"); got != "" {
		t.Errorf("ScanPURL(mise core runtime) = %q, want empty", got)
	}
	if got := ScanPURL("npm", "lodash", "4.17.20"); got != "" {
		t.Errorf("ScanPURL(non-mise type) = %q, want empty", got)
	}
}

func TestRuntimeScanCoords(t *testing.T) {
	tests := []struct {
		name                    string
		purlType, tool, version string
		want                    []ScanCoord
	}{
		{
			name: "go runtime maps to stdlib+toolchain", purlType: "mise", tool: "go", version: "1.20.0",
			want: []ScanCoord{
				{Ecosystem: "Go", Name: "stdlib", Version: "1.20.0", PURL: "pkg:golang/stdlib@1.20.0"},
				{Ecosystem: "Go", Name: "toolchain", Version: "1.20.0", PURL: "pkg:golang/toolchain@1.20.0"},
			},
		},
		{
			name: "asdf golang maps too", purlType: "asdf", tool: "golang", version: "1.21.0",
			want: []ScanCoord{
				{Ecosystem: "Go", Name: "stdlib", Version: "1.21.0", PURL: "pkg:golang/stdlib@1.21.0"},
				{Ecosystem: "Go", Name: "toolchain", Version: "1.21.0", PURL: "pkg:golang/toolchain@1.21.0"},
			},
		},
		{name: "fuzzy version not matchable", purlType: "mise", tool: "go", version: "1.20", want: nil},
		{name: "other runtime has no OSV ecosystem", purlType: "mise", tool: "node", version: "20.0.0", want: nil},
		{name: "backend tool is not a runtime", purlType: "mise", tool: "npm:lodash", version: "1.0.0", want: nil},
		{name: "non-mise type", purlType: "npm", tool: "go", version: "1.20.0", want: nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := RuntimeScanCoords(tt.purlType, tt.tool, tt.version); !reflect.DeepEqual(got, tt.want) {
				t.Errorf("RuntimeScanCoords(%q,%q,%q) = %+v, want %+v", tt.purlType, tt.tool, tt.version, got, tt.want)
			}
		})
	}
}

func TestLockfileLookup(t *testing.T) {
	lf, err := ParseLock("mise.lock", []byte(sampleLock)) // node, ripgrep
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name        string
		spec        ToolSpec
		version     string
		wantVersion string // "" => expect no match (nil)
	}{
		{"exact by short name", ToolSpec{Name: "node", Key: "node"}, "20.11.0", "20.11.0"},
		{"fuzzy declared version falls back to sole entry", ToolSpec{Name: "node", Key: "node"}, "20", "20.11.0"},
		{"backend-prefixed key resolves by short name", ToolSpec{Name: "ripgrep", Key: "aqua:BurntSushi/ripgrep"}, "14.1.1", "14.1.1"},
		{"missing tool", ToolSpec{Name: "missing", Key: "missing"}, "1.0.0", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := lf.Lookup(tt.spec, tt.version, nil)
			switch {
			case tt.wantVersion == "":
				if lt != nil {
					t.Errorf("Lookup = %+v, want nil", lt)
				}
			case lt == nil || lt.Version != tt.wantVersion:
				t.Errorf("Lookup = %+v, want version %q", lt, tt.wantVersion)
			}
		})
	}

	var nilLF *Lockfile
	if nilLF.Lookup(ToolSpec{Name: "node"}, "20.11.0", nil) != nil {
		t.Error("nil lockfile Lookup should return nil")
	}
}

// TestLockfileLookupClaimedKeys pins that a lock entry keyed by a tool's short
// name is not borrowed when the config declares that name as a separate tool.
// Sharing it lets a backend-qualified tool inherit the other tool's version,
// which after a fix reports the freshly updated tool at the old version.
func TestNameClaims(t *testing.T) {
	tests := []struct {
		name  string
		tools []ToolSpec
		want  map[string]int
	}{
		{
			name:  "a bare declaration claims one name",
			tools: []ToolSpec{{Key: "node", Name: "node"}},
			want:  map[string]int{"node": 1},
		},
		{
			name:  "a qualified declaration claims its key and its short name",
			tools: []ToolSpec{{Key: "npm:node", Name: "node"}},
			want:  map[string]int{"npm:node": 1, "node": 1},
		},
		{
			name:  "a bare and a qualified declaration contest the short name",
			tools: []ToolSpec{{Key: "npm:node", Name: "node"}, {Key: "node", Name: "node"}},
			want:  map[string]int{"npm:node": 1, "node": 2},
		},
		{
			name:  "two qualified declarations contest the short name",
			tools: []ToolSpec{{Key: "npm:foo", Name: "foo"}, {Key: "ubi:foo", Name: "foo"}},
			want:  map[string]int{"npm:foo": 1, "ubi:foo": 1, "foo": 2},
		},
		{
			name:  "options do not create a second claimant",
			tools: []ToolSpec{{Key: "ubi:cli/cli[exe=gh]", Name: "cli/cli"}},
			want:  map[string]int{"ubi:cli/cli[exe=gh]": 1, "cli/cli": 1},
		},
		{
			name:  "no declarations claim nothing",
			tools: nil,
			want:  map[string]int{},
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := NameClaims(tt.tools); !maps.Equal(got, tt.want) {
				t.Errorf("NameClaims = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestLockfileLookupClaimedKeys(t *testing.T) {
	const lock = `[[tools.node]]
version = "20.11.0"
backend = "core:node"
`
	lf, err := ParseLock("mise.lock", []byte(lock))
	if err != nil {
		t.Fatal(err)
	}
	qualified := ToolSpec{Name: "node", Key: "npm:node"}
	sole := NameClaims([]ToolSpec{qualified})
	bare := ToolSpec{Name: "node", Key: "node"}
	contestedByBare := NameClaims([]ToolSpec{qualified, bare})
	contestedByQualified := NameClaims([]ToolSpec{qualified, {Name: "node", Key: "ubi:node"}})

	tests := []struct {
		name        string
		spec        ToolSpec
		version     string
		claims      map[string]int
		wantVersion string // "" => expect no match
	}{
		{
			name: "short name free to match", spec: qualified, version: "20.12.0",
			claims: sole, wantVersion: "20.11.0",
		},
		{
			name: "short name claimed by a bare declaration", spec: qualified, version: "20.12.0",
			claims: contestedByBare, wantVersion: "",
		},
		{
			name: "short name claimed by another qualified declaration", spec: qualified, version: "20.12.0",
			claims: contestedByQualified, wantVersion: "",
		},
		{
			name: "the other qualified declaration is refused too",
			spec: ToolSpec{Name: "node", Key: "ubi:node"}, version: "20.12.0",
			claims: contestedByQualified, wantVersion: "",
		},
		{
			name: "exact version match also refused when claimed", spec: qualified, version: "20.11.0",
			claims: contestedByBare, wantVersion: "",
		},
		{
			name: "a tool always matches its own key", spec: bare, version: "20.11.0",
			claims: contestedByBare, wantVersion: "20.11.0",
		},
		{
			name: "no config context keeps the fallback", spec: qualified, version: "20.12.0",
			claims: nil, wantVersion: "20.11.0",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			lt := lf.Lookup(tt.spec, tt.version, tt.claims)
			switch {
			case tt.wantVersion == "":
				if lt != nil {
					t.Errorf("Lookup = %+v, want nil", lt)
				}
			case lt == nil || lt.Version != tt.wantVersion:
				t.Errorf("Lookup = %+v, want version %q", lt, tt.wantVersion)
			}
		})
	}
}

func TestParseTOML(t *testing.T) {
	data := []byte(`
[tools]
node = "22.5.0"
python = ["3.11", "3.12"]
"npm:prettier" = "latest"
ripgrep = { version = "14.1.0" }
go = { version = "1.24", postinstall = "echo hi" }
java = { version = ["21.0.5", "17.0.13"] }

[settings]
lockfile = true
minimum_release_age = "14d"
slsa = false

[settings.aqua]
cosign = true
`)
	cfg, err := Parse("mise.toml", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Format != FormatTOML {
		t.Errorf("format = %q", cfg.Format)
	}

	byKey := map[string]ToolSpec{}
	for _, ts := range cfg.Tools {
		byKey[ts.Key] = ts
	}
	if got := byKey["node"].Versions; !reflect.DeepEqual(got, []string{"22.5.0"}) {
		t.Errorf("node versions = %v", got)
	}
	if got := byKey["python"].Versions; !reflect.DeepEqual(got, []string{"3.11", "3.12"}) {
		t.Errorf("python versions = %v", got)
	}
	if ts := byKey["npm:prettier"]; ts.Backend != "npm" || ts.Name != "prettier" {
		t.Errorf("npm:prettier backend/name = %q/%q", ts.Backend, ts.Name)
	}
	if got := byKey["ripgrep"].Versions; !reflect.DeepEqual(got, []string{"14.1.0"}) {
		t.Errorf("ripgrep versions = %v", got)
	}
	if got := byKey["go"].Versions; !reflect.DeepEqual(got, []string{"1.24"}) {
		t.Errorf("go versions = %v", got)
	}
	// An inline table whose version is an array surfaces every version, not
	// just the first.
	if got := byKey["java"].Versions; !reflect.DeepEqual(got, []string{"21.0.5", "17.0.13"}) {
		t.Errorf("java versions = %v, want all entries from the inline-table array", got)
	}

	s := cfg.Settings
	if s.Lockfile == nil || !*s.Lockfile {
		t.Errorf("lockfile = %v, want true", s.Lockfile)
	}
	if s.MinimumReleaseAge != "14d" {
		t.Errorf("minimum_release_age = %q", s.MinimumReleaseAge)
	}
	if s.SLSA == nil || *s.SLSA {
		t.Errorf("slsa = %v, want explicit false", s.SLSA)
	}
	if s.AquaCosign == nil || !*s.AquaCosign {
		t.Errorf("aqua.cosign = %v, want true", s.AquaCosign)
	}
	if s.GithubAttestations != nil {
		t.Errorf("github_attestations = %v, want nil (unset)", s.GithubAttestations)
	}
}

// TestParseToolsArrayOfTables pins the array-of-tables form of a tool
// declaration, `[[tools.<name>]]` with the fields below it. It is ordinary
// TOML for the value shapes the [tools] table already accepts, and mise reads
// it: with a mise.toml holding `[[tools.go]]` and `version = "1.22.12"`, mise
// 2026.7.3 reports
//
//	go  1.22.12 (missing)  /private/tmp/misearr/mise.toml  1.22.12
//
// and repeating the header reports both entries. A parser that skips the form
// inventories the tool with no versions at all, so the toolchain mise resolves
// is a toolchain Deputy never scans.
func TestParseToolsArrayOfTables(t *testing.T) {
	tests := []struct {
		name    string
		content string
		want    map[string][]string
	}{
		{
			name:    "single entry",
			content: "[[tools.go]]\nversion = \"1.22.12\"\n",
			want:    map[string][]string{"go": {"1.22.12"}},
		},
		{
			name:    "repeated entries request both versions",
			content: "[[tools.go]]\nversion = \"1.21.13\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			want:    map[string][]string{"go": {"1.21.13", "1.22.12"}},
		},
		{
			name:    "an entry with options",
			content: "[[tools.\"npm:prettier\"]]\nversion = \"3.3.3\"\npostinstall = \"echo hi\"\n",
			want:    map[string][]string{"npm:prettier": {"3.3.3"}},
		},
		{
			name:    "an entry whose version is an array",
			content: "[[tools.java]]\nversion = [\"21.0.5\", \"17.0.13\"]\n",
			want:    map[string][]string{"java": {"21.0.5", "17.0.13"}},
		},
		{
			name:    "an entry beside a plain table declaration",
			content: "[tools]\nnode = \"20.11.0\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			want:    map[string][]string{"node": {"20.11.0"}, "go": {"1.22.12"}},
		},
		{
			name:    "an entry with no version requests nothing",
			content: "[[tools.go]]\nbackend = \"core:go\"\n",
			want:    map[string][]string{"go": nil},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := Parse("mise.toml", []byte(tt.content))
			if err != nil {
				t.Fatalf("Parse: %v", err)
			}
			got := make(map[string][]string, len(cfg.Tools))
			for _, spec := range cfg.Tools {
				got[spec.Key] = spec.Versions
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("tools = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestParseToolVersions(t *testing.T) {
	data := []byte("node 22.5.0\npython 3.11 3.12  # comment\n# full comment\nnpm:prettier latest\n")
	cfg, err := Parse(".tool-versions", data)
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if cfg.Format != FormatToolVersions {
		t.Errorf("format = %q", cfg.Format)
	}
	if len(cfg.Tools) != 3 {
		t.Fatalf("tools = %d, want 3: %+v", len(cfg.Tools), cfg.Tools)
	}
	byKey := map[string]ToolSpec{}
	for _, ts := range cfg.Tools {
		byKey[ts.Key] = ts
	}
	if got := byKey["python"].Versions; !reflect.DeepEqual(got, []string{"3.11", "3.12"}) {
		t.Errorf("python versions = %v", got)
	}
	if byKey["npm:prettier"].Backend != "npm" {
		t.Errorf("npm:prettier backend = %q", byKey["npm:prettier"].Backend)
	}
}

// TestDeclaredVersion pins the reading of mise's request grammar that decides
// whether a declaration's text rules out a given release. Requests mise
// resolves at install time carry no version; everything else does, including
// the vendor-prefixed exact releases mise publishes for Java, which begin with
// a letter and are still exact.
func TestDeclaredVersion(t *testing.T) {
	tests := []struct {
		request string
		want    string
		wantOK  bool
	}{
		{"1.24.3", "1.24.3", true},
		{"20", "20", true},
		{"20.11", "20.11", true},
		{"v1.24.3", "v1.24.3", true},
		{"temurin-21.0.6+7", "temurin-21.0.6+7", true},
		{"temurin-21", "temurin-21", true},
		{"  1.24.3  ", "1.24.3", true},
		{"prefix:20", "20", true},
		// A sub- request resolves below the line it names, so the version it
		// constrains is the subtracted one, not the base. Each row below is
		// what mise 2026.7.3 installs for the request, read from
		// `mise ls --current` over a real config:
		//   sub-1:20        -> 19.9.0    (the 19 line)
		//   sub-1:20.11     -> 19.9.0    (the 19 line)
		//   sub-1:20.11.1   -> 19.9.0    (the 19 line)
		//   sub-0.1:20.11   -> 20.10.0   (the 20.10 line)
		//   sub-0.1:20.11.1 -> 20.10.0   (the 20.10 line)
		//   sub-2:24        -> 22.23.2   (the 22 line)
		// The subtrahend is applied component-wise to the base as written and
		// truncated to its own length, which is why sub-1:20.11 governs 19 and
		// not 19.11.
		{"sub-1:20", "19", true},
		{"sub-1:20.11", "19", true},
		{"sub-1:20.11.1", "19", true},
		{"sub-0.1:20.11", "20.10", true},
		{"sub-0.1:20.11.1", "20.10", true},
		{"sub-2:24", "22", true},
		// A subtrahend longer than the base is truncated to the base's
		// components, so it constrains exactly what the base does:
		//   sub-0.1:20   -> 20.20.2  (the 20 line, same as "20")
		//   sub-0.0.1:20 -> 20.20.2
		{"sub-0.1:20", "20", true},
		{"sub-0.0.1:20", "20", true},
		// Subtracting past zero floors there rather than wrapping:
		//   sub-30:20 -> 0.12.18 (the 0 line)
		{"sub-30:20", "0", true},
		{"latest", "", false},
		{"lts", "", false},
		{"stable", "", false},
		{"system", "", false},
		{"", "", false},
		// The subtracted line is only computable when the base names one.
		// Over a channel or a vendor-prefixed release there is nothing to
		// subtract from without resolving it first, so the request rules
		// nothing out and stays rewritable.
		{"sub-2:lts", "", false},
		{"sub-1:temurin-21", "", false},
		{"sub-:20", "", false},
		{"sub-x:20", "", false},
		{"prefix:latest", "", false},
		{"ref:main", "", false},
		{"ref:v1.2.3", "", false},
		{"path:/opt/go-1.24.3", "", false},
		{"file:../toolchains/go", "", false},
		{"gallium", "", false},
	}
	for _, tt := range tests {
		t.Run(tt.request, func(t *testing.T) {
			got, ok := DeclaredVersion(tt.request)
			if got != tt.want || ok != tt.wantOK {
				t.Errorf("DeclaredVersion(%q) = (%q, %v), want (%q, %v)", tt.request, got, ok, tt.want, tt.wantOK)
			}
		})
	}
}

// TestSameVersion pins the equality used to decide whether a declared or
// locked version is one the finding names. The two sides come from different
// vocabularies: Deputy reports the Go runtime with the module convention
// ("v1.22.12") while a mise config and its lockfile write the release
// ("1.22.12"). Comparing them byte-for-byte makes a fix Deputy just emitted
// unapplicable, so the leading "v" is ignored on both sides, exactly as
// SelectorMatches already ignores it.
func TestSameVersion(t *testing.T) {
	tests := []struct {
		a, b string
		want bool
	}{
		{"1.22.12", "1.22.12", true},
		{"v1.22.12", "1.22.12", true},
		{"1.22.12", "v1.22.12", true},
		{"V1.22.12", "v1.22.12", true},
		{"  v1.22.12 ", "1.22.12", true},
		{"temurin-21.0.6+7", "temurin-21.0.6+7", true},
		// Not equal: a partial selector is not the release beneath it, which
		// is SelectorMatches's job and not this one.
		{"20", "20.11.0", false},
		{"1.22.12", "1.25.1", false},
		{"v1.22.12", "1.22.13", false},
		// A leading "v" that is not a version prefix stays part of the name.
		{"vault", "ault", false},
		{"", "", true},
	}
	for _, tt := range tests {
		t.Run(tt.a+"/"+tt.b, func(t *testing.T) {
			if got := SameVersion(tt.a, tt.b); got != tt.want {
				t.Errorf("SameVersion(%q, %q) = %v, want %v", tt.a, tt.b, got, tt.want)
			}
		})
	}
}

// TestSelectorMatches pins mise's matching rule against what a declaration
// actually resolves to. Every row cites `mise ls --current` over a real config
// on mise 2026.7.3, not `mise ls-remote`: ls-remote is a loose listing filter
// that prints 25 releases for node@20.1, while a config declaring 20.1
// installs 20.1.0. Resolution is what remediation is reasoning about, so
// resolution is what this table records.
func TestSelectorMatches(t *testing.T) {
	tests := []struct {
		name    string
		request string
		version string
		want    bool
	}{
		// node = "20.1" -> ls --current 20.1.0; lock --dry-run node@20.1.0.
		{"partial governs its own line", "20.1", "20.1.0", true},
		{"partial does not reach a longer neighbour", "20.1", "20.19.6", false},
		// node = "20.11" -> ls --current 20.11.1.
		{"minor selector", "20.11", "20.11.1", true},
		{"minor selector stops at its line", "20.11", "20.19.6", false},
		// node = "20" -> ls --current 20.20.2.
		{"major selector", "20", "20.20.2", true},
		// node = "2" -> ls --current reports "2", unresolved and missing.
		{"a selector that resolves to nothing", "2", "26.7.0", false},

		{"exact", "20.11.0", "20.11.0", true},
		{"vendor-prefixed exact", "temurin-21.0.6+7", "temurin-21.0.6+7", true},
		{"vendor-prefixed partial", "temurin-21", "temurin-21.0.6+7", true},
		{"v-prefixed request", "v20", "20.11.0", true},
		{"v-prefixed version", "20", "v20.11.0", true},
		{"surrounding space", " 20 ", "20.11.0", true},

		{"different line", "22", "20.11.0", false},
		{"stale exact version", "1.25.1", "1.22.12", false},
		{"request longer than the version", "20.11.0", "20.11", false},
		{"another vendor", "zulu-21.0.6+7", "temurin-21.0.6+7", false},
		{"vendor-prefixed on another line", "temurin-22", "temurin-21.0.6+7", false},
		{"a v that is not a version prefix", "vault", "1.0.0", false},
		// An empty request is not a licence to match; callers that mean
		// "no version named" go through DeclaredVersion first.
		{"empty request", "", "20.11.0", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := SelectorMatches(tt.request, tt.version); got != tt.want {
				t.Errorf("SelectorMatches(%q, %q) = %v, want %v", tt.request, tt.version, got, tt.want)
			}
		})
	}
}
