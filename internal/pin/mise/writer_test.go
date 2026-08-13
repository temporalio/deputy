package mise

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/pin"
)

func TestRewriteMiseVersions(t *testing.T) {
	const input = `# Project toolchain
[tools] # primary tool table
node = "20"            # LTS line
python = ["3.11", "3.12"]
"aqua:single" = ["33"]
"npm:prettier" = "latest"
ripgrep = { version = "14" }
terraform = "1.9.8"

[tools.go] # child table
version = "1.20"

[tools."cargo:ripgrep"] # quoted child table
version = "14"
postinstall = "rg --version"

[settings]
# node should NOT be touched here
node_thing = "20"
`
	const want = `# Project toolchain
[tools] # primary tool table
node = "20.11.0"            # LTS line
python = ["3.11", "3.12"]
"aqua:single" = ["33.1"]
"npm:prettier" = "3.3.0"
ripgrep = { version = "14.1.1" }
terraform = "1.9.8"

[tools.go] # child table
version = "1.20.1"

[tools."cargo:ripgrep"] # quoted child table
version = "14.1.1"
postinstall = "rg --version"

[settings]
# node should NOT be touched here
node_thing = "20"
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mise.toml"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	updates := []pin.Update{
		{Name: "node", PinnedValue: "20.11.0"},
		{Name: "aqua:single", PinnedValue: "33.1"},
		{Name: "npm:prettier", PinnedValue: "3.3.0"},
		{Name: "ripgrep", PinnedValue: "14.1.1"},
		{Name: "go", PinnedValue: "1.20.1"},
		{Name: "cargo:ripgrep", PinnedValue: "14.1.1"},
	}
	if err := rewriteMiseVersions(root, "mise.toml", updates); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, "mise.toml"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRewriteMiseVersionsErrorsWhenUpdateNotApplied(t *testing.T) {
	const input = `[tools]
node = ["20", "22"]
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mise.toml"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = rewriteMiseVersions(root, "mise.toml", []pin.Update{{Name: "node", PinnedValue: "20.11.0"}})
	if err == nil {
		t.Fatal("expected rewrite error")
	}
	if !strings.Contains(err.Error(), "node") {
		t.Fatalf("rewrite error = %v, want missing tool name", err)
	}
}

func TestRewriteToolVersions(t *testing.T) {
	const input = `# Toolchain
nodejs 22.14.0
golang 1.26.2   # keep this comment
pnpm 10.10.0
python 3.11 3.12
`
	const want = `# Toolchain
nodejs 22.14.0
golang 1.27.0   # keep this comment
pnpm 10.10.0
python 3.11 3.12
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tool-versions"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	updates := []pin.Update{
		{Name: "golang", PinnedValue: "1.27.0"},
	}
	if err := rewriteToolVersions(root, ".tool-versions", updates); err != nil {
		t.Fatalf("rewrite: %v", err)
	}
	got, err := os.ReadFile(filepath.Join(dir, ".tool-versions"))
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != want {
		t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
	}
}

func TestRewriteToolVersionsErrorsWhenUpdateNotApplied(t *testing.T) {
	const input = `python 3.11 3.12
`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, ".tool-versions"), []byte(input), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = rewriteToolVersions(root, ".tool-versions", []pin.Update{{Name: "python", PinnedValue: "3.11.9"}})
	if err == nil {
		t.Fatal("expected rewrite error")
	}
	if !strings.Contains(err.Error(), "python") {
		t.Fatalf("rewrite error = %v, want missing tool name", err)
	}
}

func TestReplaceVersionInValue(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		pinned      string
		want        string
		wantChanged bool
	}{
		{"scalar", ` "20"`, "20.11.0", ` "20.11.0"`, true},
		{"scalar with comment", ` "20"  # note`, "20.11.0", ` "20.11.0"  # note`, true},
		{"bare", ` 20`, "20.11.0", ` "20.11.0"`, true},
		{"single array", ` ["20"]`, "20.11.0", ` ["20.11.0"]`, true},
		{"multi array", ` ["20", "22"]`, "20.11.0", ` ["20", "22"]`, false},
		{"inline table", ` { version = "14" }`, "14.1.1", ` { version = "14.1.1" }`, true},
		{"inline table extra", ` { version = "14", postinstall = "x" }`, "14.1.1", ` { version = "14.1.1", postinstall = "x" }`, true},
		{"inline table trailing comment", ` { version = "14" } # version = "old"`, "14.1.1", ` { version = "14.1.1" } # version = "old"`, true},
		{"inline table version text in string", ` { postinstall = "echo version = old", version = "14" }`, "14.1.1", ` { postinstall = "echo version = old", version = "14.1.1" }`, true},
		{"inline table dotted key", ` { runtime.version = "old", version = "14" }`, "14.1.1", ` { runtime.version = "old", version = "14.1.1" }`, true},
		// A version array nested in an inline table follows the same rule as a
		// bare array on the pin path: a single version is pinned, several are
		// left for a manual pin, and neither may produce invalid TOML.
		{"inline table single-version array", ` { version = ["14"] }`, "14.1.1", ` { version = ["14.1.1"] }`, true},
		{"inline table multi-version array", ` { version = ["14", "15"] }`, "14.1.1", ` { version = ["14", "15"] }`, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Every value here is the tool's sole declaration; the
			// repeated-entry form has its own test.
			// The tool is node here: these rows are about TOML value shapes,
			// not about a tool's version vocabulary.
			got, changed := replaceVersionInValue("node", tt.value, tt.pinned, true)
			if got != tt.want || changed != tt.wantChanged {
				t.Errorf("replaceVersionInValue(%q,%q) = (%q,%v), want (%q,%v)", tt.value, tt.pinned, got, changed, tt.want, tt.wantChanged)
			}
		})
	}
}

// TestSelectorTargetsCurrent pins both directions of the staleness gate that
// decides whether a sole declaration may be overwritten. Every request mise
// resolves at install time must stay rewritable, or a fix that would land is
// refused; every request that names a version the plan does not describe must
// be refused, or a stale plan rolls the toolchain backwards. Vendor-prefixed
// releases are the case the "starts with a digit" reading got wrong: they are
// exact versions that begin with a letter.
func TestSelectorTargetsCurrent(t *testing.T) {
	tests := []struct {
		name     string
		declared string
		currents []string
		want     bool
	}{
		// Rewritable: the declaration could still be resolving to a current
		// version.
		{"exact current version", "20.11.0", []string{"20.11.0"}, true},
		{"major selector", "20", []string{"20.11.0"}, true},
		{"minor selector", "20.11", []string{"20.11.0"}, true},
		{"v-prefixed current", "v20.11.0", []string{"20.11.0"}, true},
		{"lts channel", "lts", []string{"20.11.0"}, true},
		{"latest channel", "latest", []string{"20.11.0"}, true},
		{"stable channel", "stable", []string{"20.11.0"}, true},
		{"subtracted channel", "sub-2:lts", []string{"20.11.0"}, true},
		// A sub- request governs the line it resolves to, which is below the
		// one it names: mise 2026.7.3 installs 19.9.0 for `node = "sub-1:20"`
		// and 20.10.0 for `node = "sub-0.1:20.11"`, both read from
		// `mise ls --current` over a real config.
		{"subtracted selector on the line it resolves to", "sub-1:20", []string{"19.9.0"}, true},
		{"subtracted minor selector on the line it resolves to", "sub-0.1:20.11", []string{"20.10.0"}, true},
		{"explicit prefix selector", "prefix:20", []string{"20.11.0"}, true},
		{"git ref", "ref:main", []string{"20.11.0"}, true},
		{"registry alias", "gallium", []string{"20.11.0"}, true},
		{"vendor-prefixed current version", "temurin-21.0.6+7", []string{"temurin-21.0.6+7"}, true},
		{"vendor-prefixed major selector", "temurin-21", []string{"temurin-21.0.6+7"}, true},
		{"no known currents", "temurin-22.0.2+9", nil, true},
		// A partial request governs its own line and no other. Verified by
		// resolving real configs on mise 2026.7.3: node = "20.1" installs
		// 20.1.0, and node = "20.11" installs 20.11.1.
		{"partial selector on its own line", "20.1", []string{"20.1.0"}, true},
		{"minor selector on its own line", "20.11", []string{"20.11.1"}, true},
		{"vendor-prefixed partial", "temurin-21.0", []string{"temurin-21.0.12+8.0.LTS"}, true},

		// Refused: the declaration names a version the plan does not describe,
		// so the config has moved on and rewriting it is a downgrade.
		{"stale exact version", "1.25.1", []string{"1.22.12"}, false},
		{"selector for another line", "22.1", []string{"20.11.0"}, false},
		{"major selector for another line", "22", []string{"20.11.0"}, false},
		{"stale vendor-prefixed version", "temurin-22.0.2+9", []string{"temurin-21.0.6+7"}, false},
		{"stale vendor-prefixed major selector", "temurin-22", []string{"temurin-21.0.6+7"}, false},
		{"another vendor at the same version", "zulu-21.0.6+7", []string{"temurin-21.0.6+7"}, false},
		{"explicit prefix for another line", "prefix:22", []string{"20.11.0"}, false},
		{"subtracted selector on another line", "sub-1:22", []string{"20.11.0"}, false},
		// The base line is not the resolved line. Reading sub-1:20 as if it
		// governed 20.x lets a plan built for 20.11.0 overwrite a declaration
		// that installs 19.9.0, and refuses the plan that actually describes
		// it.
		{"subtracted selector on its unsubtracted base line", "sub-1:20", []string{"20.11.0"}, false},
		{"subtracted minor selector on its unsubtracted base line", "sub-0.1:20.11", []string{"20.11.1"}, false},
		{"selector off by one character", "20.2", []string{"20.11.0"}, false},
		{"declaration more precise than the current version", "20.11.0", []string{"20.11"}, false},
		// The permissive misreading: a leading-character rule would let
		// "20.1" claim 20.19.6, which it does not govern, and rewrite a
		// declaration the finding does not describe.
		{"partial selector reaching past its line", "20.1", []string{"20.19.6"}, false},
		{"selector that resolves to nothing", "2", []string{"26.7.0"}, false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := selectorTargetsCurrent("node", tt.declared, tt.currents); got != tt.want {
				t.Errorf("selectorTargetsCurrent(%q, %v) = %v, want %v", tt.declared, tt.currents, got, tt.want)
			}
		})
	}
}

func TestRewriteToolVersion(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		tool     string
		currents []string
		version  string
		want     string
		wantErr  bool
	}{
		{
			name: "scalar with comment",
			input: `[tools]
go = "1.22.12" # toolchain
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = "1.24.3" # toolchain
`,
		},
		{
			// The remediation contract for arrays: replace only the vulnerable
			// element, preserve every other pinned version.
			name: "multi-version array element-wise",
			input: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = ["1.24.3", "1.23.8"]
`,
		},
		{
			name: "multi-version array second element with comment",
			input: `[tools]
go = ["1.22.12", "1.23.8"] # test matrix
`,
			tool: "go", currents: []string{"1.23.8"}, version: "1.24.3",
			want: `[tools]
go = ["1.22.12", "1.24.3"] # test matrix
`,
		},
		{
			// Every element matching any vulnerable version is replaced, so
			// one command can honestly cover several vulnerable pins.
			name: "multiple vulnerable elements all replaced",
			input: `[tools]
go = ["1.22.12", "1.23.8", "1.24.0"]
`,
			tool: "go", currents: []string{"1.22.12", "1.23.8"}, version: "1.24.3",
			want: `[tools]
go = ["1.24.3", "1.24.3", "1.24.0"]
`,
		},
		{
			name: "multi-version array bare elements",
			input: `[tools]
node = [20, 22]
`,
			tool: "node", currents: []string{"20"}, version: "20.11.1",
			want: `[tools]
node = ["20.11.1", 22]
`,
		},
		{
			name: "multi-version array without current fails closed",
			input: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			tool: "go", currents: nil, version: "1.24.3",
			want: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			wantErr: true,
		},
		{
			name: "multi-version array with unmatched current fails closed",
			input: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			tool: "go", currents: []string{"1.21.0"}, version: "1.24.3",
			want: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			wantErr: true,
		},
		{
			name: "single-version array without current",
			input: `[tools]
go = ["1.22.12"]
`,
			tool: "go", currents: nil, version: "1.24.3",
			want: `[tools]
go = ["1.24.3"]
`,
		},
		// A sole declaration is replaced only when the finding still describes
		// what the file says. An exact version the plan does not name means
		// the config moved on, and rewriting it would roll the user backwards;
		// a partial or non-numeric selector may still resolve to the
		// vulnerable version, so it is fair game. The scalar and one-element
		// array forms must answer identically.
		{
			name: "stale exact scalar fails closed",
			input: `[tools]
go = "1.25.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = "1.25.1"
`,
			wantErr: true,
		},
		{
			name: "stale exact sole array element fails closed",
			input: `[tools]
go = ["1.25.1"]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = ["1.25.1"]
`,
			wantErr: true,
		},
		{
			name: "stale exact sole inline table fails closed",
			input: `[tools]
go = { version = "1.25.1" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = { version = "1.25.1" }
`,
			wantErr: true,
		},
		{
			// mise's Java versions are vendor-prefixed exact releases, so a
			// declaration that begins with a letter is not automatically a
			// selector. A config already ahead of the plan must survive.
			name: "stale vendor-prefixed exact scalar fails closed",
			input: `[tools]
java = "temurin-22.0.2+9"
`,
			tool: "java", currents: []string{"temurin-21.0.6+7"}, version: "temurin-21.0.7+6",
			want: `[tools]
java = "temurin-22.0.2+9"
`,
			wantErr: true,
		},
		{
			name: "vendor-prefixed exact scalar rewritten",
			input: `[tools]
java = "temurin-21.0.6+7"
`,
			tool: "java", currents: []string{"temurin-21.0.6+7"}, version: "temurin-21.0.7+6",
			want: `[tools]
java = "temurin-21.0.7+6"
`,
		},
		{
			name: "vendor-prefixed major selector rewritten",
			input: `[tools]
java = "temurin-21"
`,
			tool: "java", currents: []string{"temurin-21.0.6+7"}, version: "temurin-21.0.7+6",
			want: `[tools]
java = "temurin-21.0.7+6"
`,
		},
		{
			name: "partial major selector rewritten",
			input: `[tools]
node = "20"
`,
			tool: "node", currents: []string{"20.11.0"}, version: "20.11.1",
			want: `[tools]
node = "20.11.1"
`,
		},
		{
			name: "partial minor selector rewritten",
			input: `[tools]
node = "20.11"
`,
			tool: "node", currents: []string{"20.11.0"}, version: "20.11.1",
			want: `[tools]
node = "20.11.1"
`,
		},
		{
			name: "alias selector rewritten",
			input: `[tools]
node = "lts"
`,
			tool: "node", currents: []string{"20.11.0"}, version: "20.11.1",
			want: `[tools]
node = "20.11.1"
`,
		},
		{
			name: "partial selector in a sole array element rewritten",
			input: `[tools]
node = ["20"]
`,
			tool: "node", currents: []string{"20.11.0"}, version: "20.11.1",
			want: `[tools]
node = ["20.11.1"]
`,
		},
		{
			// A partial selector for a different release line cannot resolve
			// to the vulnerable version, so it is stale like an exact one.
			name: "partial selector for another line fails closed",
			input: `[tools]
node = "22.1"
`,
			tool: "node", currents: []string{"20.11.0"}, version: "20.11.1",
			want: `[tools]
node = "22.1"
`,
			wantErr: true,
		},
		{
			name: "v-prefixed declaration matches the bare current",
			input: `[tools]
go = "v1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = "1.24.3"
`,
		},
		{
			// Multiline arrays are first-class: the vulnerable element is
			// replaced in place, preserving line structure and comments.
			name: "multiline array element-wise",
			input: `[tools]
go = [
  "1.22.12", # vulnerable
  "1.23.8",
]
node = "20.11.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = [
  "1.24.3", # vulnerable
  "1.23.8",
]
node = "20.11.1"
`,
		},
		{
			// The corruption regression: a multiline array whose elements
			// match nothing must leave the file byte-identical, never rewrite
			// the opening bracket as a scalar.
			name: "multiline array unmatched current fails closed",
			input: `[tools]
go = [
  "1.22.12",
  "1.23.8",
]
node = "20.11.1"
`,
			tool: "go", currents: []string{"1.21.0"}, version: "1.24.3",
			want: `[tools]
go = [
  "1.22.12",
  "1.23.8",
]
node = "20.11.1"
`,
			wantErr: true,
		},
		{
			name: "tools subtable version key",
			input: `[tools.go]
version = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools.go]
version = "1.24.3"
`,
		},
		{
			// Table headers are key paths, not text: mise's parser reads
			// ["tools"] as the tools table, so the rewriter must too or it
			// refuses a fix for a config inventory happily parsed.
			name: "quoted tools table header",
			input: `["tools"]
go = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `["tools"]
go = "1.24.3"
`,
		},
		{
			name: "quoted tools segment in a subtable header",
			input: `["tools".go]
version = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `["tools".go]
version = "1.24.3"
`,
		},
		{
			name: "single-quoted tools subtable header",
			input: `['tools'.'npm:cowsay']
version = "1.5.0"
`,
			tool: "npm:cowsay", currents: []string{"1.5.0"}, version: "1.6.0",
			want: `['tools'.'npm:cowsay']
version = "1.6.0"
`,
		},
		{
			// A deeper path is not the tools table; touching it would rewrite
			// an unrelated key.
			name: "deeper quoted header is not the tools table",
			input: `["tools".go.extra]
version = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `["tools".go.extra]
version = "1.22.12"
`,
			wantErr: true,
		},
		{
			// Forms mise's parser accepts beyond the [tools] table: root-level
			// dotted keys, dotted version keys, and the root inline table.
			name: "root dotted key",
			input: `tools.go = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools.go = "1.24.3"
`,
		},
		{
			name: "root dotted quoted key",
			input: `tools."npm:lodash" = "4.17.20"
`,
			tool: "npm:lodash", currents: []string{"4.17.20"}, version: "4.17.21",
			want: `tools."npm:lodash" = "4.17.21"
`,
		},
		{
			name: "root dotted version key",
			input: `tools.go.version = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools.go.version = "1.24.3"
`,
		},
		{
			name: "dotted version key inside tools table",
			input: `[tools]
go.version = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go.version = "1.24.3"
`,
		},
		{
			name: "root inline tools table",
			input: `tools = { go = "1.22.12", node = "20.11.1" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { go = "1.24.3", node = "20.11.1" }
`,
		},
		{
			name: "root inline tools table quoted key",
			input: `tools = { "npm:lodash" = "4.17.20" }
`,
			tool: "npm:lodash", currents: []string{"4.17.20"}, version: "4.17.21",
			want: `tools = { "npm:lodash" = "4.17.21" }
`,
		},
		{
			// Array of inline tables (another form mise's parser accepts):
			// replace the version field, preserve tool options.
			name: "single-element array of inline tables",
			input: `[tools]
go = [{ version = "1.22.12", postinstall = "go version" }]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = [{ version = "1.24.3", postinstall = "go version" }]
`,
		},
		{
			// Matching an inline-table element means comparing its version
			// field, not the whole table text.
			name: "multi-element array of inline tables",
			input: `[tools]
go = [{ version = "1.22.12" }, { version = "1.23.8" }]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = [{ version = "1.24.3" }, { version = "1.23.8" }]
`,
		},
		{
			name: "multi-element array of inline tables unmatched fails closed",
			input: `[tools]
go = [{ version = "1.22.12" }, { version = "1.23.8" }]
`,
			tool: "go", currents: []string{"1.21.0"}, version: "1.24.3",
			want: `[tools]
go = [{ version = "1.22.12" }, { version = "1.23.8" }]
`,
			wantErr: true,
		},
		{
			// A version array nested in an inline table must be edited
			// element-wise; truncating it at the first comma produced invalid
			// TOML like { version = "4.17.22", "4.17.21"] }.
			name: "version array nested in inline table",
			input: `[tools]
"npm:lodash" = { version = ["4.17.20", "4.17.21"] }
`,
			tool: "npm:lodash", currents: []string{"4.17.20"}, version: "4.17.22",
			want: `[tools]
"npm:lodash" = { version = ["4.17.22", "4.17.21"] }
`,
		},
		{
			name: "version array nested in inline table with options",
			input: `[tools]
"npm:lodash" = { version = ["4.17.20", "4.17.21"], postinstall = "echo hi" }
`,
			tool: "npm:lodash", currents: []string{"4.17.21"}, version: "4.17.22",
			want: `[tools]
"npm:lodash" = { version = ["4.17.20", "4.17.22"], postinstall = "echo hi" }
`,
		},
		{
			name: "single-version array nested in inline table",
			input: `[tools]
"npm:lodash" = { version = ["4.17.20"] }
`,
			tool: "npm:lodash", currents: nil, version: "4.17.22",
			want: `[tools]
"npm:lodash" = { version = ["4.17.22"] }
`,
		},
		{
			name: "version array nested in inline table unmatched fails closed",
			input: `[tools]
"npm:lodash" = { version = ["4.17.20", "4.17.21"] }
`,
			tool: "npm:lodash", currents: []string{"3.0.0"}, version: "4.17.22",
			want: `[tools]
"npm:lodash" = { version = ["4.17.20", "4.17.21"] }
`,
			wantErr: true,
		},
		{
			// Only a version key at the tool's own depth is the tool version;
			// a nested table may carry an unrelated version key, and mise
			// reads the outer one.
			name: "nested table with its own version key",
			input: `[tools]
go = { opts = { version = "meta" }, version = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = { opts = { version = "meta" }, version = "1.24.3" }
`,
		},
		{
			name: "nested table version key after the real one",
			input: `[tools]
go = { version = "1.22.12", opts = { version = "meta" } }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = { version = "1.24.3", opts = { version = "meta" } }
`,
		},
		{
			name: "array element with a nested version key",
			input: `[tools]
go = [{ opts = { version = "meta" }, version = "1.22.12" }, { version = "1.23.8" }]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = [{ opts = { version = "meta" }, version = "1.24.3" }, { version = "1.23.8" }]
`,
		},
		{
			name: "root inline table with a nested tool name",
			input: `tools = { foo = { go = "9.9.9" }, go = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { foo = { go = "9.9.9" }, go = "1.24.3" }
`,
		},
		{
			// A dotted field key inside the root inline table is the same
			// declaration as `[tools] go.version = ...`, and mise's parser
			// reads it as one, so the rewriter must resolve it to the tool
			// rather than to a field literally named "go.version".
			name: "root inline table with a dotted tool key",
			input: `tools = { go.version = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { go.version = "1.24.3" }
`,
		},
		{
			name: "root inline table with a dotted tool key beside a plain one",
			input: `tools = { node = "20.11.0", go.version = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { node = "20.11.0", go.version = "1.24.3" }
`,
		},
		{
			// Segments may be quoted independently, which is how a
			// backend-qualified tool gets a dotted version key.
			name: "root inline table with a quoted dotted tool key",
			input: `tools = { "npm:lodash".version = "4.17.20" }
`,
			tool: "npm:lodash", currents: []string{"4.17.20"}, version: "4.17.22",
			want: `tools = { "npm:lodash".version = "4.17.22" }
`,
		},
		{
			// Only the tool's own version key declares its version: a deeper
			// path is some other table's field and must not be rewritten.
			name: "root inline table with a deeper dotted key fails closed",
			input: `tools = { go.opts.version = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { go.opts.version = "1.22.12" }
`,
			wantErr: true,
		},
		{
			name: "root inline table with a nested version key",
			input: `tools = { go = { opts = { version = "meta" }, version = "1.22.12" } }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = { go = { opts = { version = "meta" }, version = "1.24.3" } }
`,
		},
		{
			// mise accepts an inline table spread over several lines, so the
			// rewriter must too rather than refusing a fix mise understands.
			name: "multiline inline table",
			input: `[tools]
go = {
  version = "1.22.12",
  postinstall = "go version"
}
node = "20.11.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = {
  version = "1.24.3",
  postinstall = "go version"
}
node = "20.11.1"
`,
		},
		{
			// mise tool keys can carry option syntax containing an assignment,
			// so the key/value split must respect quoting.
			name: "option-bearing quoted key",
			input: `[tools]
"ubi:cli/cli[exe=gh]" = "1.0.0"
`,
			tool: "ubi:cli/cli[exe=gh]", currents: []string{"1.0.0"}, version: "1.1.0",
			want: `[tools]
"ubi:cli/cli[exe=gh]" = "1.1.0"
`,
		},
		{
			name: "option-bearing quoted key in an array",
			input: `[tools]
"ubi:cli/cli[exe=gh]" = ["1.0.0", "1.2.0"]
`,
			tool: "ubi:cli/cli[exe=gh]", currents: []string{"1.0.0"}, version: "1.1.0",
			want: `[tools]
"ubi:cli/cli[exe=gh]" = ["1.1.0", "1.2.0"]
`,
		},
		{
			// A vulnerable version nested inside an element's version array
			// must select that element, not be treated as unmatchable while
			// another element's match reports the whole tool fixed.
			name: "vulnerable version nested in a multi-entry array",
			input: `[tools]
go = [{ version = ["1.22.12", "1.23.8"] }, { version = "1.21.0" }]
`,
			tool: "go", currents: []string{"1.22.12", "1.21.0"}, version: "1.24.3",
			want: `[tools]
go = [{ version = ["1.24.3", "1.23.8"] }, { version = "1.24.3" }]
`,
		},
		{
			name: "only the nested vulnerable version matches",
			input: `[tools]
go = [{ version = ["1.22.12", "1.23.8"] }, { version = "1.21.0" }]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = [{ version = ["1.24.3", "1.23.8"] }, { version = "1.21.0" }]
`,
		},
		{
			name: "no nested version matches fails closed",
			input: `[tools]
go = [{ version = ["1.22.12", "1.23.8"] }, { version = "1.21.0" }]
`,
			tool: "go", currents: []string{"1.19.0"}, version: "1.24.3",
			want: `[tools]
go = [{ version = ["1.22.12", "1.23.8"] }, { version = "1.21.0" }]
`,
			wantErr: true,
		},
		{
			// mise accepts a quoted version key; the scanner must read keys
			// with TOML quoting rules, not just the bare spelling.
			name: "quoted version key",
			input: `[tools]
go = { "version" = "1.22.12" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = { "version" = "1.24.3" }
`,
		},
		{
			name: "quoted version key beside options",
			input: `[tools]
go = { 'version' = "1.22.12", postinstall = "go version" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = { 'version' = "1.24.3", postinstall = "go version" }
`,
		},
		{
			// The root inline table may span lines; the walker must gather the
			// balanced table before trying to rewrite it.
			name: "multiline root tools table",
			input: `tools = {
  go = "1.22.12",
  node = "20.11.1"
}
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = {
  go = "1.24.3",
  node = "20.11.1"
}
`,
		},
		{
			name: "multiline root tools table with nested table",
			input: `tools = {
  go = { version = "1.22.12", postinstall = "go version" },
  node = "20.11.1"
}
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `tools = {
  go = { version = "1.24.3", postinstall = "go version" },
  node = "20.11.1"
}
`,
		},
		{
			name: "undeclared tool fails",
			input: `[tools]
node = "20.11.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
node = "20.11.1"
`,
			wantErr: true,
		},
		{
			name: "non-concrete new version rejected",
			input: `[tools]
go = "1.22.12"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "latest",
			want: `[tools]
go = "1.22.12"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "mise.toml"), []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = RewriteToolVersion(root, "mise.toml", tt.tool, tt.currents, tt.version)
			if tt.wantErr && err == nil {
				t.Fatal("expected rewrite error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "mise.toml"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
		})
	}
}

// TestRewriteToolVersionIdempotent pins the retry contract: re-applying an
// edit that a previous run already made is success, not an "unapplied update"
// error, so a caller whose later work failed (lockfile pruning) can retry and
// finish. A config that is not actually at the new version still errors.
func TestRewriteToolVersionIdempotent(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		tool     string
		currents []string
		version  string
		wantErr  bool
	}{
		{
			name: "scalar already at new version",
			input: `[tools]
go = "1.24.3"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
		},
		{
			name: "array element already replaced",
			input: `[tools]
go = ["1.24.3", "1.23.8"]
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
		},
		{
			name: "inline table already at new version",
			input: `[tools]
go = { version = "1.24.3" }
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
		},
		{
			// The config and the plan spell the same release differently, the
			// way Deputy reports a Go runtime ("v1.24.3") and mise installs it.
			// The rewriter already refuses to overwrite this declaration because
			// it is not the vulnerable one, so reading it as unapplied leaves the
			// caller unable to finish the fix it already made.
			name: "v-prefixed declaration of the new version",
			input: `[tools]
go = "v1.24.3"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
		},
		{
			name: "bare declaration of a v-prefixed new version",
			input: `[tools]
go = "1.24.3"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "v1.24.3",
		},
		{
			// A declaration ahead of the plan is not the plan's edit already
			// applied, whichever way the versions are spelled: the rewriter
			// refuses it and the caller must hear about it.
			name: "v-prefixed declaration of another version",
			input: `[tools]
go = "v1.25.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			wantErr: true,
		},
		{
			// With no known vulnerable versions, a second declared version may
			// still be the vulnerable one, so this is not provably applied.
			name: "unknown currents with several declared versions",
			input: `[tools]
go = ["1.24.3", "1.22.12"]
`,
			tool: "go", currents: nil, version: "1.24.3",
			wantErr: true,
		},
		{
			name: "unmatched multi-version array",
			input: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			tool: "go", currents: []string{"1.21.0"}, version: "1.24.3",
			wantErr: true,
		},
		{
			name: "tool not declared",
			input: `[tools]
node = "20.11.1"
`,
			tool: "go", currents: []string{"1.22.12"}, version: "1.24.3",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "mise.toml"), []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = RewriteToolVersion(root, "mise.toml", tt.tool, tt.currents, tt.version)
			if tt.wantErr && err == nil {
				t.Fatal("expected rewrite error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "mise.toml"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.input {
				t.Errorf("config changed on a no-op rewrite:\n--- got ---\n%s\n--- want ---\n%s", got, tt.input)
			}
		})
	}
}

// TestRewriteMatchesInventoryOnExoticSyntax pins the contract that binds the
// reader to the writer: a declaration mise.Parse inventories is a declaration
// RewriteToolVersion can rewrite. When only the reader understands a shape, a
// fix Deputy itself offered comes back as "could not rewrite", so both halves
// are driven from the same inputs here rather than tested apart. Every input
// is a config mise 2026.7.3 loads.
func TestRewriteMatchesInventoryOnExoticSyntax(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		tool    string
		current string
		pinned  string
		want    string
	}{
		{
			// A basic-string key is decoded by the parser, so the tool is
			// inventoried as "go" and the rewriter has to find it under a key
			// that does not spell "go" literally.
			name: "escaped key",
			input: `[tools]
"\u0067o" = "1.22.12"
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
"\u0067o" = "1.24.3"
`,
		},
		{
			name: "escaped inline table field key",
			input: `[tools]
go = { "vers\u0069on" = "1.22.12" }
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = { "vers\u0069on" = "1.24.3" }
`,
		},
		{
			// mise accepts an inline table across several lines, and such a
			// table may carry its own comments. Trailing trivia begins at the
			// closing brace, not at the first "#".
			name: "multiline inline table with an interior comment",
			input: `[tools]
go = {
  # the toolchain the build pins
  version = "1.22.12",
  postinstall = "go version"
}
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = {
  # the toolchain the build pins
  version = "1.24.3",
  postinstall = "go version"
}
`,
		},
		{
			name: "multiline inline table with a comment after the version",
			input: `[tools]
go = { # opening
  version = "1.22.12" # the vulnerable one
} # closing
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = { # opening
  version = "1.24.3" # the vulnerable one
} # closing
`,
		},
		{
			// A brace inside a comment closes nothing.
			name: "inline table with a brace in a comment",
			input: `[tools]
go = {
  # not a closing brace: }
  version = "1.22.12"
}
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = {
  # not a closing brace: }
  version = "1.24.3"
}
`,
		},
		{
			// The array path is the inline table's sibling and must read an
			// interior comment the same way.
			name: "multiline array with an interior comment",
			input: `[tools]
go = [
  # the vulnerable line
  "1.22.12"
]
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = [
  # the vulnerable line
  "1.24.3"
]
`,
		},
		{
			// TOML's multi-line basic string is a perfectly ordinary scalar
			// when it holds no newline, and mise 2026.7.3 resolves
			// `go = """1.22.12"""` to 1.22.12 under `mise ls --current`. A
			// quote-pair reading sees an empty string followed by junk and
			// refuses a fix the config can take.
			name: "triple-quoted basic string version",
			input: `[tools]
go = """1.22.12"""
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = "1.24.3"
`,
		},
		{
			name: "triple-quoted literal string version",
			input: `[tools]
go = '''1.22.12'''
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = "1.24.3"
`,
		},
		{
			name: "triple-quoted version in an inline table",
			input: `[tools]
go = { version = """1.22.12""", postinstall = "go version" }
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = { version = "1.24.3", postinstall = "go version" }
`,
		},
		{
			name: "triple-quoted version in an array",
			input: `[tools]
go = ['''1.22.12''']
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = ["1.24.3"]
`,
		},
		{
			// A triple-quoted token whose trailing comment holds an
			// apostrophe: the comment starts outside the string, so the
			// apostrophe is comment text and not a literal-string opener.
			name: "triple-quoted version with an apostrophe in the comment",
			input: `[tools]
go = """1.22.12""" # don't touch the rest
`,
			tool: "go", current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
go = "1.24.3" # don't touch the rest
`,
		},
		{
			// An escaped quote is part of the key, not its terminator.
			name: "escaped quote in key",
			input: `[tools]
"ubi:a\"b" = "1.22.12"
`,
			tool: `ubi:a"b`, current: "1.22.12", pinned: "1.24.3",
			want: `[tools]
"ubi:a\"b" = "1.24.3"
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg, err := mise.Parse("mise.toml", []byte(tt.input))
			if err != nil {
				t.Fatalf("mise.Parse: %v", err)
			}
			if !slices.ContainsFunc(cfg.Tools, func(s mise.ToolSpec) bool {
				return s.Key == tt.tool && slices.Contains(s.Versions, tt.current)
			}) {
				t.Fatalf("inventory does not report %s@%s, so this case proves nothing: %+v", tt.tool, tt.current, cfg.Tools)
			}

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "mise.toml"), []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			if err := RewriteToolVersion(root, "mise.toml", tt.tool, []string{tt.current}, tt.pinned); err != nil {
				t.Fatalf("rewrite: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "mise.toml"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
			after, err := mise.Parse("mise.toml", got)
			if err != nil {
				t.Fatalf("rewritten config no longer parses: %v", err)
			}
			if !slices.ContainsFunc(after.Tools, func(s mise.ToolSpec) bool {
				return s.Key == tt.tool && slices.Contains(s.Versions, tt.pinned)
			}) {
				t.Errorf("rewritten config does not declare %s@%s: %+v", tt.tool, tt.pinned, after.Tools)
			}
		})
	}
}

// TestRewriteArrayOfTableDeclarations pins the array-of-tables form of a tool
// declaration, `[[tools.<name>]]` with the fields below it. mise 2026.7.3
// reads it: a mise.toml holding `[[tools.go]]` and `version = "1.22.12"`
// reports
//
//	go  1.22.12 (missing)  /private/tmp/misearr/mise.toml  1.22.12
//
// under `mise ls --current`, and a repeated header reports both entries as
// separate requests. A header scanner that skips the form does not merely miss
// the fix: the table context of whatever header came before leaks past it, so
// the assignment below `[[tools.go]]` is rewritten as if it belonged to the
// previous tool, silently writing one tool's pin over another's version.
//
// Repeated entries are one multi-version declaration, so they follow the array
// rule: only the entries naming a current version are rewritten, and with no
// current version known the whole declaration is left for a manual fix.
func TestRewriteArrayOfTableDeclarations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		// tool and pinned describe the edit; currents are the versions the
		// finding names, empty for the pinning path.
		tool     string
		currents []string
		pinned   string
		// want is the file after the edit. wantErr expects the edit to be
		// refused, which must leave the file byte-for-byte alone.
		want    string
		wantErr bool
	}{
		{
			name:  "sole entry",
			input: "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n",
			tool:  "go", currents: []string{"1.22.12"}, pinned: "1.24.3",
			want: "[[tools.go]]\nversion = \"1.24.3\"\nbackend = \"core:go\"\n",
		},
		{
			name:  "sole entry with a quoted key",
			input: "[[tools.\"npm:prettier\"]]\nversion = \"3.3.2\"\n",
			tool:  "npm:prettier", currents: []string{"3.3.2"}, pinned: "3.3.3",
			want: "[[tools.\"npm:prettier\"]]\nversion = \"3.3.3\"\n",
		},
		{
			name:  "sole entry with no current version known",
			input: "[[tools.go]]\nversion = \"1.22.12\"\n",
			tool:  "go", pinned: "1.24.3",
			want: "[[tools.go]]\nversion = \"1.24.3\"\n",
		},
		{
			name:  "a following table header ends the entry",
			input: "[[tools.go]]\nversion = \"1.22.12\"\n\n[settings]\nversion = \"ignored\"\n",
			tool:  "go", currents: []string{"1.22.12"}, pinned: "1.24.3",
			want: "[[tools.go]]\nversion = \"1.24.3\"\n\n[settings]\nversion = \"ignored\"\n",
		},
		{
			// The entry the finding names is rewritten; the other request is
			// not the vulnerable one and survives.
			name:  "repeated entries rewrite only the named version",
			input: "[[tools.go]]\nversion = \"1.21.13\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			tool:  "go", currents: []string{"1.22.12"}, pinned: "1.24.3",
			want: "[[tools.go]]\nversion = \"1.21.13\"\n\n[[tools.go]]\nversion = \"1.24.3\"\n",
		},
		{
			// Without a current version there is nothing to tell the two
			// requests apart, and rewriting both would collapse a deliberate
			// pair of toolchains into one version declared twice.
			name:  "repeated entries with no current version fail closed",
			input: "[[tools.go]]\nversion = \"1.21.13\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			tool:  "go", pinned: "1.24.3",
			wantErr: true,
		},
		{
			// The header scanner has to see [[tools.go]] to know the
			// assignment under it is not still node's.
			name:  "an entry after a tool table is not the table's",
			input: "[tools.node]\nversion = \"20.11.0\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			tool:  "node", currents: []string{"20.11.0"}, pinned: "20.11.1",
			want: "[tools.node]\nversion = \"20.11.1\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
		},
		{
			name:  "an entry after a tools table is not the table's",
			input: "[tools]\nnode = \"20.11.0\"\n\n[[tools.go]]\nversion = \"1.22.12\"\n",
			tool:  "go", currents: []string{"1.22.12"}, pinned: "1.24.3",
			want: "[tools]\nnode = \"20.11.0\"\n\n[[tools.go]]\nversion = \"1.24.3\"\n",
		},
		{
			// An array of tables under a name that is not a tool declares
			// nothing the rewriter may touch.
			name:  "an unrelated array of tables is left alone",
			input: "[[env]]\nversion = \"1.22.12\"\n\n[tools]\ngo = \"1.22.12\"\n",
			tool:  "go", currents: []string{"1.22.12"}, pinned: "1.24.3",
			want: "[[env]]\nversion = \"1.22.12\"\n\n[tools]\ngo = \"1.24.3\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The case only proves something if inventory reports the version
			// the edit names, so a refusal is a fix Deputy could have offered.
			cfg, err := mise.Parse("mise.toml", []byte(tt.input))
			if err != nil {
				t.Fatalf("mise.Parse: %v", err)
			}
			for _, current := range tt.currents {
				if !slices.ContainsFunc(cfg.Tools, func(s mise.ToolSpec) bool {
					return s.Key == tt.tool && slices.Contains(s.Versions, current)
				}) {
					t.Fatalf("inventory does not report %s@%s: %+v", tt.tool, current, cfg.Tools)
				}
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(path, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = RewriteToolVersion(root, "mise.toml", tt.tool, tt.currents, tt.pinned)
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected the edit to be refused, got:\n%s", got)
				}
				if string(got) != tt.input {
					t.Errorf("refused edit still changed the file:\n--- got ---\n%s\n--- want ---\n%s", got, tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("RewriteToolVersion: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
			after, err := mise.Parse("mise.toml", got)
			if err != nil {
				t.Fatalf("rewritten config no longer parses: %v", err)
			}
			if !slices.ContainsFunc(after.Tools, func(s mise.ToolSpec) bool {
				return s.Key == tt.tool && slices.Contains(s.Versions, tt.pinned)
			}) {
				t.Errorf("rewritten config does not declare %s@%s: %+v", tt.tool, tt.pinned, after.Tools)
			}
		})
	}
}

// TestPinArrayOfTableDeclarations pins the same form on the pinning path,
// which names no current version: a sole entry is pinned like any other
// declaration, and repeated entries are a multi-version declaration that
// pinning leaves for a manual fix, exactly as it leaves `go = ["1.22", "1.23"]`
// alone. Rewriting one tool's entry must never touch another's, which is what
// a header scanner blind to [[tools.<name>]] would do.
func TestPinArrayOfTableDeclarations(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		input   string
		updates []pin.Update
		want    string
		wantErr bool
	}{
		{
			name:    "sole entry",
			input:   "[[tools.go]]\nversion = \"1.22\"\nbackend = \"core:go\"\n",
			updates: []pin.Update{{Name: "go", PinnedValue: "1.22.12"}},
			want:    "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n",
		},
		{
			name:    "repeated entries are left for a manual pin",
			input:   "[[tools.go]]\nversion = \"1.21\"\n\n[[tools.go]]\nversion = \"1.22\"\n",
			updates: []pin.Update{{Name: "go", PinnedValue: "1.22.12"}},
			wantErr: true,
		},
		{
			// Before the header was recognized, node's pin landed on go's
			// version because the [tools.node] context leaked past
			// [[tools.go]].
			name:    "a neighbouring entry keeps its own version",
			input:   "[tools.node]\nversion = \"20\"\n\n[[tools.go]]\nversion = \"1.22\"\n",
			updates: []pin.Update{{Name: "node", PinnedValue: "20.11.1"}},
			want:    "[tools.node]\nversion = \"20.11.1\"\n\n[[tools.go]]\nversion = \"1.22\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			path := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(path, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = rewriteMiseVersions(root, "mise.toml", tt.updates)
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected the pin to be refused, got:\n%s", got)
				}
				if string(got) != tt.input {
					t.Errorf("refused pin still changed the file:\n--- got ---\n%s\n--- want ---\n%s", got, tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("rewriteMiseVersions: %v", err)
			}
			if string(got) != tt.want {
				t.Errorf("pin mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
		})
	}
}

// TestRewriteLineSpanningVersionToken pins how a version token that runs across
// lines is handled. TOML lets a declaration be written that way (`go = """` then
// `1.22.12"""`), mise 2026.7.3 resolves it to 1.22.12, and Deputy reports the tool
// at that version, so a finding against it is one Deputy promises an executable
// fix for. Refusing the edit made that promise impossible to keep: `fix --apply`
// could only report "could not rewrite", leaving the user to edit by hand.
//
// The token is therefore rewritten inside its own delimiters, which keeps the
// declaration on the same number of lines. Swapping it for a single-line token is
// what must not happen: that strands the rest of the string as a bare line and
// turns a valid config into one no parser will read.
//
// A token whose text is not exactly the version it declares keeps the old
// refusal. A backslash line continuation makes the value TOML decodes differ from
// the text that spells it, and rewriting that text could change the value in ways
// nobody asked for, so the caller reports an unapplied update instead.
func TestRewriteLineSpanningVersionToken(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		input string
		// currents is the finding's known vulnerable versions; nil is the
		// pinning path, which targets whatever is declared.
		currents []string
		// want is the file after the rewrite. Empty means the rewrite must be
		// refused and the file left byte-for-byte alone.
		want string
	}{
		{
			name:     "multiline basic string, targeted",
			input:    "[tools]\ngo = \"\"\"\n1.22.12\"\"\"\n",
			currents: []string{"1.22.12"},
			want:     "[tools]\ngo = \"\"\"\n1.24.3\"\"\"\n",
		},
		{
			name:  "multiline basic string, pinning",
			input: "[tools]\ngo = \"\"\"\n1.22.12\"\"\"\n",
			want:  "[tools]\ngo = \"\"\"\n1.24.3\"\"\"\n",
		},
		{
			name:     "multiline literal string, targeted",
			input:    "[tools]\ngo = '''\n1.22.12'''\n",
			currents: []string{"1.22.12"},
			want:     "[tools]\ngo = '''\n1.24.3'''\n",
		},
		{
			name:  "multiline literal string, pinning",
			input: "[tools]\ngo = '''\n1.22.12'''\n",
			want:  "[tools]\ngo = '''\n1.24.3'''\n",
		},
		{
			// A comment after the closing delimiter is trivia around the token,
			// so it survives like any other.
			name:     "a comment after the closing delimiter",
			input:    "[tools]\ngo = \"\"\"\n1.22.12\"\"\" # pinned by hand\n",
			currents: []string{"1.22.12"},
			want:     "[tools]\ngo = \"\"\"\n1.24.3\"\"\" # pinned by hand\n",
		},
		{
			// A line continuation swallows the newline and the indentation after
			// it, so the text between the delimiters is not the version: TOML
			// reads 1.22.12 from characters spread across two lines.
			name:     "a backslash line continuation is refused",
			input:    "[tools]\ngo = \"\"\"\n1.22.\\\n12\"\"\"\n",
			currents: []string{"1.22.12"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			// The case only proves something if the parser reads the
			// declaration, so the rewriter is acting on a real one.
			cfg, err := mise.Parse("mise.toml", []byte(tt.input))
			if err != nil {
				t.Fatalf("mise.Parse: %v", err)
			}
			if !slices.ContainsFunc(cfg.Tools, func(s mise.ToolSpec) bool {
				return s.Key == "go" && slices.Contains(s.Versions, "1.22.12")
			}) {
				t.Fatalf("inventory does not report go@1.22.12, so this case proves nothing: %+v", cfg.Tools)
			}

			dir := t.TempDir()
			configPath := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(configPath, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			rewriteErr := RewriteToolVersion(root, "mise.toml", "go", tt.currents, "1.24.3")
			got, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if tt.want == "" {
				if rewriteErr == nil {
					t.Error("expected a token that does not spell its own version to be refused")
				}
				if string(got) != tt.input {
					t.Errorf("refused rewrite still changed the file:\n--- got ---\n%s\n--- want ---\n%s", got, tt.input)
				}
			} else {
				if rewriteErr != nil {
					t.Fatalf("RewriteToolVersion: %v", rewriteErr)
				}
				if string(got) != tt.want {
					t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
				}
				// The point of rewriting in place: mise reads the new version
				// from a file whose declaration still spans the same lines.
				after, err := mise.Parse("mise.toml", got)
				if err != nil {
					t.Fatalf("config no longer parses after the rewrite: %v", err)
				}
				if !slices.ContainsFunc(after.Tools, func(s mise.ToolSpec) bool {
					return s.Key == "go" && slices.Equal(s.Versions, []string{"1.24.3"})
				}) {
					t.Errorf("the rewritten config does not declare go@1.24.3: %+v", after.Tools)
				}
			}
			if _, err := mise.Parse("mise.toml", got); err != nil {
				t.Errorf("config no longer parses: %v", err)
			}
			if wantLines, gotLines := strings.Count(tt.input, "\n"), strings.Count(string(got), "\n"); wantLines != gotLines {
				t.Errorf("line count changed from %d to %d:\n%s", wantLines, gotLines, got)
			}
		})
	}
}

func TestValidateMiseUpdate(t *testing.T) {
	if err := validateMiseUpdate(pin.Update{Name: "node", PinnedValue: "20.11.0"}); err != nil {
		t.Errorf("valid update rejected: %v", err)
	}
	bad := []pin.Update{
		{Name: "", PinnedValue: "20.11.0"},
		{Name: "node", PinnedValue: ""},
		{Name: "node", PinnedValue: "20"},     // not exact
		{Name: "node", PinnedValue: "latest"}, // not exact
		{Name: "node", PinnedValue: "20.1.0\n"},
	}
	for _, u := range bad {
		if err := validateMiseUpdate(u); err == nil {
			t.Errorf("expected error for %+v", u)
		}
	}
}

// TestRewriteConfigIsPublishedAtomically pins how a rewritten config reaches
// disk. A manifest is a hand-written file Deputy was asked to edit, so a
// truncate-then-refill write is a data-loss path: an interrupt, a short write,
// or a full disk leaves the declarations gone, the fix reported as failed, and
// nothing to retry from. Replacing the file closes that window, which the
// sibling lockfile pruning already did.
//
// The window is measured rather than argued about: a reader loops over the file
// while it is rewritten repeatedly, and every read must see one whole version of
// the config. Truncating in place made that reader see an empty or partial file
// hundreds of times per run.
func TestRewriteConfigIsPublishedAtomically(t *testing.T) {
	// Large enough that a reader lands inside the write window, small enough to
	// stay quick.
	body := func(version string) string {
		return "[tools]\ngo = \"" + version + "\"\n" +
			strings.Repeat("# "+strings.Repeat("x", 4096)+"\n", 64)
	}
	const first, second = "1.22.12", "1.24.3"

	dir := t.TempDir()
	configPath := filepath.Join(dir, "mise.toml")
	if err := os.WriteFile(configPath, []byte(body(first)), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	whole := map[string]bool{body(first): true, body(second): true}
	var wg sync.WaitGroup
	stop := make(chan struct{})
	var mu sync.Mutex
	var torn []int
	wg.Add(1)
	go func() {
		defer wg.Done()
		for {
			select {
			case <-stop:
				return
			default:
			}
			data, err := os.ReadFile(configPath)
			if err != nil {
				continue
			}
			if !whole[string(data)] {
				mu.Lock()
				torn = append(torn, len(data))
				mu.Unlock()
			}
		}
	}()

	versions := []string{second, first}
	for i := range 200 {
		if err := rewriteMiseVersions(root, "mise.toml", []pin.Update{{Name: "go", PinnedValue: versions[i%2]}}); err != nil {
			t.Fatalf("rewrite %d: %v", i, err)
		}
	}
	close(stop)
	wg.Wait()

	mu.Lock()
	defer mu.Unlock()
	if len(torn) > 0 {
		t.Errorf("%d reads saw a partially written config, first at %d bytes (whole is %d)",
			len(torn), torn[0], len(body(first)))
	}
}

// TestRewriteConfigFailureLeavesTheOriginal pins that a config Deputy could not
// publish is a config it did not touch. A directory no temporary can be created
// in is the deterministic stand-in for the full disk or interrupt that a
// truncate-then-refill write would answer by emptying the file.
func TestRewriteConfigFailureLeavesTheOriginal(t *testing.T) {
	const original = "[tools]\ngo = \"1.22.12\"\n"

	dir := t.TempDir()
	configPath := filepath.Join(dir, "mise.toml")
	if err := os.WriteFile(configPath, []byte(original), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	makeDirUnwritable(t, dir)

	if err := RewriteToolVersion(root, "mise.toml", "go", []string{"1.22.12"}, "1.24.3"); err == nil {
		t.Fatal("expected the blocked publication to fail the rewrite")
	}
	got, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != original {
		t.Errorf("failed rewrite damaged the config:\n--- got ---\n%s\n--- want ---\n%s", got, original)
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mise.toml.deputy-") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}

// makeDirUnwritable strips the write bit from dir for the rest of the test,
// restoring it afterwards, and skips the test when the caller can create files
// there anyway.
//
// Mode bits do not bind a process holding CAP_DAC_OVERRIDE, which is every
// process in the root-by-default containers CI and isolated agents run in. A
// test that chmods a directory to 0555 and then asserts a write failed is
// asserting something untrue there, so the probe measures whether the bits bind
// on this host instead of guessing from the UID.
func makeDirUnwritable(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	probe := filepath.Join(dir, ".deputy-write-probe")
	f, err := os.OpenFile(probe, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	_ = f.Close()
	_ = os.Remove(probe)
	t.Skip("mode bits do not bind this process, cannot make a directory unwritable")
}

// TestRewriteToolVersionLeavesMultilineStringsAlone pins the format-preservation
// guarantee against TOML's multi-line strings. Their content is text, and it may
// look like anything: a [settings] field holding release notes can contain a
// `[tools]` line with versions written under it.
//
// A line-wise walk that skipped an out-of-scope assignment without skipping the
// string it opened read that text as TOML on the next iteration, so the note's
// contents became a tools table and a version fix rewrote prose the user never
// asked Deputy to touch, silently and while reporting success. Every case here
// is a config mise.Parse reads as declaring exactly one go, so the string is
// nobody's declaration by any reading.
func TestRewriteToolVersionLeavesMultilineStringsAlone(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		currents []string
		version  string
		want     string
	}{
		{
			// The reported case: the note's own "go" line must survive untouched
			// while the real declaration below it is updated.
			name: "a tools table inside a settings string",
			input: `[settings]
release_notes = """
[tools]
go = "1.22.12"
please do not edit this text
"""

[tools]
go = "1.22.12"
`,
			currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[settings]
release_notes = """
[tools]
go = "1.22.12"
please do not edit this text
"""

[tools]
go = "1.24.3"
`,
		},
		{
			// Entry headers inside a string are not declarations either, so they
			// must not make a sole declaration look like a repeated one: counting
			// them left the rewriter refusing a fix the config can take.
			name: "entry headers inside a string do not inflate the arity",
			input: `[settings]
release_notes = """
[[tools.go]]
[[tools.go]]
"""

[tools]
go = "1.24"
`,
			currents: []string{"1.24.9"}, version: "1.24.10",
			want: `[settings]
release_notes = """
[[tools.go]]
[[tools.go]]
"""

[tools]
go = "1.24.10"
`,
		},
		{
			// A literal multi-line string is content just the same, and the
			// declaration may sit above the string rather than below it.
			name: "a literal string after the declaration",
			input: `[tools]
go = "1.22.12"

[settings]
notes = '''
[tools]
go = "1.22.12"
'''
`,
			currents: []string{"1.22.12"}, version: "1.24.3",
			want: `[tools]
go = "1.24.3"

[settings]
notes = '''
[tools]
go = "1.22.12"
'''
`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// The premise: mise reads one declaration here, so anything else
			// the rewriter touches is text it had no business editing.
			cfg, err := mise.Parse("mise.toml", []byte(tt.input))
			if err != nil {
				t.Fatalf("fixture does not parse: %v", err)
			}
			if len(cfg.Tools) != 1 || cfg.Tools[0].Key != "go" || len(cfg.Tools[0].Versions) != 1 {
				t.Fatalf("fixture declares %+v, want a single go version", cfg.Tools)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(path, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			if err := RewriteToolVersion(root, "mise.toml", "go", tt.currents, tt.version); err != nil {
				t.Fatalf("RewriteToolVersion: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.want {
				t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
		})
	}
}

// TestRewriteToolVersionScopesGoPrefixToTheToolchain pins whose versions the Go
// project's "go1.24" spelling belongs to. For the toolchain it is one release
// written two ways, so a fix planned from a locked 1.24.9 has to reach a config
// declaring go1.24. For every other tool a version is an opaque release tag: a
// project can publish both "go1.3.0" and "1.3.0" as different artifacts, and
// reading them as one release let the rewriter treat a config at 1.3.0 as
// already carrying a fix that asked for go1.3.0, reporting success without
// writing the requested tag. A silent no-op fix is worse than a refused one.
func TestRewriteToolVersionScopesGoPrefixToTheToolchain(t *testing.T) {
	tests := []struct {
		name     string
		tool     string
		input    string
		currents []string
		version  string
		// want is the expected file; wantErr means the rewrite must refuse
		// rather than claim success.
		want    string
		wantErr bool
	}{
		{
			// The toolchain: the declaration spells the release the Go way and
			// the plan the mise way.
			name: "the toolchain reaches a go-prefixed declaration",
			tool: "go",
			input: `[tools]
go = "go1.24"
`,
			currents: []string{"1.24.9"}, version: "1.24.10",
			want: `[tools]
go = "1.24.10"
`,
		},
		{
			// Already applied, spelled the Go way: still a no-op, and rightly.
			name: "the toolchain already at the target, spelled the Go way",
			tool: "go",
			input: `[tools]
go = "go1.24.10"
`,
			currents: []string{"1.24.9"}, version: "1.24.10",
			want: `[tools]
go = "go1.24.10"
`,
		},
		{
			// The reported defect: the requested tag is never written and the
			// rewrite must say so instead of reporting success.
			name: "an opaque tag is not the same release as its go-prefixed spelling",
			tool: "ubi:owner/repo",
			input: `[tools]
"ubi:owner/repo" = "1.3.0"
`,
			currents: []string{"1.2.0"}, version: "go1.3.0",
			want: `[tools]
"ubi:owner/repo" = "1.3.0"
`,
			wantErr: true,
		},
		{
			// The same tool, asked for the tag it actually declares: the fix
			// applies, so the scoping does not cost an ordinary tool anything.
			name: "an opaque tag is rewritten when the plan names it",
			tool: "ubi:owner/repo",
			input: `[tools]
"ubi:owner/repo" = "go1.2.0"
`,
			currents: []string{"go1.2.0"}, version: "go1.3.0",
			want: `[tools]
"ubi:owner/repo" = "go1.3.0"
`,
		},
		{
			// The go backend installs a Go module, whose versions are module
			// versions, so it does not get the toolchain's spelling either.
			name: "the go backend is not the toolchain",
			tool: "go:github.com/owner/repo",
			input: `[tools]
"go:github.com/owner/repo" = "1.3.0"
`,
			currents: []string{"1.2.0"}, version: "go1.3.0",
			want: `[tools]
"go:github.com/owner/repo" = "1.3.0"
`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			path := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(path, []byte(tt.input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = RewriteToolVersion(root, "mise.toml", tt.tool, tt.currents, tt.version)
			if tt.wantErr && err == nil {
				t.Error("the rewrite reported success without writing the requested version")
			}
			if !tt.wantErr && err != nil {
				t.Errorf("RewriteToolVersion: %v", err)
			}
			got, readErr := os.ReadFile(path)
			if readErr != nil {
				t.Fatal(readErr)
			}
			if string(got) != tt.want {
				t.Errorf("config mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, tt.want)
			}
		})
	}
}

// TestRewriteToolVersionReadsBareNumberDeclarations pins the rewriter against a
// version written as a bare TOML number. mise accepts one, and mise.Parse
// reports it through the decoder's own formatting, which is not the text in the
// file: `go = 1.220` and `go = 1.22_0` are both the number 1.22, and `node =
// 0x14` is 20. A rewriter comparing the token as written therefore saw a
// different version than the finding named and refused a fix for a declaration
// Deputy itself had inventoried.
//
// The declaration is replaced with a quoted version, which is what every other
// shape produces and what mise reads back identically.
func TestRewriteToolVersionReadsBareNumberDeclarations(t *testing.T) {
	tests := []struct {
		name string
		tool string
		// declaration is the line under [tools]; parsed is the version
		// mise.Parse reports for it, which is what a plan carries.
		declaration string
		parsed      string
		current     string
		version     string
		want        string
	}{
		{
			name: "a bare minor version", tool: "go",
			declaration: "go = 1.22", parsed: "1.22",
			current: "1.22.12", version: "1.24.3",
			want: `go = "1.24.3"`,
		},
		{
			name: "a bare integer", tool: "node",
			declaration: "node = 20", parsed: "20",
			current: "20.11.0", version: "20.11.1",
			want: `node = "20.11.1"`,
		},
		{
			// The formatting the decoder applies drops the trailing zero, so the
			// text and the inventoried version differ.
			name: "a trailing zero the decoder drops", tool: "go",
			declaration: "go = 1.220", parsed: "1.22",
			current: "1.22.12", version: "1.24.3",
			want: `go = "1.24.3"`,
		},
		{
			name: "digit separators", tool: "go",
			declaration: "go = 1.22_0", parsed: "1.22",
			current: "1.22.12", version: "1.24.3",
			want: `go = "1.24.3"`,
		},
		{
			name: "a hexadecimal integer", tool: "node",
			declaration: "node = 0x14", parsed: "20",
			current: "20.11.0", version: "20.11.1",
			want: `node = "20.11.1"`,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := "[tools]\n" + tt.declaration + "\n"
			// The premise: this is a declaration Deputy inventories, and at the
			// version the plan is written in.
			cfg, err := mise.Parse("mise.toml", []byte(input))
			if err != nil {
				t.Fatalf("fixture does not parse: %v", err)
			}
			if len(cfg.Tools) != 1 || cfg.Tools[0].Versions[0] != tt.parsed {
				t.Fatalf("fixture inventories %+v, want a single %q", cfg.Tools, tt.parsed)
			}

			dir := t.TempDir()
			path := filepath.Join(dir, "mise.toml")
			if err := os.WriteFile(path, []byte(input), 0o644); err != nil {
				t.Fatal(err)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			if err := RewriteToolVersion(root, "mise.toml", tt.tool, []string{tt.current}, tt.version); err != nil {
				t.Fatalf("RewriteToolVersion: %v", err)
			}
			got, err := os.ReadFile(path)
			if err != nil {
				t.Fatal(err)
			}
			if want := "[tools]\n" + tt.want + "\n"; string(got) != want {
				t.Errorf("rewrite mismatch:\n--- got ---\n%s\n--- want ---\n%s", got, want)
			}
			// And the result is still a config mise reads, at the new version.
			after, err := mise.Parse("mise.toml", got)
			if err != nil {
				t.Fatalf("rewritten config does not parse: %v", err)
			}
			if after.Tools[0].Versions[0] != tt.version {
				t.Errorf("rewritten config declares %q, want %q", after.Tools[0].Versions[0], tt.version)
			}
		})
	}
}
