package mise

import (
	"os"
	"path/filepath"
	"slices"
	"strings"
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
			got, changed := replaceVersionInValue(tt.value, tt.pinned)
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
		{"subtracted selector on the current line", "sub-1:20", []string{"20.11.0"}, true},
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
			if got := selectorTargetsCurrent(tt.declared, tt.currents); got != tt.want {
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
