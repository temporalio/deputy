package mise

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

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

func TestRewriteToolVersion(t *testing.T) {
	tests := []struct {
		name    string
		input   string
		tool    string
		current string
		version string
		want    string
		wantErr bool
	}{
		{
			name: "scalar with comment",
			input: `[tools]
go = "1.22.12" # toolchain
`,
			tool: "go", current: "1.22.12", version: "1.24.3",
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
			tool: "go", current: "1.22.12", version: "1.24.3",
			want: `[tools]
go = ["1.24.3", "1.23.8"]
`,
		},
		{
			name: "multi-version array second element with comment",
			input: `[tools]
go = ["1.22.12", "1.23.8"] # test matrix
`,
			tool: "go", current: "1.23.8", version: "1.24.3",
			want: `[tools]
go = ["1.22.12", "1.24.3"] # test matrix
`,
		},
		{
			name: "multi-version array bare elements",
			input: `[tools]
node = [20, 22]
`,
			tool: "node", current: "20", version: "20.11.1",
			want: `[tools]
node = ["20.11.1", 22]
`,
		},
		{
			name: "multi-version array without current fails closed",
			input: `[tools]
go = ["1.22.12", "1.23.8"]
`,
			tool: "go", current: "", version: "1.24.3",
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
			tool: "go", current: "1.21.0", version: "1.24.3",
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
			tool: "go", current: "", version: "1.24.3",
			want: `[tools]
go = ["1.24.3"]
`,
		},
		{
			name: "tools subtable version key",
			input: `[tools.go]
version = "1.22.12"
`,
			tool: "go", current: "1.22.12", version: "1.24.3",
			want: `[tools.go]
version = "1.24.3"
`,
		},
		{
			name: "undeclared tool fails",
			input: `[tools]
node = "20.11.1"
`,
			tool: "go", current: "1.22.12", version: "1.24.3",
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
			tool: "go", current: "1.22.12", version: "latest",
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

			err = RewriteToolVersion(root, "mise.toml", tt.tool, tt.current, tt.version)
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
