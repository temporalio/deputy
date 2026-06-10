package githubactions

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/pin"
)

// TestRewriteWorkflow_Golden runs golden file tests for the workflow rewriter.
// Each test case reads an input fixture from testdata/, applies updates, and
// compares the result against the corresponding .golden file.
func TestRewriteWorkflow_Golden(t *testing.T) {
	tests := []struct {
		name    string
		input   string // testdata filename (input)
		golden  string // testdata filename (expected output)
		updates []pin.Update
	}{
		{
			name:   "already pinned unchanged",
			input:  "already_pinned.yml",
			golden: "already_pinned.golden.yml",
			updates: []pin.Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
				{Name: "actions/setup-go", PinnedValue: "0aaccfd150d50ccaeb58ebd88d36e91967a5f35b", VersionTag: "v5.4.0"},
			},
		},
		{
			name:   "mixed refs pinned selectively",
			input:  "mixed.yml",
			golden: "mixed.golden.yml",
			updates: []pin.Update{
				{Name: "actions/checkout", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v4.2.2"},
				{Name: "actions/setup-go", PinnedValue: "def456abc123def456abc123def456abc123def4", VersionTag: "v5.4.0"},
			},
		},
		{
			name:   "quoted refs preserve quotes",
			input:  "quoted.yml",
			golden: "quoted.golden.yml",
			updates: []pin.Update{
				{Name: "actions/checkout", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v4.2.2"},
				{Name: "actions/setup-go", PinnedValue: "def456abc123def456abc123def456abc123def4", VersionTag: "v5.4.0"},
			},
		},
		{
			name:   "subpath actions",
			input:  "subpath.yml",
			golden: "subpath.golden.yml",
			updates: []pin.Update{
				{Name: "github/codeql-action/init", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v3.28.1"},
				{Name: "github/codeql-action/analyze", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v3.28.1"},
			},
		},
		{
			name:   "tag pinned with following content",
			input:  "tag_pinned.yml",
			golden: "tag_pinned.golden.yml",
			updates: []pin.Update{
				{Name: "actions/checkout", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v4.2.2"},
				{Name: "actions/setup-go", PinnedValue: "def456abc123def456abc123def456abc123def4", VersionTag: "v5.4.0"},
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			input := readTestdata(t, tc.input)
			want := readTestdata(t, tc.golden)

			root := writerTestRoot(t, "workflow.yml", input)

			if err := RewriteWorkflow(root, "workflow.yml", tc.updates); err != nil {
				t.Fatal(err)
			}

			got, err := fs.ReadFile(root.FS(), "workflow.yml")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != want {
				t.Errorf("output mismatch (-want +got):\n--- want\n%s\n--- got\n%s", want, string(got))
			}
		})
	}
}

// readTestdata reads a file from the testdata directory.
func readTestdata(t *testing.T, name string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("testdata", name))
	if err != nil {
		t.Fatalf("reading testdata/%s: %v", name, err)
	}
	return string(data)
}

func TestRewriteWorkflow_LocalAndDocker_Unchanged(t *testing.T) {
	input := `name: CI
on: push
jobs:
  test:
    steps:
      - uses: ./local-action
      - uses: docker://alpine:3.19
`
	root := writerTestRoot(t, "workflow.yml", input)

	if err := RewriteWorkflow(root, "workflow.yml", nil); err != nil {
		t.Fatal(err)
	}

	got, err := fs.ReadFile(root.FS(), "workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != input {
		t.Errorf("file was modified when it should not have been:\n%s", string(got))
	}
}

func TestRewriteWorkflow_PreservesIndentation(t *testing.T) {
	input := strings.Join([]string{
		"name: CI",
		"jobs:",
		"  test:",
		"    steps:",
		"      - uses: actions/checkout@v4",
		"      - uses:   actions/setup-go@v5",
		"",
	}, "\n")

	root := writerTestRoot(t, "workflow.yml", input)

	err := RewriteWorkflow(root, "workflow.yml", []pin.Update{
		{Name: "actions/checkout", PinnedValue: "aaaa0000" + strings.Repeat("0", 32), VersionTag: "v4.2.2"},
		{Name: "actions/setup-go", PinnedValue: "bbbb0000" + strings.Repeat("0", 32), VersionTag: "v5.4.0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := fs.ReadFile(root.FS(), "workflow.yml")
	if err != nil {
		t.Fatal(err)
	}

	if !strings.Contains(string(got), "actions/checkout@aaaa0000") {
		t.Error("checkout not pinned")
	}
	if !strings.Contains(string(got), "actions/setup-go@bbbb0000") {
		t.Error("setup-go not pinned")
	}
	lines := strings.SplitSeq(string(got), "\n")
	for line := range lines {
		if strings.Contains(line, "uses:") && !strings.HasPrefix(line, "      ") {
			t.Errorf("indentation changed: %q", line)
		}
	}
}

func TestRewriteWorkflow_PreservesPermissions(t *testing.T) {
	input := "name: CI\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n"
	tmp := t.TempDir()
	if err := os.WriteFile(filepath.Join(tmp, "workflow.yml"), []byte(input), 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = RewriteWorkflow(root, "workflow.yml", []pin.Update{
		{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
	})
	if err != nil {
		t.Fatal(err)
	}

	info, err := fs.Stat(root.FS(), "workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	perm := info.Mode().Perm()
	if perm&0o100 == 0 {
		t.Errorf("executable bit was lost, got %o", perm)
	}
}

func TestRewriteWorkflow_ValidatesInput(t *testing.T) {
	root := writerTestRoot(t, "workflow.yml", "uses: actions/checkout@v4")

	tests := []struct {
		name    string
		update  pin.Update
		wantErr string
	}{
		{
			name:    "empty name",
			update:  pin.Update{Name: "", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4"},
			wantErr: "empty action name",
		},
		{
			name:    "empty pinned value",
			update:  pin.Update{Name: "actions/checkout", PinnedValue: "", VersionTag: "v4"},
			wantErr: "empty pinned value",
		},
		{
			name:    "invalid SHA (too short)",
			update:  pin.Update{Name: "actions/checkout", PinnedValue: "abc123", VersionTag: "v4"},
			wantErr: "not a valid SHA",
		},
		{
			name:    "newline in version tag",
			update:  pin.Update{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4\nuses: evil@sha"},
			wantErr: "contains newlines",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RewriteWorkflow(root, "workflow.yml", []pin.Update{tc.update})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
