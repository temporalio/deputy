package pin

import (
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// writerTestRoot creates a temp directory with a file, opens an os.Root,
// and returns the root and a cleanup function. Writer tests need real files
// because they test actual file writes and permission preservation.
func writerTestRoot(t *testing.T, relPath, content string) *os.Root {
	t.Helper()
	tmp := t.TempDir()
	full := filepath.Join(tmp, filepath.FromSlash(relPath))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestRewriteWorkflow(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		updates  []Update
		expected string
	}{
		{
			name: "pin tag to SHA with comment",
			input: `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
`,
		},
		{
			name: "multiple actions in one file",
			input: `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v5
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
				{Name: "actions/setup-go", PinnedValue: "0aaccfd150d50ccaeb58ebd88d36e91967a5f35b", VersionTag: "v5.4.0"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-go@0aaccfd150d50ccaeb58ebd88d36e91967a5f35b # v5.4.0
`,
		},
		{
			name: "replace existing comment",
			input: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: actions/checkout@abc123def456abc123def456abc123def456abc1 # v4.1.0
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
`,
		},
		{
			name: "double-quoted uses",
			input: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: "actions/checkout@v4"
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683" # v4.2.2
`,
		},
		{
			name: "single-quoted uses",
			input: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: 'actions/checkout@v4'
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: 'actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683' # v4.2.2
`,
		},
		{
			name: "subpath action",
			input: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: github/codeql-action/init@v3
`,
			updates: []Update{
				{Name: "github/codeql-action/init", PinnedValue: "abc123def456abc123def456abc123def456abc1", VersionTag: "v3.28.1"},
			},
			expected: `name: CI
on: push
jobs:
  test:
    steps:
      - uses: github/codeql-action/init@abc123def456abc123def456abc123def456abc1 # v3.28.1
`,
		},
		{
			name: "preserves surrounding content",
			input: `# This is a workflow
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0
      - name: Run tests
        run: go test ./...
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `# This is a workflow
name: CI
on: push
jobs:
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
        with:
          fetch-depth: 0
      - name: Run tests
        run: go test ./...
`,
		},
		{
			name:  "no match returns nil error (no modification needed)",
			input: `name: CI`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI`,
		},
		{
			name: "duplicate action pinned consistently",
			input: `name: CI
on: push
jobs:
  a:
    steps:
      - uses: actions/checkout@v4
  b:
    steps:
      - uses: actions/checkout@v4
`,
			updates: []Update{
				{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4.2.2"},
			},
			expected: `name: CI
on: push
jobs:
  a:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
  b:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
`,
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			root := writerTestRoot(t, "workflow.yml", tc.input)

			err := RewriteWorkflow(root, "workflow.yml", tc.updates)
			if err != nil {
				t.Fatal(err)
			}

			got, err := fs.ReadFile(root.FS(), "workflow.yml")
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tc.expected {
				t.Errorf("output mismatch:\ngot:\n%s\nwant:\n%s", string(got), tc.expected)
			}
		})
	}
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

	err := RewriteWorkflow(root, "workflow.yml", nil)
	if err != nil {
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

	err := RewriteWorkflow(root, "workflow.yml", []Update{
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
	lines := strings.Split(string(got), "\n")
	for _, line := range lines {
		if strings.Contains(line, "uses:") && !strings.HasPrefix(line, "      ") {
			t.Errorf("indentation changed: %q", line)
		}
	}
}

func TestRewriteWorkflow_PreservesPermissions(t *testing.T) {
	input := "name: CI\njobs:\n  test:\n    steps:\n      - uses: actions/checkout@v4\n"
	tmp := t.TempDir()
	// Create with non-default permissions
	if err := os.WriteFile(filepath.Join(tmp, "workflow.yml"), []byte(input), 0o755); err != nil {
		t.Fatal(err)
	}

	root, err := os.OpenRoot(tmp)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	err = RewriteWorkflow(root, "workflow.yml", []Update{
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

func TestRewriteWorkflow_BranchRef(t *testing.T) {
	// Branch refs like @main should be pinnable just like tags.
	input := `name: CI
on: push
jobs:
  test:
    steps:
      - uses: picatz/deputy/actions/setup@main
`
	root := writerTestRoot(t, "workflow.yml", input)

	err := RewriteWorkflow(root, "workflow.yml", []Update{
		{Name: "picatz/deputy/actions/setup", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "main"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := fs.ReadFile(root.FS(), "workflow.yml")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(got), "@11bd71901bbe5b1630ceea73d27597364c9af683 # main") {
		t.Errorf("expected branch ref to be pinned:\n%s", string(got))
	}
}

func TestRewriteWorkflow_MixedPinnedAndUnpinned(t *testing.T) {
	// File with both already-pinned and unpinned actions; only update the specified ones.
	input := `name: CI
on: push
jobs:
  test:
    steps:
      - uses: actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2
      - uses: actions/setup-go@v5
      - uses: picatz/deputy/actions/scan@main
`
	root := writerTestRoot(t, "workflow.yml", input)

	err := RewriteWorkflow(root, "workflow.yml", []Update{
		{Name: "actions/setup-go", PinnedValue: "aabbccdd11223344556677889900aabbccddeeff", VersionTag: "v5.4.0"},
	})
	if err != nil {
		t.Fatal(err)
	}

	got, err := fs.ReadFile(root.FS(), "workflow.yml")
	if err != nil {
		t.Fatal(err)
	}

	content := string(got)
	// Already-pinned checkout should remain unchanged.
	if !strings.Contains(content, "actions/checkout@11bd71901bbe5b1630ceea73d27597364c9af683 # v4.2.2") {
		t.Error("already-pinned checkout should not have been modified")
	}
	// setup-go should be pinned.
	if !strings.Contains(content, "actions/setup-go@aabbccdd11223344556677889900aabbccddeeff # v5.4.0") {
		t.Error("setup-go should have been pinned")
	}
	// @main ref should remain unchanged (not in updates).
	if !strings.Contains(content, "picatz/deputy/actions/scan@main") {
		t.Error("scan@main should not have been modified")
	}
}

func TestRewriteWorkflow_ValidatesInput(t *testing.T) {
	root := writerTestRoot(t, "workflow.yml", "uses: actions/checkout@v4")

	tests := []struct {
		name    string
		update  Update
		wantErr string
	}{
		{
			name:    "empty name",
			update:  Update{Name: "", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4"},
			wantErr: "empty action name",
		},
		{
			name:    "empty pinned value",
			update:  Update{Name: "actions/checkout", PinnedValue: "", VersionTag: "v4"},
			wantErr: "empty pinned value",
		},
		{
			name:    "invalid SHA (too short)",
			update:  Update{Name: "actions/checkout", PinnedValue: "abc123", VersionTag: "v4"},
			wantErr: "not a valid SHA",
		},
		{
			name:    "newline in version tag",
			update:  Update{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4\nuses: evil@sha"},
			wantErr: "contains newlines",
		},
		{
			name:    "carriage return in version tag",
			update:  Update{Name: "actions/checkout", PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683", VersionTag: "v4\ruses: evil@sha"},
			wantErr: "contains newlines",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			err := RewriteWorkflow(root, "workflow.yml", []Update{tc.update})
			if err == nil {
				t.Fatal("expected error")
			}
			if !strings.Contains(err.Error(), tc.wantErr) {
				t.Errorf("error %q does not contain %q", err.Error(), tc.wantErr)
			}
		})
	}
}
