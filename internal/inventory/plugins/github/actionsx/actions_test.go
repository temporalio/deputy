package actionsx

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
)

func TestExtractor_Extract_Table(t *testing.T) {
	tests := []struct {
		name  string
		files map[string]string
		entry string
		want  []string
	}{
		{
			name: "remote and docker uses",
			files: map[string]string{
				".github/workflows/ci.yml": `
name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
`,
			},
			entry: ".github/workflows/ci.yml",
			want: []string{
				"docker|alpine|3.19",
				"githubactions|actions/checkout|v4",
			},
		},
		{
			name: "local composite and reusable workflow",
			files: map[string]string{
				".github/workflows/main.yml": `
name: main
on: push
jobs:
  build:
    steps:
      - uses: ./local-action
  call:
    uses: ./.github/workflows/reusable.yml
`,
				"local-action/action.yml": `
name: local-action
runs:
  using: composite
  steps:
    - uses: actions/setup-node@v4
`,
				".github/workflows/reusable.yml": `
on:
  workflow_call:
jobs:
  inner:
    steps:
      - uses: docker://busybox:1.36
`,
			},
			entry: ".github/workflows/main.yml",
			want: []string{
				"docker|busybox|1.36",
				"githubactions|actions/setup-node|v4",
			},
		},
		{
			name: "job-level reusable workflow remote",
			files: map[string]string{
				".github/workflows/call.yml": `
on: push
jobs:
  call:
    uses: octo-org/reusable/.github/workflows/build.yml@v2
`,
			},
			entry: ".github/workflows/call.yml",
			want: []string{
				"githubactions|octo-org/reusable|v2",
			},
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			tmp := t.TempDir()
			for p, c := range tc.files {
				writeFile(t, tmp, p, c)
			}
			fs := scalibrfs.DirFS(tmp)
			f, err := os.Open(filepath.Join(tmp, filepath.FromSlash(tc.entry)))
			if err != nil {
				t.Fatalf("open workflow: %v", err)
			}
			defer f.Close()
			ext := &Extractor{}
			inv, err := ext.Extract(context.Background(), &filesystem.ScanInput{
				FS:     fs,
				Path:   filepath.ToSlash(tc.entry),
				Reader: f,
			})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			got := packageKeys(inv.Packages)
			if !equalStrings(got, tc.want) {
				t.Fatalf("packages = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSplitUsesRef_Table(t *testing.T) {
	tests := []struct {
		raw string
		pre string
		ref string
	}{
		{"actions/checkout@v4", "actions/checkout", "v4"},
		{"owner/repo/path/to/action@main", "owner/repo/path/to/action", "main"},
		{"owner/repo", "owner/repo", ""},
		{" owner/repo@ ", "owner/repo", ""},
	}
	for _, tc := range tests {
		t.Run(tc.raw, func(t *testing.T) {
			pre, ref := splitUsesRef(tc.raw)
			if pre != tc.pre || ref != tc.ref {
				t.Fatalf("splitUsesRef(%q) = (%q,%q), want (%q,%q)", tc.raw, pre, ref, tc.pre, tc.ref)
			}
		})
	}
}

func TestSplitRepoAndSubpath_Table(t *testing.T) {
	tests := []struct {
		pre     string
		repo    string
		subpath string
		ok      bool
	}{
		{"actions/checkout", "actions/checkout", "", true},
		{"owner/repo/path/to/action", "owner/repo", "path/to/action", true},
		{"/owner/repo/", "owner/repo", "", true},
		{"justone", "", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.pre, func(t *testing.T) {
			repo, sub, ok := splitRepoAndSubpath(tc.pre)
			if ok != tc.ok || repo != tc.repo || sub != tc.subpath {
				t.Fatalf("splitRepoAndSubpath(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.pre, repo, sub, ok, tc.repo, tc.subpath, tc.ok)
			}
		})
	}
}

func TestSplitDockerRef_Table(t *testing.T) {
	tests := []struct {
		ref       string
		name      string
		version   string
		hasDigest bool
	}{
		{"alpine:3.19", "alpine", "3.19", false},
		{"ghcr.io/org/img@sha256:deadbeef", "ghcr.io/org/img", "sha256:deadbeef", true},
		{"org/img:latest", "org/img", "latest", false},
		{"busybox", "busybox", "", false},
		{"", "", "", false},
	}
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			name, ver, digest := splitDockerRef(tc.ref)
			if name != tc.name || ver != tc.version || digest != tc.hasDigest {
				t.Fatalf("splitDockerRef(%q) = (%q,%q,%v), want (%q,%q,%v)", tc.ref, name, ver, digest, tc.name, tc.version, tc.hasDigest)
			}
		})
	}
}

func TestResolveLocalCandidates_Table(t *testing.T) {
	s := newParseState(nil)
	tests := []struct {
		parent string
		rel    string
		want   []string
	}{
		{".github/workflows/a.yml", "./local-action", []string{"local-action", ".github/workflows/local-action"}},
		{".github/workflows/a.yml", "./.github/workflows/reusable.yml", []string{".github/workflows/reusable.yml", ".github/workflows/.github/workflows/reusable.yml"}},
		{".github/workflows/a.yml", "../nope", []string{".github/nope"}},
	}
	for _, tc := range tests {
		t.Run(tc.rel, func(t *testing.T) {
			got := s.resolveLocalCandidates(tc.parent, tc.rel)
			if !equalStrings(got, tc.want) {
				t.Fatalf("resolveLocalCandidates(%q,%q) = %v, want %v", tc.parent, tc.rel, got, tc.want)
			}
		})
	}
}

func writeFile(t *testing.T, root, rel, content string) {
	t.Helper()
	full := filepath.Join(root, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
		t.Fatalf("mkdir: %v", err)
	}
	if err := os.WriteFile(full, []byte(strings.TrimSpace(content)+"\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", rel, err)
	}
}

func packageKeys(pkgs []*extractor.Package) []string {
	var out []string
	for _, p := range pkgs {
		if p == nil {
			continue
		}
		out = append(out, strings.ToLower(p.PURLType)+"|"+p.Name+"|"+p.Version)
	}
	slices.Sort(out)
	return out
}

func equalStrings(a, b []string) bool {
	return slices.Equal(a, b)
}
