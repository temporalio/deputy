package misex

import (
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

type mockFileAPI struct{ path string }

func (m *mockFileAPI) Path() string { return m.path }
func (m *mockFileAPI) Stat() (fs.FileInfo, error) {
	return &mockFileInfo{name: m.path}, nil
}

type mockFileInfo struct{ name string }

func (m *mockFileInfo) Name() string       { return m.name }
func (m *mockFileInfo) Size() int64        { return 0 }
func (m *mockFileInfo) Mode() fs.FileMode  { return 0o644 }
func (m *mockFileInfo) ModTime() time.Time { return time.Time{} }
func (m *mockFileInfo) IsDir() bool        { return false }
func (m *mockFileInfo) Sys() any           { return nil }

func TestFileRequired(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"mise.toml", true},
		{".mise.toml", true},
		{"mise.local.toml", true},
		{"sub/dir/mise.toml", true},
		{".config/mise/config.toml", true},
		{".tool-versions", false}, // handled by asdf extractor
		{"go.mod", false},
		{"random.toml", false},
	}
	ext := New()
	for _, tt := range tests {
		if got := ext.FileRequired(&mockFileAPI{path: tt.path}); got != tt.want {
			t.Errorf("FileRequired(%q) = %v, want %v", tt.path, got, tt.want)
		}
	}
}

func TestExtract(t *testing.T) {
	content := `
[tools]
node = "22.5.0"
python = ["3.11", "3.12"]
"npm:prettier" = "3.3.0"
terraform = "1.9"
`
	ext := New()
	inv, err := ext.Extract(t.Context(), &filesystem.ScanInput{
		Path:   "mise.toml",
		Reader: strings.NewReader(content),
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	// node(1) + python(2) + prettier(1) + terraform(1) = 5
	if len(inv.Packages) != 5 {
		t.Fatalf("got %d packages, want 5", len(inv.Packages))
	}

	byKey := map[string]string{} // name@version -> purl
	for _, p := range inv.Packages {
		if p.PURLType != purlx.TypeMise {
			t.Errorf("package %q has PURLType %q, want %q", p.Name, p.PURLType, purlx.TypeMise)
		}
		byKey[p.Name+"@"+p.Version] = purlx.MisePURL(p.Name, p.Version)

		md, ok := p.Metadata.(*mise.Metadata)
		if !ok {
			t.Fatalf("package %q metadata type = %T, want *mise.Metadata", p.Name, p.Metadata)
		}
		switch p.Name {
		case "npm:prettier":
			if md.Backend != "npm" || md.Tool != "prettier" {
				t.Errorf("prettier backend/tool = %q/%q", md.Backend, md.Tool)
			}
			if md.BackendPURL != "pkg:npm/prettier@3.3.0" {
				t.Errorf("prettier BackendPURL = %q, want pkg:npm/prettier@3.3.0", md.BackendPURL)
			}
			if md.Fuzzy {
				t.Errorf("prettier should be exact")
			}
		case "terraform":
			if !md.Fuzzy {
				t.Errorf("terraform = %q should be fuzzy (partial version)", p.Version)
			}
			if md.BackendPURL != "" {
				t.Errorf("terraform BackendPURL = %q, want empty (no registry backend)", md.BackendPURL)
			}
		case "node":
			if md.Fuzzy || md.Backend != "" {
				t.Errorf("node fuzzy/backend = %v/%q", md.Fuzzy, md.Backend)
			}
		}
	}
	if _, ok := byKey["node@22.5.0"]; !ok {
		t.Errorf("missing node@22.5.0")
	}
	if _, ok := byKey["python@3.12"]; !ok {
		t.Errorf("missing python@3.12")
	}
}

func TestExtractEnrichesFromLockfile(t *testing.T) {
	fsys := fstest.MapFS{
		"mise.toml": {Data: []byte("[tools]\nnode = \"20\"\n")},
		"mise.lock": {Data: []byte(`
[[tools.node]]
version = "20.11.0"
backend = "core:node"

[tools.node.platforms.linux-x64]
checksum = "sha256:abc123"
`)},
	}
	ext := New()
	f, err := fsys.Open("mise.toml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ext.Extract(t.Context(), &filesystem.ScanInput{
		Path:   "mise.toml",
		Reader: f,
		FS:     fsys,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(inv.Packages))
	}
	md := inv.Packages[0].Metadata.(*mise.Metadata)
	// Package identity uses the exact lockfile version; metadata preserves the
	// requested fuzzy selector for policy and remediation context.
	if inv.Packages[0].Version != "20.11.0" {
		t.Errorf("version = %q, want 20.11.0", inv.Packages[0].Version)
	}
	if md.Version != "20" {
		t.Errorf("metadata Version = %q, want 20", md.Version)
	}
	if md.LockedVersion != "20.11.0" {
		t.Errorf("LockedVersion = %q, want 20.11.0", md.LockedVersion)
	}
	if md.Checksums["linux-x64"] != "sha256:abc123" {
		t.Errorf("Checksums = %v", md.Checksums)
	}
}

func TestExtractLockfileUpdatesBackendPURL(t *testing.T) {
	fsys := fstest.MapFS{
		"mise.toml": {Data: []byte("[tools]\n\"npm:prettier\" = \"latest\"\n")},
		"mise.lock": {Data: []byte(`
[[tools."npm:prettier"]]
version = "3.8.1"
backend = "npm:prettier"
`)},
	}
	ext := New()
	f, err := fsys.Open("mise.toml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := ext.Extract(t.Context(), &filesystem.ScanInput{
		Path:   "mise.toml",
		Reader: f,
		FS:     fsys,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("got %d packages, want 1", len(inv.Packages))
	}
	if inv.Packages[0].Version != "3.8.1" {
		t.Errorf("version = %q, want 3.8.1", inv.Packages[0].Version)
	}
	md, ok := inv.Packages[0].Metadata.(*mise.Metadata)
	if !ok {
		t.Fatalf("metadata type = %T, want *mise.Metadata", inv.Packages[0].Metadata)
	}
	if md.Version != "latest" {
		t.Errorf("metadata Version = %q, want latest", md.Version)
	}
	if md.BackendPURL != "pkg:npm/prettier@3.8.1" {
		t.Errorf("BackendPURL = %q, want pkg:npm/prettier@3.8.1", md.BackendPURL)
	}
}

// TestExtractDoesNotBorrowAnotherToolsLockEntry pins that a backend-qualified
// tool is not enriched from a lock entry a different declaration could own.
// Sharing the entry made a fixed "npm:node" declaration report the untouched
// core node version, so an applied fix still looked vulnerable. Ownership is
// decided on the backend-stripped name, so two qualified declarations that
// strip to the same name are as contested as a bare declaration of it: neither
// may borrow the entry, which is also the case where lock pruning deliberately
// leaves the ambiguous entry in place.
func TestExtractDoesNotBorrowAnotherToolsLockEntry(t *testing.T) {
	tests := []struct {
		name   string
		config string
		lock   string
		want   map[string]string
	}{
		{
			name:   "qualified and bare declaration",
			config: "[tools]\n\"npm:node\" = \"20.12.0\"\nnode = \"20.11.0\"\n",
			lock:   "[[tools.node]]\nversion = \"20.11.0\"\nbackend = \"core:node\"\n",
			want:   map[string]string{"npm:node": "20.12.0", "node": "20.11.0"},
		},
		{
			name:   "two qualified declarations of one short name",
			config: "[tools]\n\"npm:foo\" = \"1.2.3\"\n\"ubi:foo\" = \"4.5.6\"\n",
			lock:   "[[tools.foo]]\nversion = \"0.9.0\"\nbackend = \"npm:foo\"\n",
			want:   map[string]string{"npm:foo": "1.2.3", "ubi:foo": "4.5.6"},
		},
		{
			name:   "sole qualified declaration still matches the short name",
			config: "[tools]\n\"npm:foo\" = \"1.2.3\"\n",
			lock:   "[[tools.foo]]\nversion = \"0.9.0\"\nbackend = \"npm:foo\"\n",
			want:   map[string]string{"npm:foo": "0.9.0"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			fsys := fstest.MapFS{
				"mise.toml": {Data: []byte(tt.config)},
				"mise.lock": {Data: []byte(tt.lock)},
			}
			f, err := fsys.Open("mise.toml")
			if err != nil {
				t.Fatal(err)
			}
			inv, err := New().Extract(t.Context(), &filesystem.ScanInput{Path: "mise.toml", Reader: f, FS: fsys})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}

			got := map[string]string{}
			for _, pkg := range inv.Packages {
				got[pkg.Name] = pkg.Version
			}
			for name, want := range tt.want {
				if got[name] != want {
					t.Errorf("%s version = %q, want %q", name, got[name], want)
				}
			}
		})
	}
}
