package misex

import (
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"
	"time"

	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"

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

// TestExtractDoesNotBorrowAcrossSharedLockConfigs pins that a name declared by
// two configs writing to one mise.lock is contested even when both spell it
// identically. mise merges a mise directory's conf.d drop-ins into one
// lockfile, so a sole [[tools.go]] entry beside two fragments that both declare
// go belongs to at most one of them; enriching the other with it reports a
// version that fragment never declared, and after a fix on that fragment the
// borrowed entry reads as the vulnerable version coming back.
func TestExtractDoesNotBorrowAcrossSharedLockConfigs(t *testing.T) {
	const lock = "[[tools.go]]\nversion = \"1.23.4\"\nbackend = \"core:go\"\n"
	tests := []struct {
		name  string
		files fstest.MapFS
		want  string
	}{
		{
			name: "sole fragment owns the entry",
			files: fstest.MapFS{
				".config/mise/conf.d/a.toml": {Data: []byte("[tools]\ngo = \"1.22\"\n")},
				".config/mise/mise.lock":     {Data: []byte(lock)},
			},
			want: "1.23.4",
		},
		{
			name: "a fragment beside it declaring the same key contests it",
			files: fstest.MapFS{
				".config/mise/conf.d/a.toml": {Data: []byte("[tools]\ngo = \"1.22\"\n")},
				".config/mise/conf.d/b.toml": {Data: []byte("[tools]\ngo = \"1.23\"\n")},
				".config/mise/mise.lock":     {Data: []byte(lock)},
			},
			want: "1.22",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cfgPath = ".config/mise/conf.d/a.toml"
			f, err := tt.files.Open(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := New().Extract(t.Context(), &filesystem.ScanInput{Path: cfgPath, Reader: f, FS: tt.files})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(inv.Packages) != 1 {
				t.Fatalf("got %d packages, want 1", len(inv.Packages))
			}
			if got := inv.Packages[0].Version; got != tt.want {
				t.Errorf("go version = %q, want %q", got, tt.want)
			}
		})
	}
}

// TestExtractKeepsLockWhenAnotherConfigLocksOutsideTheTree pins the blast radius
// of an unresolvable neighbour. Enrichment needs to know who else could own a
// lock entry, and with that unresolved it sets the lockfile aside entirely, so
// the reported version falls back to the fuzzy declaration and the integrity
// metadata is lost. A config elsewhere in the repository whose own lockfile
// points outside the tree says nothing about this config's entries: it locks
// somewhere Deputy does not scan, so it cannot be a claimant here, and one such
// link must not cost every scan in the repository its exact locked versions.
func TestExtractKeepsLockWhenAnotherConfigLocksOutsideTheTree(t *testing.T) {
	const lock = "[[tools.go]]\nversion = \"1.24.9\"\nbackend = \"core:go\"\n\n" +
		"[tools.go.platforms.linux-x64]\nchecksum = \"sha256:goodgo\"\n"
	link := func(to string) *fstest.MapFile {
		return &fstest.MapFile{Mode: fs.ModeSymlink, Data: []byte(to)}
	}

	tests := []struct {
		name  string
		files fstest.MapFS
		// want is the version the extractor reports for the go declaration and
		// wantChecksum the integrity metadata it carries.
		want         string
		wantChecksum string
	}{
		{
			name: "a neighbour locking to an absolute path outside the tree",
			files: fstest.MapFS{
				"a/mise.toml": {Data: []byte("[tools]\ngo = \"1.24\"\n")},
				"a/mise.lock": {Data: []byte(lock)},
				"b/mise.toml": {Data: []byte("[tools]\nnode = \"20\"\n")},
				"b/mise.lock": link("/var/tmp/shared.lock"),
			},
			want:         "1.24.9",
			wantChecksum: "sha256:goodgo",
		},
		{
			name: "a neighbour locking above the root",
			files: fstest.MapFS{
				"a/mise.toml": {Data: []byte("[tools]\ngo = \"1.24\"\n")},
				"a/mise.lock": {Data: []byte(lock)},
				"b/mise.toml": {Data: []byte("[tools]\nnode = \"20\"\n")},
				"b/mise.lock": link("../../outside.lock"),
			},
			want:         "1.24.9",
			wantChecksum: "sha256:goodgo",
		},
		{
			// Ownership still decides: a neighbour that really does lock into
			// this file and declares the same tool contests the entry, so the
			// declaration is reported as written.
			name: "a neighbour locking into this file still contests it",
			files: fstest.MapFS{
				"a/mise.toml": {Data: []byte("[tools]\ngo = \"1.24\"\n")},
				"a/mise.lock": {Data: []byte(lock)},
				"b/mise.toml": {Data: []byte("[tools]\ngo = \"1.23\"\n")},
				"b/mise.lock": link("../a/mise.lock"),
			},
			want: "1.24",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			const cfgPath = "a/mise.toml"
			f, err := tt.files.Open(cfgPath)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := New().Extract(t.Context(), &filesystem.ScanInput{Path: cfgPath, Reader: f, FS: tt.files})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			if len(inv.Packages) != 1 {
				t.Fatalf("got %d packages, want 1", len(inv.Packages))
			}
			pkg := inv.Packages[0]
			if got := pkg.Version; got != tt.want {
				t.Errorf("go version = %q, want %q", got, tt.want)
			}
			md, ok := pkg.Metadata.(*mise.Metadata)
			if !ok {
				t.Fatalf("metadata is %T, want *mise.Metadata", pkg.Metadata)
			}
			if got := md.Checksums["linux-x64"]; got != tt.wantChecksum {
				t.Errorf("linux-x64 checksum = %q, want %q", got, tt.wantChecksum)
			}
		})
	}
}

// TestExtractNeverOpensALockfileOutsideTheTree pins the containment of the
// lockfile read a scan does. The filesystem a scan reads through follows a
// symlink wherever it points, absolute targets included, so a checkout whose
// mise.lock names a file outside the scan root had that file opened, read, and
// parsed as a lockfile: a host file read on an untrusted repository's behalf.
//
// The assertion is on the open, not on the version reported, because ownership
// resolution already refused to enrich from a lockfile it could not place, so the
// reported version looked right while the read had already happened.
func TestExtractNeverOpensALockfileOutsideTheTree(t *testing.T) {
	t.Parallel()

	outsideDir := t.TempDir()
	outside := filepath.Join(outsideDir, "host.lock")
	if err := os.WriteFile(outside, []byte("[[tools.go]]\nversion = \"1.0.0\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	tree := t.TempDir()
	if err := os.WriteFile(filepath.Join(tree, "mise.toml"), []byte("[tools]\ngo = \"1.24.3\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(outside, filepath.Join(tree, "mise.lock")); err != nil {
		t.Skipf("symlinks unavailable: %v", err)
	}

	// The filesystem of a real scan, scalibrfs.DirFS over the scan root, with
	// every open recorded.
	fsys := &recordingFS{FS: scalibrfs.DirFS(tree)}
	f, err := fsys.Open("mise.toml")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	inv, err := New().Extract(t.Context(), &filesystem.ScanInput{Path: "mise.toml", Reader: f, FS: fsys})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	if opened := fsys.openedPaths(); slices.Contains(opened, "mise.lock") {
		t.Errorf("the extractor opened the lockfile linking outside the tree; opens: %v", opened)
	}
	if len(inv.Packages) != 1 {
		t.Fatalf("Extract reported %d packages, want 1", len(inv.Packages))
	}
	pkg := inv.Packages[0]
	if pkg.Version != "1.24.3" {
		t.Errorf("go version = %q, want the declared 1.24.3", pkg.Version)
	}
	md, ok := pkg.Metadata.(*mise.Metadata)
	if !ok {
		t.Fatalf("metadata is %T, want *mise.Metadata", pkg.Metadata)
	}
	if md.LockedVersion != "" {
		t.Errorf("locked version = %q, want none: nothing outside the tree may enrich a scan", md.LockedVersion)
	}
}

// recordingFS is a scan filesystem that records which paths were opened, so a
// test can assert that a read never happened rather than inferring it from what
// the read would have changed.
type recordingFS struct {
	scalibrfs.FS

	mu     sync.Mutex
	opened []string
}

// Open records the path and delegates.
func (r *recordingFS) Open(name string) (fs.File, error) {
	r.mu.Lock()
	r.opened = append(r.opened, name)
	r.mu.Unlock()
	return r.FS.Open(name)
}

// Lstat delegates, keeping the wrapper an [fs.ReadLinkFS] like the filesystem it
// wraps: containment resolution needs to read links without following them, and a
// wrapper that hid that would test a filesystem a scan never uses.
func (r *recordingFS) Lstat(name string) (fs.FileInfo, error) {
	return r.FS.(fs.ReadLinkFS).Lstat(name)
}

// ReadLink delegates for the same reason as [recordingFS.Lstat].
func (r *recordingFS) ReadLink(name string) (string, error) {
	return r.FS.(fs.ReadLinkFS).ReadLink(name)
}

// openedPaths returns the paths opened so far.
func (r *recordingFS) openedPaths() []string {
	r.mu.Lock()
	defer r.mu.Unlock()
	return slices.Clone(r.opened)
}
