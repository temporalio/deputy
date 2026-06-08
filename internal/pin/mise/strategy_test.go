package mise

import (
	"context"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/temporalio/deputy/internal/pin"
)

// fakeResolver returns canned exact versions keyed by "tool@prefix".
type fakeResolver struct {
	versions map[string]string
}

func (f fakeResolver) Latest(_ context.Context, toolKey, prefix string) (string, error) {
	if v, ok := f.versions[toolKey+"@"+prefix]; ok {
		return v, nil
	}
	return f.versions[toolKey], nil
}

func TestIsPinned(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{})
	if !s.IsPinned(pin.Ref{Version: "20.11.0"}) {
		t.Error("20.11.0 should be pinned")
	}
	if !s.IsPinned(pin.Ref{Name: "aqua:protocolbuffers/protobuf/protoc", Version: "33.1"}) {
		t.Error("33.1 should be pinned for GitHub-release-family tools when it is a final release tag")
	}
	if !s.IsPinned(pin.Ref{Name: "protoc", Version: "33.1"}) {
		t.Error("33.1 should be pinned for bare GitHub-release registry aliases")
	}
	if s.IsPinned(pin.Ref{Version: "20"}) {
		t.Error("20 should not be pinned")
	}
	if s.IsPinned(pin.Ref{Name: "terraform", Version: "1.9"}) {
		t.Error("terraform 1.9 should not be pinned")
	}
}

func TestShouldSkip(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{})
	tests := []struct {
		version  string
		wantSkip bool
	}{
		{"20", false},
		{"latest", false},
		{"3.11,3.12", true}, // array sentinel
		{"system", true},
		{"file:../local", true},
		{"ref:abc", true},
		{"path:/x", true},
		{"prefix:20", false},
		{"sub-2:lts", false},
		{"", true},
	}
	for _, tt := range tests {
		skip, _ := s.ShouldSkip(pin.Ref{Version: tt.version})
		if skip != tt.wantSkip {
			t.Errorf("ShouldSkip(%q) = %v, want %v", tt.version, skip, tt.wantSkip)
		}
	}
}

func TestResolve(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"node@20": "20.11.0",
	}})
	pinned, tag, err := s.Resolve(t.Context(), pin.Ref{Name: "node", Version: "20"})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pinned != "20.11.0" || tag != "20" {
		t.Errorf("Resolve = (%q,%q), want (20.11.0, 20)", pinned, tag)
	}
}

func TestResolveRejectsNonConcrete(t *testing.T) {
	// A resolver returning a bare major-only prefix ("20") or a channel is not a
	// usable pin and must error.
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{"node@20": "20"}})
	if _, _, err := s.Resolve(t.Context(), pin.Ref{Name: "node", Version: "20"}); err == nil {
		t.Error("expected error when resolver returns a non-concrete version")
	}
}

func TestResolveAcceptsPartialFinalVersion(t *testing.T) {
	// protobuf-style tools publish 2-part-final versions (e.g. "33.1"); pin must
	// accept the resolver's authoritative output rather than demanding 3 parts.
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"aqua:protocolbuffers/protobuf/protoc@33": "33.1",
	}})
	pinned, _, err := s.Resolve(t.Context(), pin.Ref{Name: "aqua:protocolbuffers/protobuf/protoc", Version: "33"})
	if err != nil {
		t.Fatalf("Resolve should accept partial-but-final version: %v", err)
	}
	if pinned != "33.1" {
		t.Errorf("Resolve = %q, want 33.1", pinned)
	}
}

func TestResolvePrefersLockedVersion(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"terraform@1.9": "1.9.8",
	}})
	pinned, tag, err := s.Resolve(t.Context(), pin.Ref{
		Name:          "terraform",
		Version:       "1.9",
		LockedVersion: "1.9.6",
	})
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if pinned != "1.9.6" || tag != "1.9" {
		t.Errorf("Resolve = (%q,%q), want (1.9.6,1.9)", pinned, tag)
	}
}

func TestResolveUpdate(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"node@20": "20.20.2",
	}})
	pinned, newTag, curTag, err := s.ResolveUpdate(t.Context(), pin.Ref{Name: "node", Version: "20.11.0"})
	if err != nil {
		t.Fatalf("ResolveUpdate: %v", err)
	}
	if pinned != "20.20.2" || newTag != "20.20.2" || curTag != "20.11.0" {
		t.Errorf("ResolveUpdate = (%q,%q,%q)", pinned, newTag, curTag)
	}
}

func TestResolveUpdateTemurinJava(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"java@temurin-21": "temurin-21.0.11+10.0.LTS",
	}})
	pinned, newTag, curTag, err := s.ResolveUpdate(t.Context(), pin.Ref{Name: "java", Version: "temurin-21.0.10+7.0.LTS"})
	if err != nil {
		t.Fatalf("ResolveUpdate: %v", err)
	}
	if pinned != "temurin-21.0.11+10.0.LTS" || newTag != "temurin-21.0.11+10.0.LTS" || curTag != "temurin-21.0.10+7.0.LTS" {
		t.Errorf("ResolveUpdate = (%q,%q,%q)", pinned, newTag, curTag)
	}
}

func TestResolveUpdateOpenJDKJavaShorthand(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"java@21": "21.0.2",
	}})
	pinned, newTag, curTag, err := s.ResolveUpdate(t.Context(), pin.Ref{Name: "java", Version: "21.0.2"})
	if err != nil {
		t.Fatalf("ResolveUpdate: %v", err)
	}
	if pinned != "21.0.2" || newTag != "21.0.2" || curTag != "21.0.2" {
		t.Errorf("ResolveUpdate = (%q,%q,%q)", pinned, newTag, curTag)
	}
}

func TestResolveUpdateIgnoresLockedVersion(t *testing.T) {
	s := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"terraform@1": "1.9.8",
	}})
	pinned, newTag, curTag, err := s.ResolveUpdate(t.Context(), pin.Ref{
		Name:          "terraform",
		Version:       "1.9.6",
		LockedVersion: "1.9.6",
	})
	if err != nil {
		t.Fatalf("ResolveUpdate: %v", err)
	}
	if pinned != "1.9.8" || newTag != "1.9.8" || curTag != "1.9.6" {
		t.Errorf("ResolveUpdate = (%q,%q,%q), want (1.9.8,1.9.8,1.9.6)", pinned, newTag, curTag)
	}
}

func TestAsdfDiscover(t *testing.T) {
	fsys := fstest.MapFS{
		".tool-versions":     {Data: []byte("nodejs 22.14.0\ngolang 1.26.2\npython 3.11 3.12\n")},
		"sub/.tool-versions": {Data: []byte("ruby 3.3.0\n")},
		"mise.toml":          {Data: []byte("[tools]\nnode = \"20\"\n")}, // mise, not asdf
	}
	s := NewAsdfStrategyWithResolver(fakeResolver{})
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got := map[string]string{}
	for _, r := range refs {
		if r.Ecosystem != AsdfEcosystem {
			t.Errorf("ref %q ecosystem = %q, want asdf", r.Name, r.Ecosystem)
		}
		got[r.FilePath+"|"+r.Name] = r.Version
	}
	want := map[string]string{
		".tool-versions|nodejs":   "22.14.0",
		".tool-versions|golang":   "1.26.2",
		".tool-versions|python":   "3.11,3.12", // array sentinel
		"sub/.tool-versions|ruby": "3.3.0",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d refs %v, want %d", len(got), got, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ref %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestDiscover(t *testing.T) {
	fsys := fstest.MapFS{
		"mise.toml": {Data: []byte(`
[tools]
node = "20"
python = ["3.11", "3.12"]
terraform = "1.9.8"
`)},
		"mise.local.toml": {Data: []byte("[tools]\nnode = \"18\"\n")}, // skipped (local)
		"sub/mise.toml":   {Data: []byte("[tools]\ngo = \"1.24\"\n")},
		".tool-versions":  {Data: []byte("ruby 3.3.0\n")}, // asdf, not mise pin
	}
	s := NewStrategyWithResolver(fakeResolver{})
	refs, err := s.Discover(t.Context(), fsys)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}
	got := map[string]string{}
	for _, r := range refs {
		got[r.FilePath+"|"+r.Name] = r.Version
	}
	want := map[string]string{
		"mise.toml|node":      "20",
		"mise.toml|python":    "3.11,3.12", // array joined with sentinel
		"mise.toml|terraform": "1.9.8",
		"sub/mise.toml|go":    "1.24",
	}
	if len(got) != len(want) {
		keys := make([]string, 0, len(got))
		for k := range got {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		t.Fatalf("Discover got %d refs %v, want %d", len(got), keys, len(want))
	}
	for k, v := range want {
		if got[k] != v {
			t.Errorf("ref %q = %q, want %q", k, got[k], v)
		}
	}
}

func TestDiscoverAddsCompatibleLockedVersion(t *testing.T) {
	fsys := fstest.MapFS{
		"mise.toml": {Data: []byte(`
[tools]
go = "go1.24"
node = "latest"
python = "3.13"
terraform = "1.9"
"npm:prettier" = "3"
`)},
		"mise.lock": {Data: []byte(`
[[tools.go]]
version = "1.24.9"

[[tools.node]]
version = "22.17.1"

[[tools.python]]
version = "3.14.0"

[[tools.terraform]]
version = "1.9.6"

[[tools."npm:prettier"]]
version = "3.6.2"
`)},
	}

	refs, err := NewStrategyWithResolver(fakeResolver{}).Discover(t.Context(), fsys)
	if err != nil {
		t.Fatalf("Discover: %v", err)
	}

	got := map[string]string{}
	for _, r := range refs {
		got[r.Name] = r.LockedVersion
	}
	want := map[string]string{
		"go":           "1.24.9",
		"node":         "22.17.1",
		"python":       "", // stale: declaration is 3.13, lock has 3.14.
		"terraform":    "1.9.6",
		"npm:prettier": "3.6.2",
	}
	for name, wantLocked := range want {
		if got[name] != wantLocked {
			t.Errorf("locked version for %s = %q, want %q", name, got[name], wantLocked)
		}
	}
}

func TestPinWritesLockedVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mise.toml", `
[tools]
terraform = "1.9"
`)
	writeFile(t, dir, "mise.lock", `
[[tools.terraform]]
version = "1.9.6"
`)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })

	strategy := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"terraform@1.9": "1.9.8",
	}})
	report, err := pin.Pin(t.Context(), root, pin.Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatalf("Pin: %v", err)
	}
	if report.Stats.Pinned != 1 || report.Results[0].PinnedValue != "1.9.6" {
		t.Fatalf("Pin result = %+v, want pinned 1.9.6", report.Results)
	}
	assertFileContains(t, dir, "mise.toml", `terraform = "1.9.6"`)
}

func TestPinUpdateMovesLockedExactVersion(t *testing.T) {
	dir := t.TempDir()
	writeFile(t, dir, "mise.toml", `
[tools]
terraform = "1.9.6"
`)
	writeFile(t, dir, "mise.lock", `
[[tools.terraform]]
version = "1.9.6"
`)
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })

	strategy := NewStrategyWithResolver(fakeResolver{versions: map[string]string{
		"terraform@1": "1.9.8",
	}})
	report, err := pin.PinUpdate(t.Context(), root, pin.Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatalf("PinUpdate: %v", err)
	}
	if report.Stats.Updated != 1 || report.Results[0].PinnedValue != "1.9.8" {
		t.Fatalf("PinUpdate result = %+v, want updated 1.9.8", report.Results)
	}
	assertFileContains(t, dir, "mise.toml", `terraform = "1.9.8"`)
}

func writeFile(t *testing.T, dir, name, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", name, err)
	}
}

func assertFileContains(t *testing.T, dir, name, want string) {
	t.Helper()
	got, err := os.ReadFile(filepath.Join(dir, name))
	if err != nil {
		t.Fatalf("read %s: %v", name, err)
	}
	if !strings.Contains(string(got), want) {
		t.Fatalf("%s = %q, want it to contain %q", name, got, want)
	}
}
