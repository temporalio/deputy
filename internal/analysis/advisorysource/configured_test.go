package advisorysource

import (
	"strings"
	"testing"
)

func TestAllSourceConfigsUnionsAndDedupes(t *testing.T) {
	t.Setenv(EnvAdvisorySources, "prog-a, prog-b")
	SetConfiguredSources([]SourceConfig{
		{Program: "prog-a"}, // duplicate of env entry
		{URL: "https://feed.example"},
	})
	t.Cleanup(func() { SetConfiguredSources(nil) })

	got := allSourceConfigs()
	want := []SourceConfig{
		{Program: "prog-a"},
		{URL: "https://feed.example"},
		{Program: "prog-b"},
	}
	if len(got) != len(want) {
		t.Fatalf("configs = %+v, want %+v", got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("configs[%d] = %+v, want %+v", i, got[i], want[i])
		}
	}
}

func TestMaterializeSourcesValidatesConfigs(t *testing.T) {
	// Invalid entries are reported, not fatal, and valid loading continues.
	_, err := materializeSources(t.Context(), []SourceConfig{
		{},                                     // neither set
		{Program: "x", URL: "https://both"},    // both set
		{Program: "definitely-not-on-path-xy"}, // load failure
	})
	if err == nil {
		t.Fatal("expected joined errors, got nil")
	}
	for _, wantSub := range []string{"got neither", "got both", "definitely-not-on-path-xy"} {
		if !strings.Contains(err.Error(), wantSub) {
			t.Errorf("error %q missing %q", err, wantSub)
		}
	}
}

// TestDisableSubprocessSourcesExcludesPrograms pins the remote-mode security
// invariant: once subprocess sources are disabled, a program-backed config
// must not execute (or even resolve) and must surface in the error report,
// while URL configs remain eligible.
func TestDisableSubprocessSourcesExcludesPrograms(t *testing.T) {
	DisableSubprocessSources()
	t.Cleanup(func() {
		configuredMu.Lock()
		subprocessDisabled = false
		configuredMu.Unlock()
	})

	sources, err := materializeSources(t.Context(), []SourceConfig{{Program: "deputy-advisory-source-evil"}})
	if len(sources) != 0 {
		t.Fatalf("sources = %d, want 0: program sources must not materialize in remote mode", len(sources))
	}
	if err == nil || !strings.Contains(err.Error(), "remote server mode") {
		t.Fatalf("error = %v, want exclusion naming remote server mode", err)
	}
}
