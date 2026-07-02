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
