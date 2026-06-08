package releases

import (
	"errors"
	"testing"

	depssemver "deps.dev/util/semver"
)

func TestIsPrerelease(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		// Glued markers with no "." or "-" separator (the regression cases).
		{"1.8.2rc1", true},
		{"1.6rc2", true},
		{"jq-1.7rc1", true}, // prefix is irrelevant to the marker
		{"3.0.0beta1", true},
		{"2.1.0alpha", true},
		{"1.0.0preview2", true},
		// Separator forms.
		{"1.2.3-rc.1", true},
		{"24.12.0-rc.1", true},
		{"22.0.0-ea", true},
		// Stable releases must not be flagged.
		{"1.8.1", false},
		{"v26.3.0", false},
		{"0.15.15", false},
		{"529.0.0", false},
		// Build metadata after "+" is ignored (Java LTS token).
		{"21.0.11+10.0.LTS", false},
		{"21.0.5+11", false},
	}
	for _, tt := range tests {
		if got := isPrerelease(tt.version); got != tt.want {
			t.Errorf("isPrerelease(%q) = %v, want %v", tt.version, got, tt.want)
		}
	}
}

func TestNewest(t *testing.T) {
	got, err := Newest([]Release{
		{Version: "v1.2.3", Stable: true},
		{Version: "v1.2.4-rc.1", Stable: true},
		{Version: "v1.3.0", Stable: true},
		{Version: "v2.0.0", Stable: false},
	}, SelectOptions{
		Prefix:        "1.2",
		SemverSystem:  depssemver.DefaultSystem,
		StripPrefixes: []string{"v"},
	})
	if err != nil {
		t.Fatalf("Newest: %v", err)
	}
	if got != "1.2.3" {
		t.Errorf("Newest = %q, want 1.2.3", got)
	}
}

func TestNewestAcceptsTwoPartConcreteVersions(t *testing.T) {
	got, err := Newest([]Release{
		{Version: "v33.0", Stable: true},
		{Version: "v33.1", Stable: true},
	}, SelectOptions{
		Prefix:        "33",
		SemverSystem:  depssemver.DefaultSystem,
		StripPrefixes: []string{"v"},
	})
	if err != nil {
		t.Fatalf("Newest: %v", err)
	}
	if got != "33.1" {
		t.Errorf("Newest = %q, want 33.1", got)
	}
}

func TestNewestNoMatch(t *testing.T) {
	_, err := Newest([]Release{{Version: "v1.2.3", Stable: true}}, SelectOptions{
		Prefix:        "2",
		SemverSystem:  depssemver.DefaultSystem,
		StripPrefixes: []string{"v"},
	})
	if !errors.Is(err, ErrNoMatch) {
		t.Fatalf("Newest error = %v, want %v", err, ErrNoMatch)
	}
}

func TestNewestChannel(t *testing.T) {
	got, err := Newest([]Release{
		{Version: "v24.9.0", Stable: true},
		{Version: "v22.17.1", Stable: true, Channel: "lts"},
		{Version: "v20.20.0", Stable: true, Channel: "lts"},
	}, SelectOptions{
		Channel:       "LTS",
		SemverSystem:  depssemver.NPM,
		StripPrefixes: []string{"v"},
	})
	if err != nil {
		t.Fatalf("Newest: %v", err)
	}
	if got != "22.17.1" {
		t.Errorf("Newest = %q, want 22.17.1", got)
	}
}
