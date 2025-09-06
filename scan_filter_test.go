package main

import "testing"

func Test_filterUnfixedVulns(t *testing.T) {
	in := []Vulnerability{
		{ID: "A", Package: "pkg/a", Version: "v1.0.0", FixedVersions: []string{"v1.0.1"}},
		{ID: "B", Package: "pkg/b", Version: "v0.9.0", FixedVersions: nil},
		{ID: "C", Package: "pkg/c", Version: "v2.0.0", FixedVersions: []string{}},
	}
	out := filterUnfixedVulns(in)
	if len(out) != 1 || out[0].ID != "A" {
		t.Fatalf("expected only A to remain, got %#v", out)
	}
}
