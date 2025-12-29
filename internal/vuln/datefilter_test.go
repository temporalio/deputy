package vuln

import (
	"testing"
	"time"
)

func TestParseFlexibleDate(t *testing.T) {
	cases := []struct {
		in     string
		intent string
		ok     bool
	}{
		{in: "2025", intent: "before", ok: true},
		{in: "2025-02", intent: "after", ok: true},
		{in: "2025-02-12", intent: "before", ok: true},
		{in: "2025-02-12T10:11:12Z", intent: "asof", ok: true},
		{in: "bad", intent: "before", ok: false},
	}
	for _, c := range cases {
		_, err := ParseFlexibleDate(c.in, c.intent)
		if c.ok && err != nil {
			t.Errorf("expected parse success for %s (%s): %v", c.in, c.intent, err)
		}
		if !c.ok && err == nil {
			t.Errorf("expected parse failure for %s", c.in)
		}
	}
}

func mkV(id, pub string) Vulnerability { return Vulnerability{ID: id, Published: pub, Affected: true} }

func TestFilterVulnerabilitiesByPublished(t *testing.T) {
	vs := []Vulnerability{
		mkV("A", "2024-12-31T23:59:59Z"),
		mkV("B", "2025-01-15T12:00:00Z"),
		mkV("C", "2025-02-01T00:00:00Z"),
		mkV("D", ""), // unknown
	}
	after, _ := time.Parse(time.RFC3339, "2025-01-01T00:00:00Z")
	before, _ := time.Parse(time.RFC3339, "2025-01-31T23:59:59Z")
	out := FilterVulnerabilitiesByPublished(vs, after, before)
	ids := map[string]bool{}
	for _, v := range out {
		ids[v.ID] = true
	}
	if !ids["B"] {
		if len(out) == 0 {
			t.Fatalf("expected some vulns")
		}
	}
	if ids["A"] || ids["C"] {
		t.Errorf("unexpected A or C in result")
	}
	// Unknown publish date (D) should be excluded because 'after' is set.
	if ids["D"] {
		t.Errorf("unknown publish date shouldn't appear when 'after' constraint present")
	}
}
