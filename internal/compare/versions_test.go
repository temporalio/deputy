package compare

import "testing"

func Test_CompareGoPackageVersions(t *testing.T) {
	cases := []struct {
		name   string
		base   string
		target string
		want   int
	}{
		{"upgrade", "v1.2.3", "v1.3.0", 1},
		{"downgrade", "v2.0.0", "v1.9.9", -1},
		{"equal", "v1.0.0", "v1.0.0", 0},
		{"missing-v-prefix", "1.2.3", "1.2.4", 1},
		{"empty", "", "", 0},
	}
	for _, c := range cases {
		c := c
		t.Run(c.name, func(t *testing.T) {
			chg := Change{BaseVersion: c.base, TargetVersion: c.target}
			got := CompareGoPackageVersions(chg)
			if got != c.want {
				t.Fatalf("CompareGoPackageVersions(%q→%q)=%d want %d", c.base, c.target, got, c.want)
			}
		})
	}
}
