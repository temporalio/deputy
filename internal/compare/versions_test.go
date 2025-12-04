package compare

import "testing"

func Test_CompareGoPackageVersions(t *testing.T) {
	cases := []struct {
		name   string
		base   string
		target string
		want   int
	}{
		{name: "upgrade", base: "v1.2.3", target: "v1.3.0", want: 1},
		{name: "downgrade", base: "v2.0.0", target: "v1.9.9", want: -1},
		{name: "equal", base: "v1.0.0", target: "v1.0.0", want: 0},
		{name: "missing-v-prefix", base: "1.2.3", target: "1.2.4", want: 1},
		{name: "empty", base: "", target: "", want: 0},
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
