package server

import (
	"testing"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
)

func TestSortListPackagesUsesStableIdentityOrder(t *testing.T) {
	pkgs := []*dependencyv1.Package{
		{Name: "zeta", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/zeta@1.0.0", Direct: false},
		nil,
		{Name: "alpha", Version: "2.0.0", Ecosystem: "npm", Purl: "pkg:npm/alpha@2.0.0", Direct: false},
		{Name: "empty-transitive", Version: "1.0.0", Ecosystem: "npm", Direct: false},
		{Name: "empty-direct", Version: "1.0.0", Ecosystem: "npm", Direct: true},
		{Name: "alpha", Version: "1.0.0", Ecosystem: "npm", Purl: "pkg:npm/alpha@1.0.0", Direct: true},
	}

	sortListPackages(pkgs)

	want := []string{
		"empty-direct",
		"empty-transitive",
		"alpha",
		"alpha",
		"zeta",
		"<nil>",
	}
	got := make([]string, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			got = append(got, "<nil>")
			continue
		}
		got = append(got, pkg.GetName())
	}

	for i := range want {
		if got[i] != want[i] {
			t.Fatalf("sorted package %d = %q, want %q; full order: %v", i, got[i], want[i], got)
		}
	}
}
