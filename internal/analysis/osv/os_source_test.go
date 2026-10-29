package osv

import (
	"context"
	"slices"
	"testing"

	"github.com/ossf/osv-schema/bindings/go/osvschema"
	"osv.dev/bindings/go/api"
)

// sourcePackageClient serves one Alpine record keyed by source package, the
// way OSV indexes Alpine: "openssl", never the binary packages split from it.
type sourcePackageClient struct {
	captureQueryClient
}

func (c *sourcePackageClient) QueryBatch(_ context.Context, queries []*api.Query) (*api.BatchVulnerabilityList, error) {
	c.queries = slices.Clone(queries)
	res := make([]*api.VulnerabilityList, len(queries))
	for i, q := range queries {
		res[i] = &api.VulnerabilityList{}
		if q.GetPackage().GetName() == "openssl" {
			res[i].Vulns = []*osvschema.Vulnerability{{Id: "ALPINE-CVE-2026-0001"}}
		}
	}
	return &api.BatchVulnerabilityList{Results: res}, nil
}

func (c *sourcePackageClient) GetVulnByID(_ context.Context, id string) (*osvschema.Vulnerability, error) {
	return &osvschema.Vulnerability{
		Id:      id,
		Aliases: []string{"CVE-2026-0001"},
		Affected: []*osvschema.Affected{{
			Package: &osvschema.Package{Name: "openssl", Ecosystem: "Alpine:v3.24", Purl: "pkg:apk/alpine/openssl?arch=source"},
			Ranges: []*osvschema.Range{{
				Type:   osvschema.Range_ECOSYSTEM,
				Events: []*osvschema.Event{{Introduced: "0"}, {Fixed: "3.5.8-r0"}},
			}},
		}},
	}, nil
}

// TestQueryRawOSPackageUsesSourceName pins the binary-to-source mapping: an
// apk binary package is queried under its origin and its findings still name
// the installed binary package. Before the mapping, libssl3 was queried as
// "libssl3", which no Alpine record names, so every openssl advisory was
// silently missed for the split packages a container actually installs.
func TestQueryRawOSPackageUsesSourceName(t *testing.T) {
	resetDiskCache(t)
	client := &sourcePackageClient{}
	in := []PkgInput{
		{QueryKey: QueryKey{Name: "libssl3", Version: "3.5.7-r0", Ecosystem: "Alpine:v3.24", PURL: "pkg:apk/alpine/libssl3@3.5.7-r0?arch=x86_64&distro=3.24.1&origin=openssl"}},
		{QueryKey: QueryKey{Name: "libcrypto3", Version: "3.5.8-r0", Ecosystem: "Alpine:v3.24", PURL: "pkg:apk/alpine/libcrypto3@3.5.8-r0?arch=x86_64&distro=3.24.1&origin=openssl"}},
	}
	vulns, _, err := QueryRaw(t.Context(), client, in)
	if err != nil {
		t.Fatalf("QueryRaw: %v", err)
	}
	for i, q := range client.queries {
		if got := q.GetPackage().GetName(); got != "openssl" {
			t.Errorf("query %d name = %q, want source package %q", i, got, "openssl")
		}
	}
	// Only the version below the fix is affected, and it is reported under
	// the binary package that is installed, not the source it was built from.
	if len(vulns) != 1 {
		t.Fatalf("got %d findings, want 1 (libssl3 below the fix): %+v", len(vulns), vulns)
	}
	if got := vulns[0].Package; got != "libssl3" {
		t.Errorf("finding package = %q, want installed binary package %q", got, "libssl3")
	}
}

func TestOSVQueryName(t *testing.T) {
	tests := []struct {
		name string
		in   PkgInput
		want string
	}{
		{"apk origin", PkgInput{QueryKey: QueryKey{Name: "busybox-binsh", Ecosystem: "Alpine:v3.24", PURL: "pkg:apk/alpine/busybox-binsh@1.37.0-r31?origin=busybox"}}, "busybox"},
		{"deb source", PkgInput{QueryKey: QueryKey{Name: "libssl3t64", Ecosystem: "Debian:13", PURL: "pkg:deb/debian/libssl3t64@3.5.1-1?source=openssl"}}, "openssl"},
		{"apk without origin", PkgInput{QueryKey: QueryKey{Name: "zlib", Ecosystem: "Alpine:v3.24", PURL: "pkg:apk/alpine/zlib@1.3.2-r0"}}, "zlib"},
		{"origin qualifier on a language package is ignored", PkgInput{QueryKey: QueryKey{Name: "left-pad", Ecosystem: "npm", PURL: "pkg:npm/left-pad@1.3.0?origin=other"}}, "left-pad"},
		{"os package without purl", PkgInput{QueryKey: QueryKey{Name: "musl", Ecosystem: "Alpine:v3.24"}}, "musl"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := osvQueryName(tt.in); got != tt.want {
				t.Fatalf("osvQueryName = %q, want %q", got, tt.want)
			}
		})
	}
}
