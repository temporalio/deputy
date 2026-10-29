package alpine

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/google/go-cmp/cmp"
	"google.golang.org/protobuf/testing/protocmp"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
)

// packAPKINDEX builds an APKINDEX.tar.gz the way the Alpine signing tools lay
// it out: a signature tar segment with no end-of-archive marker, then the
// index tar, each its own gzip member.
func packAPKINDEX(t *testing.T, index []byte) []byte {
	t.Helper()
	var sig bytes.Buffer
	tw := tar.NewWriter(&sig)
	if err := tw.WriteHeader(&tar.Header{Name: ".SIGN.RSA.test.rsa.pub", Mode: 0o644, Size: 4}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte("sig!")); err != nil {
		t.Fatal(err)
	}
	if err := tw.Flush(); err != nil { // Flush, not Close: no end-of-archive marker.
		t.Fatal(err)
	}

	var idx bytes.Buffer
	tw = tar.NewWriter(&idx)
	for _, f := range []struct {
		name string
		body []byte
	}{{"DESCRIPTION", []byte("v3.24.1-test")}, {"APKINDEX", index}} {
		if err := tw.WriteHeader(&tar.Header{Name: f.name, Mode: 0o644, Size: int64(len(f.body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(f.body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}

	var out bytes.Buffer
	for _, seg := range [][]byte{sig.Bytes(), idx.Bytes()} {
		gz := gzip.NewWriter(&out)
		if _, err := gz.Write(seg); err != nil {
			t.Fatal(err)
		}
		if err := gz.Close(); err != nil {
			t.Fatal(err)
		}
	}
	return out.Bytes()
}

// mirror serves recorded branch indexes by path; any other path is a 404.
func mirror(t *testing.T, indexes map[string][]byte) *httptest.Server {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, ok := indexes[r.URL.Path]
		if !ok {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(body)
	}))
	t.Cleanup(srv.Close)
	return srv
}

func apk(name, version, query string) *dependencyv1.Package {
	return &dependencyv1.Package{
		Name:      name,
		Version:   version,
		Ecosystem: "Alpine:v3.24",
		Purl:      "pkg:apk/alpine/" + name + "@" + version + "?" + query,
	}
}

// TestCheckReportsSecurityReleaseBeforeSecfixes reproduces the lag this check
// exists for, with the v3.24 main index recorded the day openssl 3.5.9-r0
// shipped and before its secfixes entry landed: an image built on 3.5.8-r0 is
// clean by every advisory feed, and the branch already publishes the fix.
func TestCheckReportsSecurityReleaseBeforeSecfixes(t *testing.T) {
	recorded, err := os.ReadFile("testdata/v3.24-main-x86_64.APKINDEX")
	if err != nil {
		t.Fatal(err)
	}
	srv := mirror(t, map[string][]byte{
		"/alpine/v3.24/main/x86_64/APKINDEX.tar.gz":      packAPKINDEX(t, recorded),
		"/alpine/v3.24/community/x86_64/APKINDEX.tar.gz": packAPKINDEX(t, nil),
	})
	pkgs := []*dependencyv1.Package{
		apk("libssl3", "3.5.8-r0", "arch=x86_64&distro=3.24.1&origin=openssl"),
		apk("libcrypto3", "3.5.8-r0", "arch=x86_64&distro=3.24.1&origin=openssl"),
		// Current with the branch: not reported.
		apk("busybox", "1.37.0-r31", "arch=x86_64&distro=3.24.1&origin=busybox"),
		// Not published by the branch (built locally): absence is not lag.
		apk("site-tools", "1.0-r0", "arch=x86_64&distro=3.24.1&origin=site-tools"),
		// Ahead of the index (installed from a newer mirror snapshot).
		apk("musl", "1.2.6-r9", "arch=x86_64&distro=3.24.1&origin=musl"),
		// Missing the release or architecture: cannot pick an index.
		apk("zlib", "1.3.2-r0", "arch=x86_64&origin=zlib"),
		// Another apk distribution: not an Alpine branch.
		{Name: "openssl", Version: "3.5.0-r0", Ecosystem: "Wolfi", Purl: "pkg:apk/wolfi/openssl@3.5.0-r0?arch=x86_64&distro=20230201"},
		// Not an OS package at all.
		{Name: "lodash", Version: "4.17.20", Ecosystem: "npm", Purl: "pkg:npm/lodash@4.17.20"},
	}

	c := &Checker{Mirror: srv.URL + "/alpine", Client: srv.Client()}
	got, warnings := c.Check(t.Context(), pkgs)
	if len(warnings) != 0 {
		t.Fatalf("unexpected warnings: %v", warnings)
	}
	want := []*vulnerabilityv1.DistroUpdate{{
		Ecosystem:        "Alpine:v3.24",
		SourcePackage:    "openssl",
		Packages:         []string{"libcrypto3", "libssl3"},
		InstalledVersion: "3.5.8-r0",
		AvailableVersion: "3.5.9-r0",
		Repository:       "v3.24/main",
		Source:           SourceName,
	}}
	if diff := cmp.Diff(want, got, protocmp.Transform()); diff != "" {
		t.Fatalf("distro updates mismatch (-want +got):\n%s", diff)
	}
}

// TestCheckWarnsWhenAnIndexIsUnreadable pins the honesty rule: a repository
// index that cannot be read is reported, so its packages are not silently
// treated as current, and the repositories that did answer still count.
func TestCheckWarnsWhenAnIndexIsUnreadable(t *testing.T) {
	recorded, err := os.ReadFile("testdata/v3.24-main-x86_64.APKINDEX")
	if err != nil {
		t.Fatal(err)
	}
	srv := mirror(t, map[string][]byte{
		"/alpine/v3.24/main/x86_64/APKINDEX.tar.gz": packAPKINDEX(t, recorded),
	})
	c := &Checker{Mirror: srv.URL + "/alpine", Client: srv.Client()}
	got, warnings := c.Check(t.Context(), []*dependencyv1.Package{
		apk("libssl3", "3.5.8-r0", "arch=x86_64&distro=3.24.1&origin=openssl"),
	})
	if len(got) != 1 || got[0].GetSourcePackage() != "openssl" {
		t.Fatalf("main index result lost when community failed: %v", got)
	}
	if len(warnings) != 1 || !strings.Contains(warnings[0], "v3.24/community/x86_64/APKINDEX.tar.gz") || !strings.Contains(warnings[0], "HTTP 404") {
		t.Fatalf("want one warning naming the unreadable community index, got %v", warnings)
	}
}

func TestBranchFromDistro(t *testing.T) {
	tests := map[string]string{
		"3.24.1":               "v3.24",
		"3.24":                 "v3.24",
		"3.25.0_alpha20260101": "edge",
		"3":                    "",
		"":                     "",
	}
	for in, want := range tests {
		if got := branchFromDistro(in); got != want {
			t.Errorf("branchFromDistro(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseIndexTextDefaultsOriginToName(t *testing.T) {
	got, err := parseIndexText(strings.NewReader("P:zlib\nV:1.3.2-r1\n\nP:libssl3\nV:3.5.9-r0\no:openssl\n\nP:incomplete\n"))
	if err != nil {
		t.Fatal(err)
	}
	want := []indexEntry{{Name: "zlib", Version: "1.3.2-r1", Origin: "zlib"}, {Name: "libssl3", Version: "3.5.9-r0", Origin: "openssl"}}
	if diff := cmp.Diff(want, got); diff != "" {
		t.Fatalf("entries mismatch (-want +got):\n%s", diff)
	}
}
