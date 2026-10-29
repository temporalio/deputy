package alpine

import (
	"os"
	"testing"

	"github.com/temporalio/deputy/internal/regression"
)

// TestCheckRegressionImageBehindBranch runs the check over the recorded
// alpine:3.24.1 inventory against the v3.24 main index recorded when openssl
// 3.5.9-r0 shipped. The image's split openssl packages are reported once,
// under their source, behind the branch.
func TestCheckRegressionImageBehindBranch(t *testing.T) {
	img, err := regression.Load("alpine-3.24.1")
	if err != nil {
		t.Fatal(err)
	}
	recorded, err := os.ReadFile("testdata/v3.24-main-x86_64.APKINDEX")
	if err != nil {
		t.Fatal(err)
	}
	srv := mirror(t, map[string][]byte{
		"/alpine/v3.24/main/x86_64/APKINDEX.tar.gz":      packAPKINDEX(t, recorded),
		"/alpine/v3.24/community/x86_64/APKINDEX.tar.gz": packAPKINDEX(t, nil),
	})
	c := &Checker{Mirror: srv.URL + "/alpine", Client: srv.Client()}
	got, warnings := c.Check(t.Context(), img.Packages)
	if len(warnings) != 0 {
		t.Fatalf("warnings: %v", warnings)
	}
	bySource := map[string]string{}
	for _, u := range got {
		bySource[u.GetSourcePackage()] = u.GetInstalledVersion() + " -> " + u.GetAvailableVersion()
		if u.GetEcosystem() != "Alpine:v3.24" || u.GetRepository() != "v3.24/main" || u.GetSource() != SourceName {
			t.Errorf("update %v", u)
		}
	}
	want := map[string]string{
		"openssl":   "3.5.7-r0 -> 3.5.9-r0",
		"apk-tools": "3.0.6-r0 -> 3.0.8-r0",
		"musl":      "1.2.6-r2 -> 1.2.6-r3",
		"zlib":      "1.3.2-r0 -> 1.3.2-r1",
	}
	for src, w := range want {
		if bySource[src] != w {
			t.Errorf("%s: %q, want %q", src, bySource[src], w)
		}
	}
	if len(bySource) != len(want) {
		t.Errorf("updates = %v, want exactly %v", bySource, want)
	}
}
