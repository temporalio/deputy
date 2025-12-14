package analysis

import (
	"archive/tar"
	"archive/zip"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"sync"
	"testing"

	pb "deps.dev/api/v3"
	"github.com/picatz/deputy/internal/cache"
)

type countingDepsClientEcosystem struct {
	calls int
	sys   pb.System
}

func (c *countingDepsClientEcosystem) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	c.calls++
	c.sys = req.GetVersionKey().GetSystem()
	return &pb.Version{Licenses: []string{"Apache-2.0"}}, nil
}

func TestFetchLicensesForEcosystem_NormalizesAndCaches(t *testing.T) {
	resetLicenseTestState(t)

	client := &countingDepsClientEcosystem{}
	got := FetchLicensesForEcosystem(context.Background(), client, "python", "Requests", "2.31.0")
	if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected licenses: %v", got)
	}
	if client.sys != pb.System_PYPI {
		t.Fatalf("expected PYPI system, got %v", client.sys)
	}
	FetchLicensesForEcosystem(context.Background(), client, "python", "Requests", "2.31.0")
	if client.calls != 1 {
		t.Fatalf("expected cache hit to avoid second call, got %d calls", client.calls)
	}
}

func TestLookupLicensesBestEffort_GoProxy(t *testing.T) {
	resetLicenseTestState(t)

	const mitText = `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`
	if ids := DetectLicenseIDs([]byte(mitText)); len(ids) == 0 {
		t.Fatalf("expected MIT detection for fixture text")
	}
	server, zipPath := serveLicenseZip(t, "LICENSE", mitText)
	defer server.Close()

	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(server.URL, cratesBase, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	if got := GoProxyLicenseScan(context.Background(), "example.com/mod", "v1.2.3"); !slices.Equal(got, []string{"MIT"}) {
		t.Fatalf("expected go proxy direct scan to return MIT, got %v", got)
	}

	licenses := LookupLicensesBestEffort(context.Background(), "go", "example.com/mod", "v1.2.3")
	if want := []string{"MIT"}; !slices.Equal(licenses, want) {
		t.Fatalf("expected go proxy license, got %v", licenses)
	}
	if zipPath == nil || *zipPath != "/example.com/mod/@v/v1.2.3.zip" {
		t.Fatalf("unexpected proxy path %v", zipPath)
	}
}

func TestLookupLicensesBestEffort_Crates(t *testing.T) {
	resetLicenseTestState(t)
	var requested string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": map[string]any{"license": "MIT"},
		})
	}))
	defer server.Close()

	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, server.URL, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := LookupLicensesBestEffort(context.Background(), "rust", "serde", "1.0.0")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected crates.io license, got %v", got)
	}
	if !strings.Contains(requested, "/api/v1/crates/serde/") {
		t.Fatalf("unexpected crates path %s", requested)
	}
}

func TestLookupLicensesBestEffort_Packagist(t *testing.T) {
	t.Run("p2", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/p2/") {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"packages": map[string]any{
						"laravel/framework": []map[string]any{
							{"version": "v10.0.0", "version_normalized": "10.0.0", "license": []string{"BSD-3-Clause"}},
						},
					},
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()
		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()
		restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, server.URL, pubBase, cocoapodsBase, hexpmBase)
		defer restoreBases()

		got := LookupLicensesBestEffort(context.Background(), "php", "laravel/framework", "10.0.0")
		if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
			t.Fatalf("expected packagist license, got %v", got)
		}
	})

	t.Run("legacy", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/p/") {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"packages": map[string]any{
						"vendor/name": map[string]any{
							"1.2.3": map[string]any{
								"license":            []string{"Apache-2.0"},
								"version_normalized": "1.2.3",
							},
						},
					},
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()
		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()
		restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, server.URL, pubBase, cocoapodsBase, hexpmBase)
		defer restoreBases()

		got := LookupLicensesBestEffort(context.Background(), "composer", "vendor/name", "1.2.3")
		if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
			t.Fatalf("expected packagist legacy license, got %v", got)
		}
	})
}

func TestLookupLicensesBestEffort_Pub(t *testing.T) {
	resetLicenseTestState(t)
	mitText := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/packages/riverpod/versions/1.0.0") {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"pubspec":{"license":""},"archive_url":"%s/pkg.tar.gz"}`, base)))
			return
		}
		if strings.Contains(r.URL.Path, "/pkg.tar.gz") {
			zw := gzip.NewWriter(w)
			tw := tar.NewWriter(zw)
			_ = tw.WriteHeader(&tar.Header{Name: "LICENSE", Size: int64(len(mitText))})
			_, _ = tw.Write([]byte(mitText))
			_ = tw.Close()
			_ = zw.Close()
			return
		}
		http.NotFound(w, r)
	}))
	base = server.URL
	defer server.Close()
	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, packagistBase, server.URL, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := LookupLicensesBestEffort(context.Background(), "dart", "riverpod", "1.0.0")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected pub license, got %v", got)
	}
}

func TestLookupLicensesBestEffort_CocoaPods(t *testing.T) {
	resetLicenseTestState(t)
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/v1/pods/Alamofire/versions/5.9.1") {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data_url":"%s/Specs/Alamofire.json"}`, base)))
			return
		}
		if strings.Contains(r.URL.Path, "/Specs/Alamofire.json") {
			_, _ = w.Write([]byte(`{"license":{"type":"MIT"}}`))
			return
		}
		http.NotFound(w, r)
	}))
	base = server.URL
	defer server.Close()
	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, packagistBase, pubBase, server.URL, hexpmBase)
	defer restoreBases()

	got := LookupLicensesBestEffort(context.Background(), "cocoapods", "Alamofire", "5.9.1")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected cocoapods license, got %v", got)
	}
}

func TestLookupLicensesBestEffort_Hex(t *testing.T) {
	resetLicenseTestState(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/packages/plug") && !strings.Contains(r.URL.Path, "releases") {
			_, _ = w.Write([]byte(`{"meta":{"licenses":["Apache-2.0"]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, packagistBase, pubBase, cocoapodsBase, server.URL)
	defer restoreBases()

	got := LookupLicensesBestEffort(context.Background(), "hex", "plug", "1.12.0")
	if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
		t.Fatalf("expected hex license, got %v", got)
	}
}

func serveLicenseZip(t *testing.T, filename, content string) (*httptest.Server, *string) {
	t.Helper()
	var requestedPath string
	handler := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requestedPath = r.URL.Path
		var buf bytes.Buffer
		zw := zip.NewWriter(&buf)
		f, err := zw.Create(filename)
		if err != nil {
			t.Fatalf("create zip: %v", err)
		}
		if _, err := f.Write([]byte(content)); err != nil {
			t.Fatalf("write zip: %v", err)
		}
		if err := zw.Close(); err != nil {
			t.Fatalf("close zip: %v", err)
		}
		w.WriteHeader(http.StatusOK)
		_, _ = w.Write(buf.Bytes())
	})
	server := httptest.NewServer(handler)
	return server, &requestedPath
}

func swapHTTPGlobals(server *httptest.Server) func() {
	origClient := licenseHTTPClient
	licenseHTTPClient = server.Client()
	return func() {
		licenseHTTPClient = origClient
	}
}

func resetLicenseTestState(t *testing.T) {
	t.Helper()
	cacheDirOnce = sync.Once{}
	cacheDirPath = ""
	t.Setenv("DEPUTY_CACHE_DIR", t.TempDir())
	registryLicenseMemo = cache.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
	remoteLicenseMemo = cache.NewTTLCache[string, []string](licenseMemoMaxItems, licenseMemoTTL)
}
