package license

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
)

type countingDepsClientEcosystem struct {
	calls int
	sys   pb.System
}

const testMITLicenseText = `MIT License

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

// testISCLicenseText is a sentinel license fixture. The live packages these
// hermetic registry tests borrow names from are not ISC licensed, so an ISC
// result proves the lookup consulted the mock host rather than silently
// falling through to the real registry after a base-URL routing regression.
const testISCLicenseText = `ISC License

Copyright (c) 2004-2010 by Internet Systems Consortium, Inc. ("ISC")
Copyright (c) 1995-2003 by Internet Software Consortium

Permission to use, copy, modify, and/or distribute this software for any
purpose with or without fee is hereby granted, provided that the above
copyright notice and this permission notice appear in all copies.

THE SOFTWARE IS PROVIDED "AS IS" AND ISC DISCLAIMS ALL WARRANTIES WITH
REGARD TO THIS SOFTWARE INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY
AND FITNESS. IN NO EVENT SHALL ISC BE LIABLE FOR ANY SPECIAL, DIRECT,
INDIRECT, OR CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM
LOSS OF USE, DATA OR PROFITS, WHETHER IN AN ACTION OF CONTRACT, NEGLIGENCE
OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION WITH THE USE OR
PERFORMANCE OF THIS SOFTWARE.`

func (c *countingDepsClientEcosystem) GetVersion(ctx context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	c.calls++
	c.sys = req.GetVersionKey().GetSystem()
	return &pb.Version{Licenses: []string{"Apache-2.0"}}, nil
}

func TestFetchLicensesForEcosystem_NormalizesAndCaches(t *testing.T) {
	resetLicenseTestState(t)

	client := &countingDepsClientEcosystem{}
	got := FetchLicensesForEcosystem(t.Context(), client, "python", "Requests", "2.31.0")
	if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
		t.Fatalf("unexpected licenses: %v", got)
	}
	if client.sys != pb.System_PYPI {
		t.Fatalf("expected PYPI system, got %v", client.sys)
	}
	FetchLicensesForEcosystem(t.Context(), client, "python", "Requests", "2.31.0")
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

	if got := GoProxyLicenseScan(t.Context(), "example.com/mod", "v1.2.3"); !slices.Equal(got, []string{"MIT"}) {
		t.Fatalf("expected go proxy direct scan to return MIT, got %v", got)
	}

	licenses := LookupLicensesBestEffort(t.Context(), "go", "example.com/mod", "v1.2.3")
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
	var gotUserAgent string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		requested = r.URL.Path
		gotUserAgent = r.Header.Get("User-Agent")
		_ = json.NewEncoder(w).Encode(map[string]any{
			"version": map[string]any{"license": "MIT"},
		})
	}))
	defer server.Close()

	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, server.URL, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := LookupLicensesBestEffort(t.Context(), "rust", "serde", "1.0.0")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected crates.io license, got %v", got)
	}
	if !strings.Contains(requested, "/api/v1/crates/serde/") {
		t.Fatalf("unexpected crates path %s", requested)
	}
	if gotUserAgent != licenseUserAgent {
		t.Fatalf("expected User-Agent %q on crates lookup, got %q", licenseUserAgent, gotUserAgent)
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

		got := LookupLicensesBestEffort(t.Context(), "php", "laravel/framework", "10.0.0")
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

		got := LookupLicensesBestEffort(t.Context(), "composer", "vendor/name", "1.2.3")
		if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
			t.Fatalf("expected packagist legacy license, got %v", got)
		}
	})
}

func TestLookupLicensesBestEffort_Pub(t *testing.T) {
	resetLicenseTestState(t)
	var base string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/packages/riverpod/versions/1.0.0") {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"pubspec":{"license":""},"archive_url":"%s/pkg.tar.gz"}`, base)))
			return
		}
		if strings.Contains(r.URL.Path, "/pkg.tar.gz") {
			// ISC is a sentinel: live riverpod ships an MIT license, so a
			// revert of the pubBase routing cannot produce this value.
			zw := gzip.NewWriter(w)
			tw := tar.NewWriter(zw)
			_ = tw.WriteHeader(&tar.Header{Name: "LICENSE", Size: int64(len(testISCLicenseText))})
			_, _ = tw.Write([]byte(testISCLicenseText))
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

	got := LookupLicensesBestEffort(t.Context(), "dart", "riverpod", "1.0.0")
	if want := []string{"ISC"}; !slices.Equal(got, want) {
		t.Fatalf("expected pub license, got %v", got)
	}
}

func TestLookupLicensesBestEffort_CocoaPods(t *testing.T) {
	resetLicenseTestState(t)
	var base string
	var mu sync.Mutex
	var hits int
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		hits++
		mu.Unlock()
		if strings.Contains(r.URL.Path, "/api/v1/pods/Alamofire/versions/5.9.1") {
			_, _ = w.Write([]byte(fmt.Sprintf(`{"data_url":"%s/Specs/Alamofire.json"}`, base)))
			return
		}
		if strings.Contains(r.URL.Path, "/Specs/Alamofire.json") {
			// ISC is a sentinel: live Alamofire is MIT, so a revert of the
			// cocoapodsBase routing cannot produce this value from the network.
			_, _ = w.Write([]byte(`{"license":{"type":"ISC"}}`))
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

	got := LookupLicensesBestEffort(t.Context(), "cocoapods", "Alamofire", "5.9.1")
	if want := []string{"ISC"}; !slices.Equal(got, want) {
		t.Fatalf("expected cocoapods license, got %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if hits == 0 {
		t.Fatal("expected cocoapods lookup to hit the mock registry host")
	}
}

func TestLookupLicensesBestEffort_Hex(t *testing.T) {
	resetLicenseTestState(t)
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/api/packages/plug") && !strings.Contains(r.URL.Path, "releases") {
			// ISC is a sentinel: live plug is Apache-2.0, so a revert of the
			// hexpmBase routing cannot produce this value from the network.
			_, _ = w.Write([]byte(`{"meta":{"licenses":["ISC"]}}`))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()
	restoreClient := swapHTTPGlobals(server)
	defer restoreClient()
	restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, packagistBase, pubBase, cocoapodsBase, server.URL)
	defer restoreBases()

	got := LookupLicensesBestEffort(t.Context(), "hex", "plug", "1.12.0")
	if want := []string{"ISC"}; !slices.Equal(got, want) {
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
	ResetLicenseCachesForTest(t)
}

func TestLookupLicensesBestEffort_WellKnown(t *testing.T) {
	resetLicenseTestState(t)

	// Go stdlib should return BSD-3-Clause without any network calls
	got := LookupLicensesBestEffort(t.Context(), "go", "stdlib", "")
	if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
		t.Fatalf("expected Go stdlib license %v, got %v", want, got)
	}

	// toolchain should also work
	got = LookupLicensesBestEffort(t.Context(), "golang", "toolchain", "go1.21.0")
	if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
		t.Fatalf("expected toolchain license %v, got %v", want, got)
	}
}

func TestLookupLicensesBestEffort_GitHubWithoutVersion(t *testing.T) {
	resetLicenseTestState(t)

	// GitHub Actions can be looked up without a version via the GitHub License API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/actions/checkout/license") {
			// ISC is a sentinel: live actions/checkout is MIT, so a revert of
			// the githubAPIBase routing cannot produce this value.
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "isc",
					"spdx_id": "ISC",
					"name":    "ISC License",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()

	// GitHub Actions without version should still work
	got := LookupLicensesBestEffort(t.Context(), "github", "actions/checkout", "")
	if want := []string{"ISC"}; !slices.Equal(got, want) {
		t.Fatalf("expected GitHub Actions license %v without version, got %v", want, got)
	}
}

func TestRemoteModuleLicenseScan_GitHubVersionedUsesRequestedRef(t *testing.T) {
	resetLicenseTestState(t)

	const version = "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	var mu sync.Mutex
	var sawRawRef bool
	var sawAPI bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos/owner/repo/license"):
			mu.Lock()
			sawAPI = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "apache-2.0",
					"spdx_id": "Apache-2.0",
					"name":    "Apache License 2.0",
				},
			})
		case r.URL.Path == "/owner/repo/"+version+"/LICENSE":
			mu.Lock()
			sawRawRef = true
			mu.Unlock()
			_, _ = w.Write([]byte(testMITLicenseText))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()
	restoreHTTP := WithLicenseHTTPClient(server.Client())
	defer restoreHTTP()
	restoreBases := WithLicenseEndpoints(server.URL, cratesBase, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := RemoteModuleLicenseScan(t.Context(), "github.com/owner/repo", version)
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected requested-ref license %v, got %v", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if !sawRawRef {
		t.Fatal("expected raw license lookup at the requested ref")
	}
	if sawAPI {
		t.Fatal("versioned GitHub license lookup used default-branch License API")
	}
}

// TestRemoteModuleLicenseScan_GitHubSubmoduleUsesSubpathTag pins submodule
// resolution: a module below the repo root resolves its subpath-prefixed tag
// (sub/v1.2.3) and reads the license closest to the module directory, without
// consulting the default-branch License API.
func TestRemoteModuleLicenseScan_GitHubSubmoduleUsesSubpathTag(t *testing.T) {
	resetLicenseTestState(t)

	var mu sync.Mutex
	var sawAPI bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case strings.Contains(r.URL.Path, "/repos/owner/repo/license"):
			mu.Lock()
			sawAPI = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{"key": "apache-2.0", "spdx_id": "Apache-2.0", "name": "Apache License 2.0"},
			})
		case r.URL.Path == "/owner/repo/sub/v1.2.3/sub/LICENSE":
			// The submodule tag with the submodule's own license file.
			_, _ = w.Write([]byte(testMITLicenseText))
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()
	restoreHTTP := WithLicenseHTTPClient(server.Client())
	defer restoreHTTP()
	restoreBases := WithLicenseEndpoints(server.URL, cratesBase, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := RemoteModuleLicenseScan(t.Context(), "github.com/owner/repo/sub", "v1.2.3")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected submodule-tag license %v, got %v", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if sawAPI {
		t.Fatal("versioned submodule lookup used default-branch License API")
	}
}

func TestRemoteModuleLicenseScan_GitHubVersionedDoesNotFallBackToDefaultBranchLicense(t *testing.T) {
	resetLicenseTestState(t)

	const version = "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	var mu sync.Mutex
	var sawAPI bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/owner/repo/license") {
			mu.Lock()
			sawAPI = true
			mu.Unlock()
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "mit",
					"spdx_id": "MIT",
					"name":    "MIT License",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()
	restoreHTTP := WithLicenseHTTPClient(server.Client())
	defer restoreHTTP()
	restoreBases := WithLicenseEndpoints(server.URL, cratesBase, packagistBase, pubBase, cocoapodsBase, hexpmBase)
	defer restoreBases()

	got := RemoteModuleLicenseScan(t.Context(), "github.com/owner/repo", version)
	if len(got) != 0 {
		t.Fatalf("expected no license when requested ref has no license file, got %v", got)
	}
	mu.Lock()
	defer mu.Unlock()
	if sawAPI {
		t.Fatal("versioned GitHub license lookup used default-branch License API")
	}
}

func TestFetchLicensesFromGitHubRawUsesSHAWithoutVPrefix(t *testing.T) {
	resetLicenseTestState(t)

	const sha = "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	var mu sync.Mutex
	var paths []string
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		paths = append(paths, r.URL.Path)
		mu.Unlock()
		if r.URL.Path == "/owner/repo/"+sha+"/LICENSE" {
			_, _ = w.Write([]byte(testMITLicenseText))
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()

	got, err := fetchLicensesFromGitHubRaw(t.Context(), "owner", "repo", "", sha)
	if err != nil {
		t.Fatalf("fetchLicensesFromGitHubRaw returned error: %v", err)
	}
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected %v, got %v", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	for _, path := range paths {
		if strings.Contains(path, "/v"+sha+"/") {
			t.Fatalf("raw lookup incorrectly prefixed SHA with v: %v", paths)
		}
	}
}

func TestGitHubLicenseRefCandidates(t *testing.T) {
	tests := []struct {
		name    string
		version string
		subpath string
		want    []string
	}{
		{
			name:    "semver_without_v",
			version: "1.2.3",
			want:    []string{"v1.2.3", "1.2.3"},
		},
		{
			name:    "semver_with_v",
			version: "v1.2.3",
			want:    []string{"v1.2.3"},
		},
		{
			name:    "commit_sha",
			version: "FAD22EB3FA582B7357FC0EA48AF6645851B884FD",
			want:    []string{"fad22eb3fa582b7357fc0ea48af6645851b884fd"},
		},
		{
			name:    "go_pseudo_version",
			version: "v0.0.0-20200622213623-75b288015ac9",
			want:    []string{"75b288015ac9"},
		},
		{
			name:    "build_metadata_trimmed",
			version: "v1.2.3+incompatible",
			want:    []string{"v1.2.3"},
		},
		{
			name:    "submodule_tags_first",
			version: "v1.2.3",
			subpath: "sub/dir",
			want:    []string{"sub/dir/v1.2.3", "v1.2.3"},
		},
		{
			name:    "submodule_without_v",
			version: "1.2.3",
			subpath: "sub",
			want:    []string{"sub/v1.2.3", "sub/1.2.3", "v1.2.3", "1.2.3"},
		},
		{
			name:    "submodule_sha_is_path_independent",
			version: "fad22eb3fa582b7357fc0ea48af6645851b884fd",
			subpath: "sub",
			want:    []string{"fad22eb3fa582b7357fc0ea48af6645851b884fd"},
		},
		{
			name:    "submodule_pseudo_version_is_path_independent",
			version: "v0.0.0-20200622213623-75b288015ac9",
			subpath: "sub",
			want:    []string{"75b288015ac9"},
		},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := githubLicenseRefCandidates(tc.version, tc.subpath); !slices.Equal(got, tc.want) {
				t.Fatalf("githubLicenseRefCandidates(%q, %q) = %v, want %v", tc.version, tc.subpath, got, tc.want)
			}
		})
	}
}

func TestLookupLicensesBestEffort_GitHubRefCandidatesAreGitHubOnly(t *testing.T) {
	resetLicenseTestState(t)

	const shaLikeVersion = "fad22eb3fa582b7357fc0ea48af6645851b884fd"
	var mu sync.Mutex
	var sawGitHubLookup bool
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		if strings.HasPrefix(r.URL.Path, "/repos/") || strings.HasPrefix(r.URL.Path, "/owner/") {
			sawGitHubLookup = true
		}
		mu.Unlock()
		if r.URL.Path == "/pypi/requests/"+shaLikeVersion+"/json" {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"license_expression": "Apache-2.0",
				},
			})
			return
		}
		http.NotFound(w, r)
	}))
	defer server.Close()

	restoreClient := swapGitHubHTTPClient(server)
	defer restoreClient()
	restoreHTTP := WithLicenseHTTPClient(server.Client())
	defer restoreHTTP()
	oldPyPIBase := pypiBase
	pypiBase = server.URL
	defer func() { pypiBase = oldPyPIBase }()

	got := LookupLicensesBestEffort(t.Context(), "pypi", "requests", shaLikeVersion)
	if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
		t.Fatalf("expected PyPI license %v, got %v", want, got)
	}
	mu.Lock()
	defer mu.Unlock()
	if sawGitHubLookup {
		t.Fatal("non-GitHub ecosystem used GitHub ref-candidate lookup")
	}
}

func TestLookupLicensesBestEffort_PyPI(t *testing.T) {
	resetLicenseTestState(t)

	t.Run("license_expression", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"license_expression": "Apache-2.0",
				},
			})
		}))
		defer server.Close()

		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()
		restoreBases := WithLicenseEndpoints(goProxyBase, cratesBase, packagistBase, pubBase, cocoapodsBase, hexpmBase)
		defer restoreBases()

		// Override pypiBase for testing
		oldPyPIBase := pypiBase
		pypiBase = server.URL
		defer func() { pypiBase = oldPyPIBase }()

		got := LookupLicensesBestEffort(t.Context(), "pypi", "requests", "2.31.0")
		if want := []string{"Apache-2.0"}; !slices.Equal(got, want) {
			t.Fatalf("expected PyPI license_expression %v, got %v", want, got)
		}
	})

	t.Run("license_field", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"license": "MIT",
				},
			})
		}))
		defer server.Close()

		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()

		oldPyPIBase := pypiBase
		pypiBase = server.URL
		defer func() { pypiBase = oldPyPIBase }()

		got := LookupLicensesBestEffort(t.Context(), "python", "flask", "3.0.0")
		if want := []string{"MIT"}; !slices.Equal(got, want) {
			t.Fatalf("expected PyPI license field %v, got %v", want, got)
		}
	})

	t.Run("classifiers", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"info": map[string]any{
					"license": "", // empty license field
					"classifiers": []string{
						"Development Status :: 5 - Production/Stable",
						// ISC is a sentinel: live numpy carries the BSD
						// classifier, so a revert of the pypiBase routing
						// cannot produce this value from the network.
						"License :: OSI Approved :: ISC License (ISCL)",
						"Programming Language :: Python :: 3",
					},
				},
			})
		}))
		defer server.Close()

		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()

		oldPyPIBase := pypiBase
		pypiBase = server.URL
		defer func() { pypiBase = oldPyPIBase }()

		got := LookupLicensesBestEffort(t.Context(), "pypi", "numpy", "1.26.0")
		if want := []string{"ISC"}; !slices.Equal(got, want) {
			t.Fatalf("expected PyPI classifier license %v, got %v", want, got)
		}
	})
}

func TestLooksLikeSPDX(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"MIT", true},
		{"Apache-2.0", true},
		{"BSD-3-Clause", true},
		{"GPL-3.0-only", true},
		{"LGPL-2.1-or-later", true},
		{"MIT AND Apache-2.0", true},
		{"MIT OR Apache-2.0", true},
		{"", false},
		{"The MIT License", true},            // contains "MIT" - permissive heuristic
		{"Apache License Version 2.0", true}, // contains "Apache"
		{"See LICENSE file", false},
		{"UNKNOWN", false},
		{"Proprietary", false},
	}
	for _, tc := range tests {
		got := looksLikeSPDX(tc.input)
		if got != tc.want {
			t.Errorf("looksLikeSPDX(%q) = %v, want %v", tc.input, got, tc.want)
		}
	}
}

func TestClassifierToSPDX(t *testing.T) {
	tests := []struct {
		classifier string
		want       string
	}{
		{"License :: OSI Approved :: MIT License", "MIT"},
		{"License :: OSI Approved :: Apache Software License", "Apache-2.0"},
		{"License :: OSI Approved :: BSD License", "BSD-3-Clause"},
		{"License :: OSI Approved :: GNU General Public License v3 (GPLv3)", "GPL-3.0-only"},
		{"License :: OSI Approved :: Mozilla Public License 2.0 (MPL 2.0)", "MPL-2.0"},
		{"License :: OSI Approved :: ISC License (ISCL)", "ISC"},
		{"License :: Public Domain", "CC0-1.0"},
		{"Programming Language :: Python", ""},
		{"Development Status :: 5 - Production/Stable", ""},
	}
	for _, tc := range tests {
		got := classifierToSPDX(tc.classifier)
		if got != tc.want {
			t.Errorf("classifierToSPDX(%q) = %q, want %q", tc.classifier, got, tc.want)
		}
	}
}

func TestFetchLicenseFromGitHubAPI(t *testing.T) {
	resetLicenseTestState(t)

	t.Run("returns_spdx_id", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if strings.Contains(r.URL.Path, "/repos/owner/repo/license") {
				_ = json.NewEncoder(w).Encode(map[string]any{
					"license": map[string]any{
						"key":     "mit",
						"spdx_id": "MIT",
						"name":    "MIT License",
					},
				})
				return
			}
			http.NotFound(w, r)
		}))
		defer server.Close()

		restoreClient := swapGitHubHTTPClient(server)
		defer restoreClient()

		got := fetchLicenseFromGitHubAPI(t.Context(), "owner", "repo")
		if want := []string{"MIT"}; !slices.Equal(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("falls_back_to_key", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "apache-2.0",
					"spdx_id": "",
					"name":    "Apache License 2.0",
				},
			})
		}))
		defer server.Close()

		restoreClient := swapGitHubHTTPClient(server)
		defer restoreClient()

		got := fetchLicenseFromGitHubAPI(t.Context(), "owner", "repo")
		if want := []string{"APACHE-2.0"}; !slices.Equal(got, want) {
			t.Fatalf("expected %v, got %v", want, got)
		}
	})

	t.Run("ignores_noassertion", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "other",
					"spdx_id": "NOASSERTION",
					"name":    "Other",
				},
			})
		}))
		defer server.Close()

		restoreClient := swapGitHubHTTPClient(server)
		defer restoreClient()

		got := fetchLicenseFromGitHubAPI(t.Context(), "owner", "repo")
		if got != nil {
			t.Fatalf("expected nil for NOASSERTION, got %v", got)
		}
	})
}

func swapGitHubHTTPClient(server *httptest.Server) func() {
	// Force initialization so we can swap
	_ = getGitHubHTTPClient()
	origClient := getGitHubHTTPClientForTest()
	origBase := githubAPIBase
	origRawBase := githubRawBase
	setGitHubHTTPClientForTest(server.Client())
	githubAPIBase = server.URL
	githubRawBase = server.URL
	return func() {
		setGitHubHTTPClientForTest(origClient)
		githubAPIBase = origBase
		githubRawBase = origRawBase
	}
}
