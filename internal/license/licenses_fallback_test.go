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
	"testing"

	pb "deps.dev/api/v3"
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

func TestLookupLicensesBestEffort_TerraformProviderRegistry(t *testing.T) {
	t.Run("registry licenses", func(t *testing.T) {
		resetLicenseTestState(t)
		server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/providers/hashicorp/aws" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"source":   "https://github.com/hashicorp/terraform-provider-aws",
				"licenses": []string{"MPL-2.0"},
			})
		}))
		defer server.Close()

		restoreClient := swapHTTPGlobals(server)
		defer restoreClient()
		restoreBase := WithTerraformRegistryEndpoint(server.URL)
		defer restoreBase()

		got := LookupLicensesBestEffort(context.Background(), "terraform-provider", "hashicorp/aws", ">= 5.0.0")
		if want := []string{"MPL-2.0"}; !slices.Equal(got, want) {
			t.Fatalf("expected registry licenses %v, got %v", want, got)
		}
	})

	t.Run("fallback to source repo", func(t *testing.T) {
		resetLicenseTestState(t)
		registry := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if r.URL.Path != "/v1/providers/hashicorp/aws" {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"source": "https://github.com/hashicorp/terraform-provider-aws",
			})
		}))
		defer registry.Close()

		restoreClient := swapHTTPGlobals(registry)
		defer restoreClient()
		restoreBase := WithTerraformRegistryEndpoint(registry.URL)
		defer restoreBase()

		github := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			if !strings.Contains(r.URL.Path, "/repos/hashicorp/terraform-provider-aws/license") {
				http.NotFound(w, r)
				return
			}
			_ = json.NewEncoder(w).Encode(map[string]any{
				"license": map[string]any{
					"key":     "mit",
					"spdx_id": "MIT",
					"name":    "MIT License",
				},
			})
		}))
		defer github.Close()

		restoreGitHub := swapGitHubHTTPClient(github)
		defer restoreGitHub()

		got := LookupLicensesBestEffort(context.Background(), "terraform-provider", "hashicorp/aws", "")
		if want := []string{"MIT"}; !slices.Equal(got, want) {
			t.Fatalf("expected fallback license %v, got %v", want, got)
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
	ResetLicenseCachesForTest(t)
}

func TestLookupLicensesBestEffort_WellKnown(t *testing.T) {
	resetLicenseTestState(t)

	// Go stdlib should return BSD-3-Clause without any network calls
	got := LookupLicensesBestEffort(context.Background(), "go", "stdlib", "")
	if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
		t.Fatalf("expected Go stdlib license %v, got %v", want, got)
	}

	// toolchain should also work
	got = LookupLicensesBestEffort(context.Background(), "golang", "toolchain", "go1.21.0")
	if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
		t.Fatalf("expected toolchain license %v, got %v", want, got)
	}
}

func TestLookupLicensesBestEffort_GitHubWithoutVersion(t *testing.T) {
	resetLicenseTestState(t)

	// GitHub Actions can be looked up without a version via the GitHub License API
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.Path, "/repos/actions/checkout/license") {
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

	// GitHub Actions without version should still work
	got := LookupLicensesBestEffort(context.Background(), "github", "actions/checkout", "")
	if want := []string{"MIT"}; !slices.Equal(got, want) {
		t.Fatalf("expected GitHub Actions license %v without version, got %v", want, got)
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

		got := LookupLicensesBestEffort(context.Background(), "pypi", "requests", "2.31.0")
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

		got := LookupLicensesBestEffort(context.Background(), "python", "flask", "3.0.0")
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
						"License :: OSI Approved :: BSD License",
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

		got := LookupLicensesBestEffort(context.Background(), "pypi", "numpy", "1.26.0")
		if want := []string{"BSD-3-Clause"}; !slices.Equal(got, want) {
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

		got := fetchLicenseFromGitHubAPI(context.Background(), "owner", "repo")
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

		got := fetchLicenseFromGitHubAPI(context.Background(), "owner", "repo")
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

		got := fetchLicenseFromGitHubAPI(context.Background(), "owner", "repo")
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
	setGitHubHTTPClientForTest(server.Client())
	githubAPIBase = server.URL
	return func() {
		setGitHubHTTPClientForTest(origClient)
		githubAPIBase = origBase
	}
}
