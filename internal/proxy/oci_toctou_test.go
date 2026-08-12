package proxy

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"slices"
	"strings"
	"sync"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/temporalio/deputy/internal/scanning"
)

func TestIsMutableTag(t *testing.T) {
	tests := []struct {
		tag         string
		wantMutable bool
	}{
		// Explicitly mutable tags
		{"latest", true},
		{"stable", true},
		{"edge", true},
		{"nightly", true},
		{"dev", true},
		{"snapshot", true},
		{"master", true},
		{"main", true},
		{"LATEST", true}, // Case insensitive
		{"Latest", true},

		// Digest references (immutable)
		{"sha256:" + strings.Repeat("a", 64), false},
		{"sha512:" + strings.Repeat("b", 128), false},

		// Semver-like tags (immutable)
		{"v1.0.0", false},
		{"1.0.0", false},
		{"v1.2.3", false},
		{"1.2.3", false},
		{"v2.0", false},
		{"2.0", false},
		{"v1.2.3-alpine", false},
		{"1.2.3+build123", false},

		// Date/build number tags (mutable)
		{"20240101", true},
		{"12345", true},
		{"202401", true},

		// Base image tags (mutable - could change)
		{"alpine", true},
		{"bookworm", true},
		{"bullseye", true},
		{"slim", true},

		// Empty tag
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := isMutableTag(tt.tag)
			if got != tt.wantMutable {
				t.Errorf("isMutableTag(%q) = %v, want %v", tt.tag, got, tt.wantMutable)
			}
		})
	}
}

func TestLooksLikeSemver(t *testing.T) {
	tests := []struct {
		tag  string
		want bool
	}{
		{"v1.0.0", true},
		{"1.0.0", true},
		{"v1.2.3", true},
		{"1.2.3", true},
		{"v2.0", true},
		{"2.0", true},
		{"v1.2.3-alpine", true},
		{"1.2.3+build123", true},
		{"v1.2.3-rc.1", true},

		{"latest", false},
		{"alpine", false},
		{"v", false},
		{"", false},
		{"v1", false}, // Single component
		{"1", false},  // Single component
	}

	for _, tt := range tests {
		t.Run(tt.tag, func(t *testing.T) {
			got := looksLikeSemver(tt.tag)
			if got != tt.want {
				t.Errorf("looksLikeSemver(%q) = %v, want %v", tt.tag, got, tt.want)
			}
		})
	}
}

func TestRewriteManifestPath(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)

	tests := []struct {
		name     string
		path     string
		tag      string
		digest   string
		wantPath string
	}{
		{
			name:     "rewrite tag to digest",
			path:     "/v2/library/nginx/manifests/latest",
			tag:      "latest",
			digest:   digest,
			wantPath: "/v2/library/nginx/manifests/" + digest,
		},
		{
			name:     "rewrite semver tag",
			path:     "/v2/myorg/myapp/manifests/v1.2.3",
			tag:      "v1.2.3",
			digest:   digest,
			wantPath: "/v2/myorg/myapp/manifests/" + digest,
		},
		{
			name:     "no rewrite when tag is empty",
			path:     "/v2/library/nginx/manifests/latest",
			tag:      "",
			digest:   digest,
			wantPath: "/v2/library/nginx/manifests/latest",
		},
		{
			name:     "no rewrite when digest is empty",
			path:     "/v2/library/nginx/manifests/latest",
			tag:      "latest",
			digest:   "",
			wantPath: "/v2/library/nginx/manifests/latest",
		},
		{
			name:     "nested repository path",
			path:     "/v2/gcr.io/project/app/manifests/v1.0.0",
			tag:      "v1.0.0",
			digest:   digest,
			wantPath: "/v2/gcr.io/project/app/manifests/" + digest,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := rewriteManifestPath(tt.path, tt.tag, tt.digest)
			if got != tt.wantPath {
				t.Errorf("rewriteManifestPath() = %q, want %q", got, tt.wantPath)
			}
		})
	}
}

func TestCheckMutableTagPolicy(t *testing.T) {
	digest := "sha256:" + strings.Repeat("a", 64)

	tests := []struct {
		name       string
		cfg        *OCIConfig
		tag        string
		repository string
		digest     string
		wantErr    bool
	}{
		{
			name:       "nil config allows all",
			cfg:        nil,
			tag:        "latest",
			repository: "library/nginx",
			digest:     "",
			wantErr:    false,
		},
		{
			name:       "strict mode blocks latest without digest",
			cfg:        &OCIConfig{StrictMode: true},
			tag:        "latest",
			repository: "library/nginx",
			digest:     "",
			wantErr:    true,
		},
		{
			name:       "strict mode allows latest with digest",
			cfg:        &OCIConfig{StrictMode: true},
			tag:        "latest",
			repository: "library/nginx",
			digest:     digest,
			wantErr:    false,
		},
		{
			name:       "strict mode allows semver tags",
			cfg:        &OCIConfig{StrictMode: true},
			tag:        "v1.2.3",
			repository: "library/nginx",
			digest:     "",
			wantErr:    false,
		},
		{
			name:       "allow mutable tags explicitly",
			cfg:        &OCIConfig{AllowMutableTags: true},
			tag:        "latest",
			repository: "library/nginx",
			digest:     "",
			wantErr:    false,
		},
		{
			name:       "disallow mutable tags without digest",
			cfg:        &OCIConfig{AllowMutableTags: false, PinDigests: false},
			tag:        "latest",
			repository: "library/nginx",
			digest:     "",
			wantErr:    true,
		},
		{
			name:       "disallow mutable tags but allow with pinned digest",
			cfg:        &OCIConfig{AllowMutableTags: false, PinDigests: true},
			tag:        "latest",
			repository: "library/nginx",
			digest:     digest,
			wantErr:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkMutableTagPolicy(tt.cfg, tt.tag, tt.repository, tt.digest)
			if (err != nil) != tt.wantErr {
				t.Errorf("checkMutableTagPolicy() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestOCIConfigEffectiveMethods(t *testing.T) {
	t.Run("nil config defaults", func(t *testing.T) {
		var cfg *OCIConfig = nil
		if !cfg.EffectiveAllowMutableTags() {
			t.Error("nil config should allow mutable tags by default")
		}
		if !cfg.EffectivePinDigests() {
			t.Error("nil config should enable digest pinning by default")
		}
	})

	t.Run("strict mode overrides", func(t *testing.T) {
		cfg := &OCIConfig{
			StrictMode:       true,
			AllowMutableTags: true,  // Should be overridden
			PinDigests:       false, // Should be overridden
		}
		if cfg.EffectiveAllowMutableTags() {
			t.Error("strict mode should disallow mutable tags")
		}
		if !cfg.EffectivePinDigests() {
			t.Error("strict mode should enable digest pinning")
		}
	})

	t.Run("explicit config without strict mode", func(t *testing.T) {
		cfg := &OCIConfig{
			StrictMode:       false,
			AllowMutableTags: true,
			PinDigests:       false,
		}
		if !cfg.EffectiveAllowMutableTags() {
			t.Error("should allow mutable tags when explicitly set")
		}
		if cfg.EffectivePinDigests() {
			t.Error("should not pin digests when explicitly disabled")
		}
	})
}

func TestOCIHandler_DigestPinning(t *testing.T) {
	pinnedDigest := "sha256:" + strings.Repeat("a", 64)

	// Capture every proxied path so the digest rewrite is asserted on
	// requests that provably happened; an in-callback assertion alone is
	// vacuous if the proxy never reaches upstream, and keeping only the last
	// path would let an unrewritten request hide behind a rewritten one.
	var mu sync.Mutex
	var upstreamPaths []string
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		upstreamPaths = append(upstreamPaths, r.URL.Path)
		mu.Unlock()
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()

	// Pre-populate cache with scan result
	info := parseOCIRequestPath("/v2/library/nginx/manifests/latest")
	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, pinnedDigest), ImageScanResult{
		Vulnerabilities: []map[string]any{{"id": "CVE-TEST-1"}},
	})

	// Mock digest resolution to return our pinned digest
	mockResolve := func(ctx context.Context, ref name.Reference) (string, error) {
		return pinnedDigest, nil
	}

	// Create handler with strict mode (enables digest pinning)
	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache:  cache,
		digestCache: NewDigestResolutionCache(),
		scanner:     stubImageScanner{},
		resolveHead: mockResolve,
		ociConfig:   &OCIConfig{StrictMode: true},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/nginx/manifests/latest", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Verify the request was actually proxied and every upstream request used
	// the pinned digest path.
	mu.Lock()
	gotPaths := slices.Clone(upstreamPaths)
	mu.Unlock()
	if len(gotPaths) == 0 {
		t.Fatalf("upstream was never called; digest rewrite was not exercised (status=%d body=%s)", rr.Code, rr.Body.String())
	}
	for _, path := range gotPaths {
		if !strings.Contains(path, pinnedDigest) {
			t.Errorf("upstream request should use pinned digest, got path: %s", path)
		}
	}

	// Verify the pinned digest header was set
	if got := rr.Header().Get(HeaderPinnedDigest); got != pinnedDigest {
		t.Errorf("X-Deputy-Pinned-Digest = %q, want %q", got, pinnedDigest)
	}

	// Verify digest pinning is enabled
	if got := rr.Header().Get(HeaderDigestPinningEnabled); got != "true" {
		t.Errorf("X-Deputy-Digest-Pinning = %q, want %q", got, "true")
	}
}

func TestOCIHandler_MutableTagBlocking(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Error("upstream should not be called when mutable tag is blocked")
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	capture := &capturePolicyEvaluator{}

	// Mock digest resolution to fail (simulating unable to resolve)
	mockResolve := func(ctx context.Context, ref name.Reference) (string, error) {
		return "", nil // Return empty digest
	}

	// Create handler with strict mode but no digest available
	// This should block mutable tags
	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache:  NewImageScanCache(),
		digestCache: NewDigestResolutionCache(),
		scanner:     stubImageScannerAllowScan{},
		resolveHead: mockResolve,
		ociConfig:   &OCIConfig{StrictMode: true},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/nginx/manifests/latest", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	// Request should be blocked with 403
	if rr.Code != http.StatusForbidden {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusForbidden)
	}

	// Verify the mutable tag blocked header was set
	if got := rr.Header().Get(HeaderMutableTagBlocked); got != "true" {
		t.Errorf("X-Deputy-Mutable-Tag-Blocked = %q, want %q", got, "true")
	}

	// Body should contain error message
	if !strings.Contains(rr.Body.String(), "mutable tag") {
		t.Errorf("response body should mention mutable tag, got: %s", rr.Body.String())
	}
}

func TestOCIHandler_SemverTagsAllowed(t *testing.T) {
	pinnedDigest := "sha256:" + strings.Repeat("a", 64)

	upstreamCalled := false
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamCalled = true
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()

	// Pre-populate cache
	info := parseOCIRequestPath("/v2/library/nginx/manifests/v1.25.3")
	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, pinnedDigest), ImageScanResult{
		Vulnerabilities: nil,
	})

	mockResolve := func(ctx context.Context, ref name.Reference) (string, error) {
		return pinnedDigest, nil
	}

	// Create handler with strict mode
	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache:  cache,
		digestCache: NewDigestResolutionCache(),
		scanner:     stubImageScanner{},
		resolveHead: mockResolve,
		ociConfig:   &OCIConfig{StrictMode: true},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	// Request with semver tag should be allowed
	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/nginx/manifests/v1.25.3", nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	if !upstreamCalled {
		t.Error("upstream should have been called for semver tag")
	}
}

func TestOCIHandler_DigestReferencePassthrough(t *testing.T) {
	pinnedDigest := "sha256:" + strings.Repeat("a", 64)

	upstreamPath := ""
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstreamPath = r.URL.Path
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()

	// Pre-populate cache with digest key
	cache.Set(imageCacheKey(upstreamURL.Host, "library/nginx", pinnedDigest), ImageScanResult{
		Vulnerabilities: nil,
	})

	// Create handler with strict mode
	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache:  cache,
		digestCache: NewDigestResolutionCache(),
		scanner:     stubImageScanner{},
		ociConfig:   &OCIConfig{StrictMode: true},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	// Request with digest should pass through without modification
	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/nginx/manifests/"+pinnedDigest, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Errorf("status = %d, want %d", rr.Code, http.StatusOK)
	}

	// Verify path was not modified
	if !strings.Contains(upstreamPath, pinnedDigest) {
		t.Errorf("upstream path should contain digest, got: %s", upstreamPath)
	}

	// No pinned digest header for already-digest requests
	if got := rr.Header().Get(HeaderPinnedDigest); got != "" {
		t.Errorf("X-Deputy-Pinned-Digest should be empty for digest requests, got: %q", got)
	}
}

// stubImageScannerAllowScan allows scans without failing
type stubImageScannerAllowScan struct{}

func (s stubImageScannerAllowScan) ScanContainerImage(ctx context.Context, target string, targetOpts map[string]string, opts scanning.Options) (*scanning.Execution, error) {
	return &scanning.Execution{
		Result: scanning.Result{},
	}, nil
}
