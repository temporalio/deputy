package proxy

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/google/go-containerregistry/pkg/name"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/scanning"
)

func TestParseOCIRequestPath(t *testing.T) {
	tests := []struct {
		name       string
		path       string
		wantRepo   string
		wantRef    string
		wantTag    string
		wantDigest string
		wantOp     string
	}{
		{
			name:   "ping",
			path:   "/v2/",
			wantOp: ociOperationPing,
		},
		{
			name:   "catalog",
			path:   "/v2/_catalog",
			wantOp: ociOperationCatalog,
		},
		{
			name:       "manifest_tag",
			path:       "/v2/library/ubuntu/manifests/latest",
			wantRepo:   "library/ubuntu",
			wantRef:    "latest",
			wantTag:    "latest",
			wantDigest: "",
			wantOp:     ociOperationManifest,
		},
		{
			name:       "manifest_digest",
			path:       "/v2/library/ubuntu/manifests/" + testDigest,
			wantRepo:   "library/ubuntu",
			wantRef:    testDigest,
			wantTag:    "",
			wantDigest: testDigest,
			wantOp:     ociOperationManifest,
		},
		{
			name:       "blob",
			path:       "/v2/library/ubuntu/blobs/" + testDigest,
			wantRepo:   "library/ubuntu",
			wantRef:    testDigest,
			wantDigest: testDigest,
			wantOp:     ociOperationBlob,
		},
		{
			name:     "tags",
			path:     "/v2/library/ubuntu/tags/list",
			wantRepo: "library/ubuntu",
			wantOp:   ociOperationTags,
		},
		{
			name:     "upload",
			path:     "/v2/library/ubuntu/blobs/uploads/",
			wantRepo: "library/ubuntu",
			wantOp:   ociOperationUpload,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseOCIRequestPath(tt.path)
			if got.Repository != tt.wantRepo {
				t.Fatalf("repo=%q want=%q", got.Repository, tt.wantRepo)
			}
			if got.Reference != tt.wantRef {
				t.Fatalf("ref=%q want=%q", got.Reference, tt.wantRef)
			}
			if got.Tag != tt.wantTag {
				t.Fatalf("tag=%q want=%q", got.Tag, tt.wantTag)
			}
			if got.Digest != tt.wantDigest {
				t.Fatalf("digest=%q want=%q", got.Digest, tt.wantDigest)
			}
			if got.Operation != tt.wantOp {
				t.Fatalf("op=%q want=%q", got.Operation, tt.wantOp)
			}
		})
	}
}

func TestOCIHandler_ManifestPayloadIncludesImage(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()
	info := parseOCIRequestPath("/v2/library/ubuntu/manifests/" + testDigest)
	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []map[string]any{{"id": "OSV-TEST-1"}},
	})

	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache: cache,
		scanner:    stubImageScanner{t: t},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/ubuntu/manifests/"+testDigest, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}
	if capture.entrypoint != policy.EntrypointOCIArtifactRequest.String() {
		t.Fatalf("entrypoint=%q want=%q", capture.entrypoint, policy.EntrypointOCIArtifactRequest)
	}

	reqMap, ok := capture.payload["request"].(map[string]any)
	if !ok {
		t.Fatalf("expected request map in payload")
	}
	if reqMap["repository"] != "library/ubuntu" {
		t.Fatalf("repository=%v want=%q", reqMap["repository"], "library/ubuntu")
	}
	if reqMap["digest"] != testDigest {
		t.Fatalf("digest=%v want=%q", reqMap["digest"], testDigest)
	}
	if reqMap["registry"] != upstreamURL.Host {
		t.Fatalf("registry=%v want=%q", reqMap["registry"], upstreamURL.Host)
	}

	imageMap, ok := capture.payload["image"].(map[string]any)
	if !ok {
		t.Fatalf("expected image map in payload")
	}
	if imageMap["reference"] != testDigest {
		t.Fatalf("image.reference=%v want=%q", imageMap["reference"], testDigest)
	}

	if vulns, ok := capture.payload["vulnerabilities"].([]map[string]any); !ok || len(vulns) != 1 {
		t.Fatalf("expected vulnerabilities in payload, got %T", capture.payload["vulnerabilities"])
	}
}

type capturePolicyEvaluator struct {
	entrypoint string
	payload    map[string]any
}

func (c *capturePolicyEvaluator) Evaluate(_ context.Context, entrypoint string, payload map[string]any) ([]policy.Action, error) {
	c.entrypoint = entrypoint
	c.payload = payload
	return nil, nil
}

type stubImageScanner struct {
	t *testing.T
}

func (s stubImageScanner) ScanContainerImage(context.Context, string, map[string]string, scanning.Options) (*scanning.Execution, error) {
	if s.t != nil {
		s.t.Fatalf("unexpected image scan")
	}
	return nil, errors.New("unexpected scan")
}

var testDigest = "sha256:" + strings.Repeat("a", 64)

func TestDigestResolutionCache(t *testing.T) {
	cache := NewDigestResolutionCache()

	registry := "gcr.io"
	repository := "test/image"
	tag := "latest"
	digest := "sha256:" + strings.Repeat("b", 64)

	// Test cache miss
	d, found, wasFailed := GetCachedDigestResolution(cache, registry, repository, tag)
	if found {
		t.Fatalf("expected cache miss, got found=%v", found)
	}
	if d != "" || wasFailed {
		t.Fatalf("expected empty digest and wasFailed=false, got digest=%q wasFailed=%v", d, wasFailed)
	}

	// Test successful resolution caching
	CacheDigestResolution(cache, registry, repository, tag, digest)
	d, found, wasFailed = GetCachedDigestResolution(cache, registry, repository, tag)
	if !found {
		t.Fatalf("expected cache hit after caching")
	}
	if wasFailed {
		t.Fatalf("expected wasFailed=false for successful resolution")
	}
	if d != digest {
		t.Fatalf("digest=%q want=%q", d, digest)
	}

	// Test failure caching (different tag to avoid collision)
	failedTag := "nonexistent"
	CacheDigestResolutionFailure(cache, registry, repository, failedTag)
	d, found, wasFailed = GetCachedDigestResolution(cache, registry, repository, failedTag)
	if !found {
		t.Fatalf("expected cache hit for failed resolution")
	}
	if !wasFailed {
		t.Fatalf("expected wasFailed=true for cached failure")
	}
	if d != "" {
		t.Fatalf("expected empty digest for cached failure, got %q", d)
	}
}

func TestDigestResolutionCacheKeyValidation(t *testing.T) {
	cache := NewDigestResolutionCache()

	// Empty values should not cache
	CacheDigestResolution(cache, "", "repo", "tag", "sha256:abc")
	CacheDigestResolution(cache, "registry", "", "tag", "sha256:abc")
	CacheDigestResolution(cache, "registry", "repo", "", "sha256:abc")
	CacheDigestResolution(cache, "registry", "repo", "tag", "")

	// None of these should be cached (empty key = no-op)
	_, found1, _ := GetCachedDigestResolution(cache, "", "repo", "tag")
	_, found2, _ := GetCachedDigestResolution(cache, "registry", "", "tag")
	_, found3, _ := GetCachedDigestResolution(cache, "registry", "repo", "")

	if found1 || found2 || found3 {
		t.Fatalf("expected no cache entries for invalid keys")
	}
}

func TestOCIHandler_LayerDetailsPreservedInPayload(t *testing.T) {
	// Test that vulnerability layer details are preserved when passed through
	// scanVulnerabilitiesToMaps and made available for policy evaluation.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	// Create cache entry with vulnerability containing layer details
	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()
	info := parseOCIRequestPath("/v2/library/vulnerable-app/manifests/" + testDigest)

	// Simulate vulnerability with full layer details as would come from a container scan
	vulnWithLayerDetails := map[string]any{
		"id":       "CVE-2024-TEST-LAYER",
		"severity": "HIGH",
		"package":  "openssl",
		"layerDetails": map[string]any{
			"index":       2,
			"diffId":      "sha256:" + strings.Repeat("b", 64),
			"chainId":     "sha256:" + strings.Repeat("c", 64),
			"command":     "RUN apt-get update && apt-get install -y openssl",
			"inBaseImage": true,
		},
	}

	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []map[string]any{vulnWithLayerDetails},
	})

	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache: cache,
		scanner:    stubImageScanner{t: t},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/vulnerable-app/manifests/"+testDigest, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}

	// Verify vulnerabilities are in payload
	vulns, ok := capture.payload["vulnerabilities"].([]map[string]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in payload, got %T with len %d", capture.payload["vulnerabilities"], len(vulns))
	}

	// Verify layer details are preserved
	layerDetails, ok := vulns[0]["layerDetails"].(map[string]any)
	if !ok {
		t.Fatalf("expected layerDetails map, got %T", vulns[0]["layerDetails"])
	}

	// Verify individual layer detail fields
	if layerDetails["index"] != 2 {
		t.Errorf("layerDetails.index=%v want=%v", layerDetails["index"], 2)
	}
	if layerDetails["inBaseImage"] != true {
		t.Errorf("layerDetails.inBaseImage=%v want=%v", layerDetails["inBaseImage"], true)
	}
	if !strings.Contains(layerDetails["command"].(string), "apt-get install") {
		t.Errorf("layerDetails.command=%v should contain 'apt-get install'", layerDetails["command"])
	}
	if layerDetails["diffId"] == nil || layerDetails["diffId"] == "" {
		t.Errorf("layerDetails.diffId should be populated")
	}
	if layerDetails["chainId"] == nil || layerDetails["chainId"] == "" {
		t.Errorf("layerDetails.chainId should be populated")
	}
}

func TestOCIHandler_VulnerabilityWithoutLayerDetails(t *testing.T) {
	// Test that vulnerabilities without layer details (non-container scans)
	// still work correctly in the payload.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()
	info := parseOCIRequestPath("/v2/library/go-app/manifests/" + testDigest)

	// Vulnerability without layerDetails (typical for non-OS packages in containers)
	vulnWithoutLayerDetails := map[string]any{
		"id":            "GO-2024-TEST",
		"severity":      "MEDIUM",
		"package":       "github.com/example/vulnerable",
		"fixedVersions": []any{"1.2.3"},
	}

	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []map[string]any{vulnWithoutLayerDetails},
	})

	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache: cache,
		scanner:    stubImageScanner{t: t},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/go-app/manifests/"+testDigest, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}

	vulns, ok := capture.payload["vulnerabilities"].([]map[string]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in payload")
	}

	// Verify layerDetails is absent (not nil map, just absent)
	if _, hasLayerDetails := vulns[0]["layerDetails"]; hasLayerDetails {
		// It's okay if layerDetails exists and is nil, but shouldn't have incorrect data
		if vulns[0]["layerDetails"] != nil {
			t.Errorf("layerDetails should be nil or absent for non-container vuln, got %v", vulns[0]["layerDetails"])
		}
	}

	// Verify other fields are preserved
	if vulns[0]["id"] != "GO-2024-TEST" {
		t.Errorf("id=%v want=%v", vulns[0]["id"], "GO-2024-TEST")
	}
	if vulns[0]["severity"] != "MEDIUM" {
		t.Errorf("severity=%v want=%v", vulns[0]["severity"], "MEDIUM")
	}
}

func TestOCIHandler_ImageInfoMergedIntoPayload(t *testing.T) {
	// Test that ImageInfo (config, metadata, history) is properly merged into
	// the policy payload, enabling policies to access image.config.user,
	// image.config.is_root, image.metadata.layer_count, etc.
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(upstream.Close)

	upstreamURL, err := url.Parse(upstream.URL)
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()
	info := parseOCIRequestPath("/v2/library/secure-app/manifests/" + testDigest)

	// Create cache entry with ImageInfo populated
	imageInfo := map[string]any{
		"config": map[string]any{
			"user":          "nobody",
			"is_root":       false,
			"env":           []any{"PATH=/usr/bin"},
			"sensitive_env": []any{},
			"entrypoint":    []any{"/app"},
			"cmd":           []any{"serve"},
			"exposed_ports": []any{"8080/tcp"},
			"volumes":       []any{},
			"labels":        map[string]any{"version": "1.0"},
			"working_dir":   "/app",
		},
		"metadata": map[string]any{
			"architecture": "amd64",
			"os":           "linux",
			"layer_count":  5,
			"size":         int64(50000000),
			"created":      int64(1704067200),
			"digest":       testDigest,
		},
		"history": []any{
			map[string]any{
				"created_by":  "/bin/sh -c #(nop) ADD file:abc...",
				"empty_layer": false,
			},
		},
	}

	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []map[string]any{{"id": "CVE-2024-TEST"}},
		ImageInfo:       imageInfo,
	})

	handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
		imageCache: cache,
		scanner:    stubImageScanner{t: t},
	})
	if err != nil {
		t.Fatalf("new handler: %v", err)
	}

	req := httptest.NewRequest(http.MethodGet, "http://deputy.local/v2/library/secure-app/manifests/"+testDigest, nil)
	rr := httptest.NewRecorder()
	handler.ServeHTTP(rr, req)

	if rr.Code != http.StatusOK {
		t.Fatalf("status=%d want=%d", rr.Code, http.StatusOK)
	}

	// Verify image_info is exposed as a separate payload variable
	imageInfoPayload, ok := capture.payload["image_info"].(map[string]any)
	if !ok {
		t.Fatalf("expected image_info map in payload, got %T", capture.payload["image_info"])
	}

	// Verify config is accessible
	config, ok := imageInfoPayload["config"].(map[string]any)
	if !ok {
		t.Fatalf("expected config map in image_info")
	}
	if config["user"] != "nobody" {
		t.Errorf("image_info.config.user=%v want=%v", config["user"], "nobody")
	}
	if config["is_root"] != false {
		t.Errorf("image_info.config.is_root=%v want=%v", config["is_root"], false)
	}

	// Verify metadata is accessible
	metadata, ok := imageInfoPayload["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map in image_info")
	}
	if metadata["layer_count"] != 5 {
		t.Errorf("image_info.metadata.layer_count=%v want=%v", metadata["layer_count"], 5)
	}
	if metadata["architecture"] != "amd64" {
		t.Errorf("image_info.metadata.architecture=%v want=%v", metadata["architecture"], "amd64")
	}

	// Verify ImageInfo is also merged into the image payload
	imageMap, ok := capture.payload["image"].(map[string]any)
	if !ok {
		t.Fatalf("expected image map in payload")
	}

	// Config should be merged into image (since it doesn't override existing keys)
	if _, hasConfig := imageMap["config"]; !hasConfig {
		t.Error("expected config to be merged into image payload")
	}
	if _, hasMetadata := imageMap["metadata"]; !hasMetadata {
		t.Error("expected metadata to be merged into image payload")
	}

	// Verify provenance keys are preserved (not overridden by ImageInfo)
	if imageMap["registry"] != upstreamURL.Host {
		t.Errorf("image.registry=%v want=%v (should not be overridden)", imageMap["registry"], upstreamURL.Host)
	}
	if imageMap["repository"] != "library/secure-app" {
		t.Errorf("image.repository=%v want=%v (should not be overridden)", imageMap["repository"], "library/secure-app")
	}
}

// TestOCIHandler_PolicyExpressionsWithRealPayloads verifies that container security
// policy expressions from container-security.yaml work correctly with actual OCI
// proxy payloads. This is a critical integration test to ensure policies are not
// hallucinated and will work in production.
func TestOCIHandler_PolicyExpressionsWithRealPayloads(t *testing.T) {
	// Simulate an OCI proxy payload for gcr.io/myproject/app:v1.2.3
	tagPayload := map[string]any{
		"request": map[string]any{
			"ecosystem":  "oci",
			"operation":  "manifest",
			"registry":   "gcr.io",
			"repository": "myproject/app",
			"tag":        "v1.2.3",
			"digest":     "",
			"reference":  "v1.2.3",
			"image":      "gcr.io/myproject/app:v1.2.3",
		},
		"image": map[string]any{
			"registry":   "gcr.io",
			"repository": "myproject/app",
			"tag":        "v1.2.3",
			"digest":     "",
			"reference":  "v1.2.3",
			"image":      "gcr.io/myproject/app:v1.2.3",
		},
	}

	// Simulate an OCI proxy payload for nginx:latest (should trigger block-latest-tag)
	latestPayload := map[string]any{
		"request": map[string]any{
			"ecosystem":  "oci",
			"operation":  "manifest",
			"registry":   "docker.io",
			"repository": "library/nginx",
			"tag":        "latest",
			"digest":     "",
			"reference":  "latest",
			"image":      "docker.io/library/nginx:latest",
		},
		"image": map[string]any{
			"registry":   "docker.io",
			"repository": "library/nginx",
			"tag":        "latest",
			"digest":     "",
			"reference":  "latest",
			"image":      "docker.io/library/nginx:latest",
		},
	}

	// Simulate an OCI proxy payload with image running as root
	rootPayload := map[string]any{
		"request": map[string]any{
			"ecosystem":  "oci",
			"operation":  "manifest",
			"registry":   "ghcr.io",
			"repository": "acme/insecure-app",
			"tag":        "v1.0.0",
			"reference":  "v1.0.0",
			"image":      "ghcr.io/acme/insecure-app:v1.0.0",
		},
		"image": map[string]any{
			"registry":   "ghcr.io",
			"repository": "acme/insecure-app",
			"tag":        "v1.0.0",
			"reference":  "v1.0.0",
			"image":      "ghcr.io/acme/insecure-app:v1.0.0",
			"config": map[string]any{
				"user":    "",
				"is_root": true,
			},
		},
	}

	tests := []struct {
		name       string
		expression string
		payload    map[string]any
		wantMatch  bool
		desc       string
	}{
		// Tests for block-latest-tag policy expression
		{
			name: "block-latest-tag detects explicit latest",
			expression: `has(image.image) && image.image != "" &&
				cel.bind(ref, imageRef(image.image),
					ref.tag == "latest" || (ref.tag == "" && ref.digest == ""))`,
			payload:   latestPayload,
			wantMatch: true,
			desc:      "Policy should detect :latest tag",
		},
		{
			name: "block-latest-tag allows semver tag",
			expression: `has(image.image) && image.image != "" &&
				cel.bind(ref, imageRef(image.image),
					ref.tag == "latest" || (ref.tag == "" && ref.digest == ""))`,
			payload:   tagPayload,
			wantMatch: false,
			desc:      "Policy should allow v1.2.3 tag",
		},
		// Tests for require-semver-tags policy expression
		{
			name: "require-semver-tags passes for v1.2.3",
			expression: `has(image.image) && image.image != "" &&
				cel.bind(ref, imageRef(image.image),
					ref.digest == "" &&
					!ref.tag.matches("^v?[0-9]+\\.[0-9]+\\.[0-9]+"))`,
			payload:   tagPayload,
			wantMatch: false,
			desc:      "v1.2.3 should pass semver check (not trigger warning)",
		},
		{
			name: "require-semver-tags warns for latest",
			expression: `has(image.image) && image.image != "" &&
				cel.bind(ref, imageRef(image.image),
					ref.digest == "" &&
					!ref.tag.matches("^v?[0-9]+\\.[0-9]+\\.[0-9]+"))`,
			payload:   latestPayload,
			wantMatch: true,
			desc:      "latest tag should fail semver check",
		},
		// Tests for no-root-user policy expression
		{
			name:       "no-root-user detects root",
			expression: `has(image.config) && image.config.is_root == true`,
			payload:    rootPayload,
			wantMatch:  true,
			desc:       "Policy should detect root user",
		},
		{
			name:       "no-root-user allows non-root (no config)",
			expression: `has(image.config) && image.config.is_root == true`,
			payload:    tagPayload,
			wantMatch:  false,
			desc:       "Policy should not match when no config present",
		},
		// Tests for allowed-registries policy expression
		{
			name: "allowed-registries allows gcr.io",
			expression: `has(image.image) && image.image != "" &&
				cel.bind(registry, imageRef(image.image).registry,
					!(registry in ["docker.io", "ghcr.io", "gcr.io"]) &&
					!registry.endsWith(".gcr.io") &&
					!registry.endsWith(".azurecr.io") &&
					!registry.matches(".*\\.dkr\\.ecr\\..*\\.amazonaws\\.com"))`,
			payload:   tagPayload,
			wantMatch: false,
			desc:      "gcr.io should be allowed",
		},
		// Tests for imageRef helper parsing
		{
			name:       "imageRef parses registry correctly",
			expression: `imageRef(image.image).registry == "gcr.io"`,
			payload:    tagPayload,
			wantMatch:  true,
			desc:       "imageRef should parse registry from full reference",
		},
		{
			name:       "imageRef parses tag correctly",
			expression: `imageRef(image.image).tag == "v1.2.3"`,
			payload:    tagPayload,
			wantMatch:  true,
			desc:       "imageRef should parse tag from full reference",
		},
		{
			name:       "imageRef parses repository correctly",
			expression: `imageRef(image.image).repository == "myproject/app"`,
			payload:    tagPayload,
			wantMatch:  true,
			desc:       "imageRef should parse repository from full reference",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := policy.Evaluate(t.Context(), tt.expression, tt.payload)
			if err != nil {
				t.Fatalf("Evaluate() error = %v\n%s", err, tt.desc)
			}
			got, ok := result.(bool)
			if !ok {
				t.Fatalf("expected bool result, got %T\n%s", result, tt.desc)
			}
			if got != tt.wantMatch {
				t.Errorf("expression result = %v, want %v\n%s", got, tt.wantMatch, tt.desc)
			}
		})
	}
}

// TestOCIHandler_ImageImageContainsFullReference verifies that image.image
// contains the full image reference including tag or digest, which is required
// for the imageRef() helper function to work correctly in policies.
func TestOCIHandler_ImageImageContainsFullReference(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantImageImage string // expected value of image.image
	}{
		{
			name:           "tag reference",
			path:           "/v2/library/nginx/manifests/1.25.3",
			wantImageImage: "127.0.0.1/library/nginx:1.25.3", // registry will be the upstream host
		},
		{
			name:           "digest reference",
			path:           "/v2/acme/app/manifests/" + testDigest,
			wantImageImage: "127.0.0.1/acme/app@" + testDigest,
		},
		{
			name:           "nested repository with tag",
			path:           "/v2/gcr.io/project/subdir/myimage/manifests/v1.0.0",
			wantImageImage: "127.0.0.1/gcr.io/project/subdir/myimage:v1.0.0",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)

			upstreamURL, err := url.Parse(upstream.URL)
			if err != nil {
				t.Fatalf("parse upstream: %v", err)
			}

			capture := &capturePolicyEvaluator{}

			// Mock resolver to avoid actual network calls
			mockResolve := func(ctx context.Context, ref name.Reference) (string, error) {
				return testDigest, nil
			}

			handler, err := newOCIHandler(upstream.URL, capture, &ociHandlerOptions{
				imageCache:  NewImageScanCache(),
				digestCache: NewDigestResolutionCache(),
				scanner:     stubImageScanner{},
				resolveHead: mockResolve,
			})
			if err != nil {
				t.Fatalf("new handler: %v", err)
			}

			req := httptest.NewRequest(http.MethodGet, "http://deputy.local"+tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			imageMap, ok := capture.payload["image"].(map[string]any)
			if !ok {
				t.Fatalf("expected image map in payload")
			}

			// Replace 127.0.0.1 placeholder with actual upstream host
			wantImageImage := strings.Replace(tt.wantImageImage, "127.0.0.1", upstreamURL.Host, 1)

			if imageMap["image"] != wantImageImage {
				t.Errorf("image.image=%q want=%q", imageMap["image"], wantImageImage)
			}
		})
	}
}
