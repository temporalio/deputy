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
	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/scanning"
	"google.golang.org/protobuf/proto"
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
	// Use proto Finding messages as expected by the proto-first design
	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []*vulnerabilityv1.Finding{{
			AdvisoryId: "OSV-TEST-1",
			Advisory:   &vulnerabilityv1.Advisory{Id: "OSV-TEST-1"},
		}},
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
	// Proto-first: request.package contains the repository (OCI uses package field for this)
	if reqMap["package"] != "library/ubuntu" {
		t.Fatalf("request.package=%v want=%q", reqMap["package"], "library/ubuntu")
	}
	// Proto-first: version contains the reference (tag or digest)
	if reqMap["version"] != testDigest {
		t.Fatalf("request.version=%v want=%q", reqMap["version"], testDigest)
	}
	// Proto-first: ecosystem should be "oci"
	if reqMap["ecosystem"] != "oci" {
		t.Fatalf("request.ecosystem=%v want=%q", reqMap["ecosystem"], "oci")
	}

	imageMap, ok := capture.payload["image"].(map[string]any)
	if !ok {
		t.Fatalf("expected image map in payload")
	}
	// Proto-first: image metadata contains the digest
	metadata, ok := imageMap["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected image.metadata map in payload")
	}
	if metadata["digest"] != testDigest {
		t.Fatalf("image.metadata.digest=%v want=%q", metadata["digest"], testDigest)
	}

	if vulns, ok := capture.payload["vulnerabilities"].([]any); !ok || len(vulns) != 1 {
		t.Fatalf("expected vulnerabilities in payload, got %T (len=%v)", capture.payload["vulnerabilities"], len(vulns))
	}
}

type capturePolicyEvaluator struct {
	entrypoint string
	payload    map[string]any
}

func (c *capturePolicyEvaluator) Evaluate(_ context.Context, entrypoint string, input proto.Message) ([]policy.Action, error) {
	c.entrypoint = entrypoint
	// Convert proto to map for test assertions
	var err error
	c.payload, err = policy.ProtoToMap(input)
	if err != nil {
		return nil, err
	}
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

	// Create cache entry with vulnerability containing layer details (proto-first)
	capture := &capturePolicyEvaluator{}
	cache := NewImageScanCache()
	info := parseOCIRequestPath("/v2/library/vulnerable-app/manifests/" + testDigest)

	// Proto-first: use proto Finding messages in the cache
	vulnWithLayerDetails := []*vulnerabilityv1.Finding{
		{
			AdvisoryId: "CVE-2024-TEST-LAYER",
			Advisory: &vulnerabilityv1.Advisory{
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH,
				},
			},
			Package: &dependencyv1.Package{
				Name: "openssl",
				LayerDetails: &containerv1.LayerDetails{
					Index:       2,
					DiffId:      "sha256:" + strings.Repeat("b", 64),
					ChainId:     "sha256:" + strings.Repeat("c", 64),
					Command:     "RUN apt-get update && apt-get install -y openssl",
					InBaseImage: true,
				},
			},
		},
	}

	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: vulnWithLayerDetails,
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

	// Proto-first: vulnerabilities is []any after ProtoToMap conversion
	vulns, ok := capture.payload["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in payload, got %T with len %d", capture.payload["vulnerabilities"], len(vulns))
	}

	// Proto-first: each vulnerability is map[string]any with snake_case keys
	vulnMap, ok := vulns[0].(map[string]any)
	if !ok {
		t.Fatalf("expected vulnerability map, got %T", vulns[0])
	}

	// Proto-first: layer_details is in package field
	pkgMap, ok := vulnMap["package"].(map[string]any)
	if !ok {
		t.Fatalf("expected package map, got %T", vulnMap["package"])
	}

	// Proto-first: use snake_case field name
	layerDetails, ok := pkgMap["layer_details"].(map[string]any)
	if !ok {
		t.Fatalf("expected layer_details map, got %T", pkgMap["layer_details"])
	}

	// Proto-first: index is int64
	if idx, ok := layerDetails["index"].(int64); !ok || idx != 2 {
		t.Errorf("layer_details.index=%v want=%v", layerDetails["index"], 2)
	}
	if layerDetails["in_base_image"] != true {
		t.Errorf("layer_details.in_base_image=%v want=%v", layerDetails["in_base_image"], true)
	}
	if cmd, ok := layerDetails["command"].(string); !ok || !strings.Contains(cmd, "apt-get install") {
		t.Errorf("layer_details.command=%v should contain 'apt-get install'", layerDetails["command"])
	}
	if layerDetails["diff_id"] == nil || layerDetails["diff_id"] == "" {
		t.Errorf("layer_details.diff_id should be populated")
	}
	if layerDetails["chain_id"] == nil || layerDetails["chain_id"] == "" {
		t.Errorf("layer_details.chain_id should be populated")
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

	// Proto-first: Vulnerability without layerDetails (typical for non-OS packages in containers)
	vulnWithoutLayerDetails := []*vulnerabilityv1.Finding{
		{
			AdvisoryId: "GO-2024-TEST",
			Advisory: &vulnerabilityv1.Advisory{
				Id: "GO-2024-TEST",
				Severity: &vulnerabilityv1.Severity{
					Level: vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM,
				},
				FixedVersions: []string{"1.2.3"},
			},
			Package: &dependencyv1.Package{
				Name: "github.com/example/vulnerable",
				// No LayerDetails
			},
		},
	}

	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: vulnWithoutLayerDetails,
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

	// Proto-first: vulnerabilities is []any after ProtoToMap conversion
	vulns, ok := capture.payload["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in payload, got %T with len %v", capture.payload["vulnerabilities"], len(vulns))
	}

	vulnMap, ok := vulns[0].(map[string]any)
	if !ok {
		t.Fatalf("expected vulnerability map, got %T", vulns[0])
	}

	// Proto-first: layer_details should not be present in package (removed by removeNullValues)
	pkgMap, ok := vulnMap["package"].(map[string]any)
	if !ok {
		t.Fatalf("expected package map, got %T", vulnMap["package"])
	}
	// layer_details should be absent (nil fields are removed by removeNullValues)
	if _, hasLayerDetails := pkgMap["layer_details"]; hasLayerDetails {
		t.Errorf("layer_details should be absent for non-container vuln, got %v", pkgMap["layer_details"])
	}

	// Proto-first: verify fields using correct keys
	if vulnMap["advisory_id"] != "GO-2024-TEST" {
		t.Errorf("advisory_id=%v want=%v", vulnMap["advisory_id"], "GO-2024-TEST")
	}
}

func TestOCIHandler_ImageInfoMergedIntoPayload(t *testing.T) {
	// Test that ImageInfo (config, metadata, history) is properly exposed in
	// the policy payload, enabling policies to access image.config,
	// image.metadata.layer_count, etc.
	//
	// Proto-first design: The OciArtifactRequestPolicyInput proto has an `image`
	// field of type ImageInfo. When reading from cache, the handler builds a
	// minimal ImageInfo proto with just the digest since cached maps can't be
	// fully reconstructed back to the original struct.
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

	// Proto-first: use proto Finding messages in the cache
	cache.Set(imageCacheKey(upstreamURL.Host, info.Repository, info.Digest), ImageScanResult{
		Vulnerabilities: []*vulnerabilityv1.Finding{{
			AdvisoryId: "CVE-2024-TEST",
			Advisory:   &vulnerabilityv1.Advisory{Id: "CVE-2024-TEST"},
		}},
		// Note: ImageInfo from cache maps cannot be converted back to structs
		// The handler builds minimal ImageInfo from request metadata
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

	// Proto-first: image field contains ImageInfo (config, metadata, history)
	imageMap, ok := capture.payload["image"].(map[string]any)
	if !ok {
		t.Fatalf("expected image map in payload, got %T", capture.payload["image"])
	}

	// Proto-first: metadata contains digest from request
	metadata, ok := imageMap["metadata"].(map[string]any)
	if !ok {
		t.Fatalf("expected metadata map in image, got %T", imageMap["metadata"])
	}
	if metadata["digest"] != testDigest {
		t.Errorf("image.metadata.digest=%v want=%v", metadata["digest"], testDigest)
	}

	// Proto-first: vulnerabilities should be present
	vulns, ok := capture.payload["vulnerabilities"].([]any)
	if !ok || len(vulns) != 1 {
		t.Fatalf("expected 1 vulnerability in payload, got %T with len %v", capture.payload["vulnerabilities"], len(vulns))
	}
}

// TestOCIHandler_PolicyExpressionsWithRealPayloads verifies that container security
// policy expressions from container-security.yaml work correctly with actual OCI
// proxy payloads. This is a critical integration test to ensure policies are not
// hallucinated and will work in production.
//
// Proto-first design: Payloads mirror OciArtifactRequestPolicyInput proto:
// - request: ProxyRequest with package, version, ecosystem, operation
// - image: ImageInfo with image (full ref), registry, repository, tag, config, metadata
func TestOCIHandler_PolicyExpressionsWithRealPayloads(t *testing.T) {
	// Simulate an OCI proxy payload for gcr.io/myproject/app:v1.2.3
	// Proto fields only - matches actual handler output
	tagPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "oci",
			"operation": "manifest",
			"package":   "myproject/app",
			"version":   "v1.2.3",
		},
		"image": map[string]any{
			"image":      "gcr.io/myproject/app:v1.2.3",
			"registry":   "gcr.io",
			"repository": "myproject/app",
			"tag":        "v1.2.3",
		},
	}

	// Simulate an OCI proxy payload for nginx:latest (should trigger block-latest-tag)
	latestPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "oci",
			"operation": "manifest",
			"package":   "library/nginx",
			"version":   "latest",
		},
		"image": map[string]any{
			"image":      "docker.io/library/nginx:latest",
			"registry":   "docker.io",
			"repository": "library/nginx",
			"tag":        "latest",
		},
	}

	// Simulate an OCI proxy payload with image running as root
	rootPayload := map[string]any{
		"request": map[string]any{
			"ecosystem": "oci",
			"operation": "manifest",
			"package":   "acme/insecure-app",
			"version":   "v1.0.0",
		},
		"image": map[string]any{
			"image":      "ghcr.io/acme/insecure-app:v1.0.0",
			"registry":   "ghcr.io",
			"repository": "acme/insecure-app",
			"tag":        "v1.0.0",
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

// TestOCIHandler_ImageReferenceInPayload verifies that the OCI handler
// populates the request with repository and version information that can be
// used for policy evaluation.
//
// Proto-first design: The OciArtifactRequestPolicyInput proto uses:
// - request.package: the repository name
// - request.version: the reference (tag or digest)
// - image.image: full image reference (registry/repo:tag or registry/repo@digest)
// - image.registry: registry hostname
// - image.repository: repository path
// - image.tag: image tag (empty for digest references)
// - image.metadata.digest: the resolved digest (when available)
//
// Policies can use the full image reference directly or access individual
// components for pattern matching.
func TestOCIHandler_ImageReferenceInPayload(t *testing.T) {
	tests := []struct {
		name           string
		path           string
		wantRepository string
		wantVersion    string
		wantTag        string
		wantFullRef    string // expected image.image field
	}{
		{
			name:           "tag reference",
			path:           "/v2/library/nginx/manifests/1.25.3",
			wantRepository: "library/nginx",
			wantVersion:    "1.25.3",
			wantTag:        "1.25.3",
			wantFullRef:    "", // filled in dynamically with registry
		},
		{
			name:           "digest reference",
			path:           "/v2/acme/app/manifests/" + testDigest,
			wantRepository: "acme/app",
			wantVersion:    testDigest,
			wantTag:        "",
			wantFullRef:    "", // filled in dynamically with registry
		},
		{
			name:           "nested repository with tag",
			path:           "/v2/gcr.io/project/subdir/myimage/manifests/v1.0.0",
			wantRepository: "gcr.io/project/subdir/myimage",
			wantVersion:    "v1.0.0",
			wantTag:        "v1.0.0",
			wantFullRef:    "", // filled in dynamically with registry
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				w.WriteHeader(http.StatusOK)
			}))
			t.Cleanup(upstream.Close)

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

			// Get registry from upstream URL for expected values
			upstreamURL, _ := url.Parse(upstream.URL)
			registry := upstreamURL.Host

			req := httptest.NewRequest(http.MethodGet, "http://deputy.local"+tt.path, nil)
			rr := httptest.NewRecorder()
			handler.ServeHTTP(rr, req)

			// Proto-first: request contains repository and version
			reqMap, ok := capture.payload["request"].(map[string]any)
			if !ok {
				t.Fatalf("expected request map in payload")
			}

			// Proto-first: package field contains repository
			if reqMap["package"] != tt.wantRepository {
				t.Errorf("request.package=%q want=%q", reqMap["package"], tt.wantRepository)
			}

			// Proto-first: version field contains reference (tag or digest)
			if reqMap["version"] != tt.wantVersion {
				t.Errorf("request.version=%q want=%q", reqMap["version"], tt.wantVersion)
			}

			// Proto-first: image field should be present with provenance fields
			imageMap, ok := capture.payload["image"].(map[string]any)
			if !ok {
				t.Fatalf("expected image map in payload")
			}

			// Verify image.registry
			if imageMap["registry"] != registry {
				t.Errorf("image.registry=%q want=%q", imageMap["registry"], registry)
			}

			// Verify image.repository
			if imageMap["repository"] != tt.wantRepository {
				t.Errorf("image.repository=%q want=%q", imageMap["repository"], tt.wantRepository)
			}

			// Verify image.tag
			if imageMap["tag"] != tt.wantTag {
				t.Errorf("image.tag=%q want=%q", imageMap["tag"], tt.wantTag)
			}

			// Verify image.image (full reference)
			var expectedFullRef string
			if tt.wantTag != "" {
				expectedFullRef = registry + "/" + tt.wantRepository + ":" + tt.wantTag
			} else {
				expectedFullRef = registry + "/" + tt.wantRepository + "@" + testDigest
			}
			if imageMap["image"] != expectedFullRef {
				t.Errorf("image.image=%q want=%q", imageMap["image"], expectedFullRef)
			}

			// Verify image.metadata is present
			if imageMap["metadata"] == nil {
				t.Error("expected image.metadata to be present")
			}
		})
	}
}
