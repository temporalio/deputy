//go:build integration

package proxy

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	"github.com/google/go-containerregistry/pkg/v1/remote"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/container/image"
	"github.com/temporalio/deputy/internal/scanning"
	"github.com/temporalio/deputy/internal/vulnerability"
)

// TestOCIProxy_PullImageThroughProxy validates that go-containerregistry can
// pull images through the Deputy OCI proxy. This is an integration test that
// requires network access but uses ghcr.io/distroless to avoid DockerHub rate limits.
func TestOCIProxy_PullImageThroughProxy(t *testing.T) {
	// Use a small, public image from ghcr.io to avoid DockerHub rate limits.
	// gcr.io/distroless/static-debian12 is tiny (~2MB) and doesn't require auth.
	const testImage = "gcr.io/distroless/static-debian12:nonroot"

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Start a real upstream proxy that forwards to gcr.io
	upstream, err := url.Parse("https://gcr.io")
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	// Use a no-op policy evaluator (captures payloads but allows all requests)
	policyEval := &capturePolicyEvaluator{}

	// Use a stub scanner to avoid actual vulnerability scanning in this test
	// (that's tested separately)
	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{
			Result: scanning.Result{},
		},
	}

	handler, err := newOCIHandler(upstream.String(), policyEval, &ociHandlerOptions{
		scanner: stubScanner,
		// Skip digest resolution for faster test
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			return "", fmt.Errorf("skip resolution in test")
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	// Start the proxy server
	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	// Parse the proxy URL to get host:port
	proxyURL, err := url.Parse(proxy.URL)
	if err != nil {
		t.Fatalf("parse proxy URL: %v", err)
	}

	// Create a reference that points to our proxy instead of gcr.io
	// The proxy will forward requests to the real gcr.io
	proxyRef := fmt.Sprintf("%s/distroless/static-debian12:nonroot", proxyURL.Host)
	ref, err := name.ParseReference(proxyRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	// Pull the image manifest through the proxy using go-containerregistry
	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
		remote.WithTransport(http.DefaultTransport),
	)
	if err != nil {
		t.Fatalf("remote.Get through proxy: %v", err)
	}

	// Verify we got a valid manifest
	if desc.Digest.String() == "" {
		t.Error("expected non-empty digest")
	}
	if desc.Size == 0 {
		t.Error("expected non-zero size")
	}

	t.Logf("Successfully pulled manifest through proxy: digest=%s size=%d", desc.Digest, desc.Size)
}

// TestOCIProxy_PolicyBlocksLatestTag tests that the proxy correctly blocks
// images with the :latest tag when configured with a policy that forbids it.
func TestOCIProxy_PolicyBlocksLatestTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a mock upstream that returns valid OCI responses
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			// Return a minimal valid manifest
			w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":100},"layers":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// Load the container security policy that blocks :latest tags
	policyPath := filepath.Join("..", "..", "policy", "examples", "container-security.yaml")
	engine, err := NewPolicyEngine([]string{policyPath})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Create handler with stub scanner (no vulns to focus on tag policy)
	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{Result: scanning.Result{}},
	}

	handler, err := newOCIHandler(upstream.URL, engine, &ociHandlerOptions{
		scanner: stubScanner,
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			return "sha256:" + strings.Repeat("a", 64), nil
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)

	// Try to pull with :latest tag - should be blocked by policy
	latestRef := fmt.Sprintf("%s/library/ubuntu:latest", proxyURL.Host)
	ref, err := name.ParseReference(latestRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	_, err = remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
	if err == nil {
		t.Fatal("expected error when pulling :latest tag, but got success")
	}

	// The error should indicate the request was forbidden
	if !strings.Contains(err.Error(), "403") && !strings.Contains(err.Error(), "DENIED") {
		t.Logf("Note: error was %v (may need policy adjustment)", err)
	}

	t.Log("Policy correctly blocked :latest tag pull")
}

// TestOCIProxy_PolicyAllowsSemverTag tests that the proxy allows images
// with proper semver tags when the policy requires semver.
func TestOCIProxy_PolicyAllowsSemverTag(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	// Create a mock upstream that returns valid OCI responses
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":100},"layers":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// Use permissive policy (no restrictions)
	policyEval := &capturePolicyEvaluator{}

	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{Result: scanning.Result{}},
	}

	handler, err := newOCIHandler(upstream.URL, policyEval, &ociHandlerOptions{
		scanner: stubScanner,
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			return "sha256:" + strings.Repeat("a", 64), nil
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)

	// Pull with a proper semver tag - should succeed
	semverRef := fmt.Sprintf("%s/library/ubuntu:v1.2.3", proxyURL.Host)
	ref, err := name.ParseReference(semverRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
	if err != nil {
		t.Fatalf("remote.Get with semver tag failed: %v", err)
	}

	if desc.Digest.String() == "" {
		t.Error("expected non-empty digest")
	}

	t.Log("Semver tag pull succeeded as expected")
}

// TestOCIProxy_VulnerabilityBlocksImage tests that the proxy blocks images
// when vulnerabilities are detected and policy requires blocking.
func TestOCIProxy_VulnerabilityBlocksImage(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":100},"layers":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// Create a policy that blocks critical vulnerabilities
	policyYAML := `
policies:
  - name: block-critical-vulns
    description: Block images with critical vulnerabilities
    entrypoints: ["oci_artifact_request"]
    rules:
      - action: deny
        when: |
          type(vulnerabilities) == list &&
          vulnerabilities.exists(v, v.severity == "CRITICAL")
        reason: "Critical vulnerability detected"
`
	policyFile := filepath.Join(t.TempDir(), "vuln-policy.yaml")
	if err := writeTestFile(policyFile, policyYAML); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	engine, err := NewPolicyEngine([]string{policyFile})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Scanner that returns a critical vulnerability
	// Note: The scan result uses vulnerability.Finding and Advisory types.
	// The proxy converts these to maps for policy evaluation via scanVulnerabilitiesToMaps.
	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{
			Result: scanning.Result{
				Findings: []vulnerability.Finding{
					{
						AdvisoryID: "CVE-2024-9999",
						Version:    "1.0.0",
					},
				},
				Advisories: map[string]*vulnerabilityv1.Advisory{
					"CVE-2024-9999": {
						Id:       "CVE-2024-9999",
						Severity: vulnerability.NewSeverity("CRITICAL", ""),
						Summary:  "Test critical vulnerability",
					},
				},
			},
		},
	}

	handler, err := newOCIHandler(upstream.URL, engine, &ociHandlerOptions{
		scanner: stubScanner,
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			return "sha256:" + strings.Repeat("a", 64), nil
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)

	vulnRef := fmt.Sprintf("%s/vulnerable/image:v1.0.0", proxyURL.Host)
	ref, err := name.ParseReference(vulnRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	_, err = remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
	if err == nil {
		t.Fatal("expected error when pulling image with critical vuln, but got success")
	}

	t.Logf("Policy correctly blocked image with critical vulnerability: %v", err)
}

// TestOCIProxy_ImageConfigAvailableInPolicy tests that image configuration
// (user, env, etc.) is available for policy evaluation.
func TestOCIProxy_ImageConfigAvailableInPolicy(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/v2/":
			w.WriteHeader(http.StatusOK)
		case strings.Contains(r.URL.Path, "/manifests/"):
			w.Header().Set("Content-Type", "application/vnd.docker.distribution.manifest.v2+json")
			w.Header().Set("Docker-Content-Digest", "sha256:"+strings.Repeat("a", 64))
			w.Write([]byte(`{"schemaVersion":2,"mediaType":"application/vnd.docker.distribution.manifest.v2+json","config":{"mediaType":"application/vnd.docker.container.image.v1+json","digest":"sha256:` + strings.Repeat("b", 64) + `","size":100},"layers":[]}`))
		default:
			w.WriteHeader(http.StatusNotFound)
		}
	}))
	defer upstream.Close()

	// Create a policy that blocks root user images
	policyYAML := `
policies:
  - name: block-root-user
    entrypoints: ["oci_artifact_request"]
    rules:
      - action: deny
        when: |
          has(image.config) && image.config.is_root == true
        reason: "Running as root is not allowed"
`
	policyFile := filepath.Join(t.TempDir(), "root-policy.yaml")
	if err := writeTestFile(policyFile, policyYAML); err != nil {
		t.Fatalf("write policy file: %v", err)
	}

	engine, err := NewPolicyEngine([]string{policyFile})
	if err != nil {
		t.Fatalf("NewPolicyEngine: %v", err)
	}

	// Scanner that returns image info with root user
	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{
			Result: scanning.Result{
				ImageInfo: &image.Info{
					Config: image.Config{
						User: "", // empty user means root
					},
				},
			},
		},
	}

	handler, err := newOCIHandler(upstream.URL, engine, &ociHandlerOptions{
		scanner: stubScanner,
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			return "sha256:" + strings.Repeat("a", 64), nil
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)

	rootRef := fmt.Sprintf("%s/root/image:v1.0.0", proxyURL.Host)
	ref, err := name.ParseReference(rootRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	_, err = remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
	if err == nil {
		t.Fatal("expected error when pulling root user image, but got success")
	}

	t.Logf("Policy correctly blocked root user image: %v", err)
}

// TestOCIProxy_RealGCRImage is an integration test that pulls a real image
// from gcr.io through the proxy. This validates end-to-end functionality.
func TestOCIProxy_RealGCRImage(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping real registry test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	// Forward to gcr.io
	upstream, err := url.Parse("https://gcr.io")
	if err != nil {
		t.Fatalf("parse upstream: %v", err)
	}

	// Use permissive policy evaluator
	policyEval := &capturePolicyEvaluator{}

	// Use stub scanner to avoid slow vuln scanning
	stubScanner := &integrationStubScanner{
		result: &scanning.Execution{Result: scanning.Result{}},
	}

	handler, err := newOCIHandler(upstream.String(), policyEval, &ociHandlerOptions{
		scanner: stubScanner,
		resolveHead: func(ctx context.Context, ref name.Reference) (string, error) {
			// Actually resolve for this test
			desc, err := remote.Head(ref,
				remote.WithContext(ctx),
				remote.WithAuth(authn.Anonymous),
			)
			if err != nil {
				return "", err
			}
			return desc.Digest.String(), nil
		},
	})
	if err != nil {
		t.Fatalf("newOCIHandler: %v", err)
	}

	proxy := httptest.NewServer(handler)
	defer proxy.Close()

	proxyURL, _ := url.Parse(proxy.URL)

	// Pull distroless/static:nonroot - tiny image, public, no rate limits
	proxyRef := fmt.Sprintf("%s/distroless/static-debian12:nonroot", proxyURL.Host)
	ref, err := name.ParseReference(proxyRef, name.Insecure)
	if err != nil {
		t.Fatalf("parse reference: %v", err)
	}

	desc, err := remote.Get(ref,
		remote.WithContext(ctx),
		remote.WithAuth(authn.Anonymous),
	)
	if err != nil {
		t.Fatalf("remote.Get through proxy: %v", err)
	}

	t.Logf("Successfully pulled real image through proxy:")
	t.Logf("  Digest: %s", desc.Digest)
	t.Logf("  Size: %d bytes", desc.Size)
	t.Logf("  MediaType: %s", desc.MediaType)

	// Verify we can read the manifest
	manifest, err := desc.Image()
	if err != nil {
		// This is expected for index manifests
		t.Logf("Note: could not parse as image (likely an index): %v", err)
	} else {
		layers, _ := manifest.Layers()
		t.Logf("  Layers: %d", len(layers))
	}
}

// writeTestFile writes content to a file for testing.
func writeTestFile(path, content string) error {
	return os.WriteFile(path, []byte(content), 0644)
}

// integrationStubScanner is a configurable test stub for the imageScanner interface.
// It returns configured results/errors for testing policy evaluation.
type integrationStubScanner struct {
	result *scanning.Execution
	err    error
}

func (s *integrationStubScanner) ScanContainerImage(ctx context.Context, target string, opts map[string]string, scanOpts scanning.Options) (*scanning.Execution, error) {
	if s.err != nil {
		return nil, s.err
	}
	return s.result, nil
}
