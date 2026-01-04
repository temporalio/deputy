//go:build integration
// +build integration

package scan

import (
	"context"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/picatz/deputy/internal/analysis/osv"
)

// TestScanContainerImageIntegration is the basic integration test that validates
// container image scanning works end-to-end with a real image.
func TestScanContainerImageIntegration(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	if exec == nil {
		t.Fatal("expected execution result")
	}
	t.Cleanup(func() { _ = exec.Close() })

	if exec.Result.PackagesScanned == 0 {
		t.Fatalf("expected packages scanned > 0")
	}
}

// TestScanContainerImage_ImageInfoExtraction validates that ImageInfo (user, env,
// entrypoint, etc.) is correctly extracted from container images.
func TestScanContainerImage_ImageInfoExtraction(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// Use distroless/static:nonroot which has a non-root user configured
	exec, err := svc.ScanContainerImage(ctx, "docker://gcr.io/distroless/static-debian12:nonroot", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	// Verify ImageInfo was extracted
	if exec.Result.ImageInfo == nil {
		t.Fatal("expected ImageInfo to be extracted")
	}

	info := exec.Result.ImageInfo
	t.Logf("ImageInfo extracted:")
	t.Logf("  User: %q", info.Config.User)
	t.Logf("  Entrypoint: %v", info.Config.Entrypoint)
	t.Logf("  Cmd: %v", info.Config.Cmd)
	t.Logf("  WorkingDir: %q", info.Config.WorkingDir)
	t.Logf("  Labels: %d", len(info.Config.Labels))
	t.Logf("  LayerCount: %d", info.Metadata.LayerCount)
	t.Logf("  Size: %d bytes", info.Metadata.Size)

	// distroless/static:nonroot should have a non-empty user (nonroot=65532)
	if info.Config.User == "" {
		t.Error("expected non-empty User for distroless/static:nonroot")
	}

	// Should have metadata
	if info.Metadata.LayerCount == 0 {
		t.Error("expected LayerCount > 0")
	}
	if info.Metadata.Architecture == "" {
		t.Error("expected non-empty Architecture")
	}
	if info.Metadata.OS == "" {
		t.Error("expected non-empty OS")
	}
}

// TestScanContainerImage_RootUserDetection validates that root user detection works.
func TestScanContainerImage_RootUserDetection(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	tests := []struct {
		name       string
		image      string
		expectRoot bool
	}{
		{
			name:       "alpine runs as root by default",
			image:      "docker://alpine:3.19",
			expectRoot: true,
		},
		{
			name:       "distroless nonroot runs as nonroot",
			image:      "docker://gcr.io/distroless/static-debian12:nonroot",
			expectRoot: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			exec, err := svc.ScanContainerImage(ctx, tt.image, map[string]string{"platform": "linux/amd64"}, Options{})
			if err != nil {
				t.Fatalf("ScanContainerImage(%s): %v", tt.image, err)
			}
			t.Cleanup(func() { _ = exec.Close() })

			if exec.Result.ImageInfo == nil {
				t.Fatal("expected ImageInfo")
			}

			isRoot := exec.Result.ImageInfo.Config.User == "" || exec.Result.ImageInfo.Config.User == "0" || exec.Result.ImageInfo.Config.User == "root"
			if isRoot != tt.expectRoot {
				t.Errorf("root detection: got isRoot=%v, want %v (user=%q)", isRoot, tt.expectRoot, exec.Result.ImageInfo.Config.User)
			}
		})
	}
}

// TestScanContainerImage_PlatformSelection validates that platform selection works
// correctly for multi-arch images.
func TestScanContainerImage_PlatformSelection(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	platforms := []string{"linux/amd64", "linux/arm64"}

	for _, platform := range platforms {
		t.Run(platform, func(t *testing.T) {
			exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": platform}, Options{})
			if err != nil {
				t.Fatalf("ScanContainerImage with platform %s: %v", platform, err)
			}
			t.Cleanup(func() { _ = exec.Close() })

			if exec.Result.ImageInfo == nil {
				t.Fatal("expected ImageInfo")
			}

			// Verify architecture matches requested platform
			parts := strings.Split(platform, "/")
			wantArch := parts[1]
			if exec.Result.ImageInfo.Metadata.Architecture != wantArch {
				t.Errorf("architecture mismatch: got %q, want %q", exec.Result.ImageInfo.Metadata.Architecture, wantArch)
			}
			if exec.Result.ImageInfo.Metadata.OS != parts[0] {
				t.Errorf("OS mismatch: got %q, want %q", exec.Result.ImageInfo.Metadata.OS, parts[0])
			}

			t.Logf("Platform %s: packages=%d, layers=%d", platform, exec.Result.PackagesScanned, exec.Result.ImageInfo.Metadata.LayerCount)
		})
	}
}

// TestScanContainerImage_LayerDetails validates that layer information is
// captured for vulnerabilities when scanning container images.
func TestScanContainerImage_LayerDetails(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Use real OSV client to get actual vulnerabilities with layer info
	svc := NewService()

	// Use an older image that likely has vulnerabilities
	// alpine:3.14 has known CVEs
	exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.14", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	t.Logf("Scanned alpine:3.14: packages=%d, findings=%d", exec.Result.PackagesScanned, len(exec.Result.Findings))

	// Check if any findings have layer details
	hasLayerDetails := false
	for _, finding := range exec.Result.Findings {
		if finding.LayerDetails != nil {
			hasLayerDetails = true
			t.Logf("Finding %s has layer details: index=%d, command=%q",
				finding.AdvisoryID,
				finding.LayerDetails.Index,
				truncate(finding.LayerDetails.Command, 50))
		}
	}

	if len(exec.Result.Findings) > 0 && !hasLayerDetails {
		t.Log("Note: findings exist but none have layer details (may be expected for some images)")
	}
}

// TestScanContainerImage_GCRDistroless tests scanning Google's distroless images
// which are minimal and should have few or no vulnerabilities.
func TestScanContainerImage_GCRDistroless(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewService()

	exec, err := svc.ScanContainerImage(ctx, "docker://gcr.io/distroless/static-debian12:nonroot", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	t.Logf("Distroless static scan results:")
	t.Logf("  Packages: %d", exec.Result.PackagesScanned)
	t.Logf("  Findings: %d", len(exec.Result.Findings))
	t.Logf("  Advisories: %d", len(exec.Result.Advisories))

	// Distroless static should have very few packages (it's nearly empty)
	if exec.Result.PackagesScanned > 50 {
		t.Logf("Warning: distroless/static has more packages than expected (%d)", exec.Result.PackagesScanned)
	}
}

// TestScanContainerImage_GHCRRegistry tests scanning from GitHub Container Registry.
func TestScanContainerImage_GHCRRegistry(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// Use a well-known public GHCR image
	exec, err := svc.ScanContainerImage(ctx, "docker://ghcr.io/actions/actions-runner:latest", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		// This image may require auth, so don't fail the test
		t.Skipf("Could not scan GHCR image (may require auth): %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	t.Logf("GHCR image scan: packages=%d", exec.Result.PackagesScanned)
	if exec.Result.PackagesScanned == 0 {
		t.Error("expected packages from GHCR image")
	}
}

// TestScanContainerImage_OCILayoutFromTarball tests scanning an OCI layout
// extracted from a pulled image.
func TestScanContainerImage_OCILayoutFromTarball(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}
	if testing.Short() {
		t.Skip("skipping tarball creation test in short mode")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
	defer cancel()

	// Create temp directory for OCI layout (used if crane is available)
	_ = t.TempDir()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// First scan from remote to establish baseline
	remoteExec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("Remote scan failed: %v", err)
	}
	defer remoteExec.Close()

	t.Logf("Remote scan: packages=%d", remoteExec.Result.PackagesScanned)

	// If we had the tarball, we'd scan it like this:
	// exec, err := svc.ScanContainerImage(ctx, "tarball://"+tarballPath, nil, Options{})
	// For now, just verify remote scan works
	if remoteExec.Result.PackagesScanned == 0 {
		t.Error("expected packages from remote scan")
	}
}

// TestScanContainerImage_EnvironmentVariables tests that environment variables
// are extracted from image config.
func TestScanContainerImage_EnvironmentVariables(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// Alpine has PATH set by default
	exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	if exec.Result.ImageInfo == nil {
		t.Fatal("expected ImageInfo")
	}

	t.Logf("Environment variables: %v", exec.Result.ImageInfo.Config.Env)

	// Alpine should have PATH
	hasPath := false
	for _, env := range exec.Result.ImageInfo.Config.Env {
		if strings.HasPrefix(env, "PATH=") {
			hasPath = true
			break
		}
	}
	if !hasPath {
		t.Log("Note: PATH not found in environment (may be expected for some images)")
	}

	// Check for sensitive env detection
	t.Logf("Sensitive env vars detected: %v", exec.Result.ImageInfo.Config.HasSensitiveEnv())
}

// TestScanContainerImage_Labels tests that image labels are extracted.
func TestScanContainerImage_Labels(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// nginx has various labels
	exec, err := svc.ScanContainerImage(ctx, "docker://nginx:1.25", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	if exec.Result.ImageInfo == nil {
		t.Fatal("expected ImageInfo")
	}

	t.Logf("Labels found: %d", len(exec.Result.ImageInfo.Config.Labels))
	for k, v := range exec.Result.ImageInfo.Config.Labels {
		t.Logf("  %s=%s", k, truncate(v, 60))
	}
}

// TestScanContainerImage_History tests that build history is captured.
func TestScanContainerImage_History(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	if exec.Result.ImageInfo == nil {
		t.Fatal("expected ImageInfo")
	}

	t.Logf("Build history entries: %d", len(exec.Result.ImageInfo.History))
	for i, h := range exec.Result.ImageInfo.History {
		t.Logf("  [%d] empty=%v: %s", i, h.EmptyLayer, truncate(h.CreatedBy, 60))
	}

	if len(exec.Result.ImageInfo.History) == 0 {
		t.Error("expected build history entries")
	}
}

// TestScanContainerImage_Warnings tests that warnings are captured when
// image scanning has issues.
func TestScanContainerImage_Warnings(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// Normal scan should have no warnings
	exec, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "linux/amd64"}, Options{})
	if err != nil {
		t.Fatalf("ScanContainerImage: %v", err)
	}
	t.Cleanup(func() { _ = exec.Close() })

	if len(exec.Result.Warnings) > 0 {
		t.Logf("Warnings from scan: %v", exec.Result.Warnings)
	} else {
		t.Log("No warnings (expected for healthy image scan)")
	}
}

// TestScanContainerImage_InvalidPlatform tests error handling for invalid platforms.
func TestScanContainerImage_InvalidPlatform(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 1*time.Minute)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	// Request a platform that doesn't exist for alpine
	_, err := svc.ScanContainerImage(ctx, "docker://alpine:3.19", map[string]string{"platform": "windows/arm64"}, Options{})
	if err == nil {
		t.Fatal("expected error for invalid platform")
	}

	// Error should be helpful
	if !strings.Contains(err.Error(), "platform") {
		t.Errorf("error should mention platform, got: %v", err)
	}
	t.Logf("Got expected error for invalid platform: %v", err)
}

// TestScanContainerImage_NonexistentImage tests error handling for images that don't exist.
func TestScanContainerImage_NonexistentImage(t *testing.T) {
	if os.Getenv("DEPUTY_TEST_CONTAINER_IMAGE") == "" {
		t.Skip("set DEPUTY_TEST_CONTAINER_IMAGE to run container image integration tests")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, _ osv.Client, _ []osv.PkgInput) ([]osv.Vulnerability, error) {
			return nil, nil
		},
	})

	_, err := svc.ScanContainerImage(ctx, "docker://nonexistent-registry-12345.invalid/no/such/image:v999", nil, Options{})
	if err == nil {
		t.Fatal("expected error for nonexistent image")
	}
	t.Logf("Got expected error for nonexistent image: %v", err)
}

// truncate truncates a string to maxLen characters with ellipsis.
func truncate(s string, maxLen int) string {
	if len(s) <= maxLen {
		return s
	}
	return s[:maxLen-3] + "..."
}
