package providers

import (
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestValidateImageTarballPathOCIImageLayout(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write oci-layout: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte("{}"), 0o644); err != nil {
		t.Fatalf("write index.json: %v", err)
	}

	err := validateImageTarballPath(imageTransportTarball, dir)
	if err == nil {
		t.Fatal("expected error for OCI layout directory")
	}
	if !strings.Contains(err.Error(), "OCI layout directory") {
		t.Fatalf("unexpected error: %v", err)
	}
	// Verify the error message suggests the correct alternative
	if !strings.Contains(err.Error(), "oci-layout://") {
		t.Fatalf("error should suggest oci-layout:// scheme, got: %v", err)
	}
}

func TestValidateImageTarballPathDirectory(t *testing.T) {
	t.Parallel()
	dir := t.TempDir()
	err := validateImageTarballPath(imageTransportTarball, dir)
	if err == nil {
		t.Fatal("expected error for directory tarball path")
	}
	if !strings.Contains(err.Error(), "directory") {
		t.Fatalf("unexpected error: %v", err)
	}
}

func TestParseImageTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		target    string
		wantTrans imageTransport
		wantRef   string
		wantOK    bool
	}{
		{
			name:      "docker scheme",
			target:    "docker://alpine:latest",
			wantTrans: imageTransportRemote,
			wantRef:   "alpine:latest",
			wantOK:    true,
		},
		{
			name:      "oci scheme",
			target:    "oci://ghcr.io/owner/repo:v1.0.0",
			wantTrans: imageTransportRemote,
			wantRef:   "ghcr.io/owner/repo:v1.0.0",
			wantOK:    true,
		},
		{
			name:      "container scheme",
			target:    "container://nginx:1.25",
			wantTrans: imageTransportRemote,
			wantRef:   "nginx:1.25",
			wantOK:    true,
		},
		{
			name:      "docker-daemon scheme",
			target:    "docker-daemon://myapp:latest",
			wantTrans: imageTransportDocker,
			wantRef:   "myapp:latest",
			wantOK:    true,
		},
		{
			name:      "tarball scheme",
			target:    "tarball:///path/to/image.tar",
			wantTrans: imageTransportTarball,
			wantRef:   "/path/to/image.tar",
			wantOK:    true,
		},
		{
			name:      "oci-archive scheme",
			target:    "oci-archive:///tmp/oci-image.tar",
			wantTrans: imageTransportOCITarball,
			wantRef:   "/tmp/oci-image.tar",
			wantOK:    true,
		},
		{
			name:      "oci-layout scheme",
			target:    "oci-layout:///tmp/image-layout",
			wantTrans: imageTransportOCILayout,
			wantRef:   "/tmp/image-layout",
			wantOK:    true,
		},
		{
			name:      "no scheme (bare Docker Hub ref)",
			target:    "alpine:latest",
			wantTrans: imageTransportRemote,
			wantRef:   "alpine:latest",
			wantOK:    true,
		},
		{
			name:   "unknown scheme",
			target: "unknown://something",
			wantOK: false,
		},
		{
			name:   "empty target",
			target: "",
			wantOK: false,
		},
		{
			name:      "docker scheme with leading slash",
			target:    "docker:///alpine:latest",
			wantTrans: imageTransportRemote,
			wantRef:   "alpine:latest",
			wantOK:    true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			trans, ref, ok := parseImageTarget(tt.target)
			if ok != tt.wantOK {
				t.Errorf("parseImageTarget(%q) ok = %v, want %v", tt.target, ok, tt.wantOK)
			}
			if !tt.wantOK {
				return
			}
			if trans != tt.wantTrans {
				t.Errorf("parseImageTarget(%q) transport = %v, want %v", tt.target, trans, tt.wantTrans)
			}
			if ref != tt.wantRef {
				t.Errorf("parseImageTarget(%q) ref = %q, want %q", tt.target, ref, tt.wantRef)
			}
		})
	}
}

func TestNormalizeImageReference(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name       string
		ref        string
		wantErr    bool
		wantNorm   string
		wantReg    string
		wantRepo   string
		wantTag    string
		wantDigest string
	}{
		{
			name:     "simple tag",
			ref:      "alpine:3.19",
			wantNorm: "index.docker.io/library/alpine:3.19",
			wantReg:  "index.docker.io",
			wantRepo: "library/alpine",
			wantTag:  "3.19",
		},
		{
			name:     "full reference with tag",
			ref:      "ghcr.io/owner/repo:v1.0.0",
			wantNorm: "ghcr.io/owner/repo:v1.0.0",
			wantReg:  "ghcr.io",
			wantRepo: "owner/repo",
			wantTag:  "v1.0.0",
		},
		{
			name:       "reference with digest",
			ref:        "nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantNorm:   "index.docker.io/library/nginx@sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
			wantReg:    "index.docker.io",
			wantRepo:   "library/nginx",
			wantDigest: "sha256:e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
		},
		{
			name:     "implicit latest tag",
			ref:      "alpine",
			wantNorm: "index.docker.io/library/alpine:latest",
			wantReg:  "index.docker.io",
			wantRepo: "library/alpine",
			wantTag:  "latest",
		},
		{
			name:    "empty reference",
			ref:     "",
			wantErr: true,
		},
		{
			name:    "whitespace only",
			ref:     "   ",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			imgRef, err := normalizeImageReference(tt.ref)
			if (err != nil) != tt.wantErr {
				t.Errorf("normalizeImageReference(%q) error = %v, wantErr %v", tt.ref, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if imgRef.normalized != tt.wantNorm {
				t.Errorf("normalized = %q, want %q", imgRef.normalized, tt.wantNorm)
			}
			if imgRef.registry != tt.wantReg {
				t.Errorf("registry = %q, want %q", imgRef.registry, tt.wantReg)
			}
			if imgRef.repository != tt.wantRepo {
				t.Errorf("repository = %q, want %q", imgRef.repository, tt.wantRepo)
			}
			if imgRef.tag != tt.wantTag {
				t.Errorf("tag = %q, want %q", imgRef.tag, tt.wantTag)
			}
			if imgRef.digest != tt.wantDigest {
				t.Errorf("digest = %q, want %q", imgRef.digest, tt.wantDigest)
			}
		})
	}
}

func TestParsePlatform(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name        string
		platform    string
		wantOS      string
		wantArch    string
		wantVariant string
		wantErr     bool
	}{
		{
			name:     "linux/amd64",
			platform: "linux/amd64",
			wantOS:   "linux",
			wantArch: "amd64",
		},
		{
			name:        "linux/arm/v7",
			platform:    "linux/arm/v7",
			wantOS:      "linux",
			wantArch:    "arm",
			wantVariant: "v7",
		},
		{
			name:     "windows/amd64",
			platform: "windows/amd64",
			wantOS:   "windows",
			wantArch: "amd64",
		},
		{
			name:     "darwin/arm64",
			platform: "darwin/arm64",
			wantOS:   "darwin",
			wantArch: "arm64",
		},
		{
			name:     "with whitespace",
			platform: "  linux/amd64  ",
			wantOS:   "linux",
			wantArch: "amd64",
		},
		{
			name:     "unknown OS (allowed with warning)",
			platform: "freebsd/amd64",
			wantOS:   "freebsd",
			wantArch: "amd64",
		},
		{
			name:     "unknown arch (allowed with warning)",
			platform: "linux/sparc64",
			wantOS:   "linux",
			wantArch: "sparc64",
		},
		{
			name:     "empty",
			platform: "",
			wantErr:  true,
		},
		{
			name:     "single part",
			platform: "linux",
			wantErr:  true,
		},
		{
			name:     "too many parts",
			platform: "linux/arm/v7/extra",
			wantErr:  true,
		},
		{
			name:     "empty OS",
			platform: "/amd64",
			wantErr:  true,
		},
		{
			name:     "empty arch",
			platform: "linux/",
			wantErr:  true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			p, err := parsePlatform(tt.platform)
			if (err != nil) != tt.wantErr {
				t.Errorf("parsePlatform(%q) error = %v, wantErr %v", tt.platform, err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if p.OS != tt.wantOS {
				t.Errorf("OS = %q, want %q", p.OS, tt.wantOS)
			}
			if p.Architecture != tt.wantArch {
				t.Errorf("Architecture = %q, want %q", p.Architecture, tt.wantArch)
			}
			if p.Variant != tt.wantVariant {
				t.Errorf("Variant = %q, want %q", p.Variant, tt.wantVariant)
			}
		})
	}
}

func TestContainerImageProviderDetect(t *testing.T) {
	t.Parallel()
	provider := containerImageProvider{}
	ctx := context.Background()

	tests := []struct {
		target string
		want   bool
	}{
		// Explicit schemes
		{"docker://alpine:latest", true},
		{"oci://ghcr.io/owner/repo:v1", true},
		{"docker-daemon://myapp:latest", true},
		{"tarball:///tmp/image.tar", true},
		{"oci-archive:///tmp/oci.tar", true},
		{"oci-layout:///tmp/layout", true},
		// Bare container refs (new behavior: detected as container images)
		{"alpine:latest", true},
		{"nginx:1.25", true},
		{"ghcr.io/owner/repo:v1", true},
		{"gcr.io/project/image:tag", true},
		// Non-container targets (should not match)
		{"./local/path", false},
		{"github.com/owner/repo", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			if got := provider.Detect(ctx, tt.target); got != tt.want {
				t.Errorf("Detect(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestContainerImageProviderPriority(t *testing.T) {
	t.Parallel()
	provider := containerImageProvider{}
	if got := provider.Priority(); got != priorityContainerImage {
		t.Errorf("Priority() = %d, want %d", got, priorityContainerImage)
	}
	// Verify priority ordering
	if priorityContainerImage >= priorityLocalGit {
		t.Error("Container image priority should be lower than local git")
	}
	if priorityContainerImage <= priorityLocalDir {
		t.Error("Container image priority should be higher than local dir")
	}
	if priorityContainerImage <= priorityRemoteGit {
		t.Error("Container image priority should be higher than remote git")
	}
}

func TestSelectOCIManifest(t *testing.T) {
	t.Parallel()

	// Single manifest case
	t.Run("single manifest", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{{
			MediaType: "application/vnd.oci.image.manifest.v1+json",
			Digest:    ociDigest{Algorithm: "sha256", Encoded: "abc123"},
		}}
		got, err := selectOCIManifest(manifests, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Digest.Encoded != "abc123" {
			t.Errorf("got digest %q, want %q", got.Digest.Encoded, "abc123")
		}
	})

	// Multiple manifests with tag selection
	t.Run("select by tag", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{
			{
				Digest:      ociDigest{Algorithm: "sha256", Encoded: "aaa"},
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v1.0"},
			},
			{
				Digest:      ociDigest{Algorithm: "sha256", Encoded: "bbb"},
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v2.0"},
			},
		}
		got, err := selectOCIManifest(manifests, map[string]string{"tag": "v2.0"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Digest.Encoded != "bbb" {
			t.Errorf("got digest %q, want %q", got.Digest.Encoded, "bbb")
		}
	})

	// Multiple manifests with platform selection
	t.Run("select by platform", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{
			{
				Digest:   ociDigest{Algorithm: "sha256", Encoded: "amd64"},
				Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
			},
			{
				Digest:   ociDigest{Algorithm: "sha256", Encoded: "arm64"},
				Platform: &ociPlatform{OS: "linux", Architecture: "arm64"},
			},
		}
		got, err := selectOCIManifest(manifests, map[string]string{"platform": "linux/arm64"})
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Digest.Encoded != "arm64" {
			t.Errorf("got digest %q, want %q", got.Digest.Encoded, "arm64")
		}
	})

	// Tag not found - error when tag specified but not found
	t.Run("tag not found", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{
			{
				Digest:      ociDigest{Algorithm: "sha256", Encoded: "aaa"},
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v1.0"},
			},
			{
				Digest:      ociDigest{Algorithm: "sha256", Encoded: "bbb"},
				Annotations: map[string]string{"org.opencontainers.image.ref.name": "v2.0"},
			},
		}
		_, err := selectOCIManifest(manifests, map[string]string{"tag": "nonexistent"})
		if err == nil {
			t.Fatal("expected error for nonexistent tag")
		}
	})

	// Platform not found - error when platform specified but not found
	t.Run("platform not found", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{
			{
				Digest:   ociDigest{Algorithm: "sha256", Encoded: "amd64"},
				Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
			},
			{
				Digest:   ociDigest{Algorithm: "sha256", Encoded: "ppc64le"},
				Platform: &ociPlatform{OS: "linux", Architecture: "ppc64le"},
			},
		}
		_, err := selectOCIManifest(manifests, map[string]string{"platform": "linux/arm64"})
		if err == nil {
			t.Fatal("expected error for nonexistent platform")
		}
	})

	// Default to first when no selection criteria
	t.Run("default to first manifest", func(t *testing.T) {
		t.Parallel()
		manifests := []ociManifest{
			{Digest: ociDigest{Algorithm: "sha256", Encoded: "first"}},
			{Digest: ociDigest{Algorithm: "sha256", Encoded: "second"}},
		}
		got, err := selectOCIManifest(manifests, nil)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if got.Digest.Encoded != "first" {
			t.Errorf("got digest %q, want %q (first manifest)", got.Digest.Encoded, "first")
		}
	})
}

func TestOCIDigestUnmarshalJSON(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name    string
		input   string
		wantAlg string
		wantEnc string
		wantErr bool
	}{
		{
			name:    "valid sha256",
			input:   `"sha256:abc123def456"`,
			wantAlg: "sha256",
			wantEnc: "abc123def456",
		},
		{
			name:    "valid sha512",
			input:   `"sha512:longhash"`,
			wantAlg: "sha512",
			wantEnc: "longhash",
		},
		{
			name:    "invalid format",
			input:   `"nodivider"`,
			wantErr: true,
		},
		{
			name:    "not a string",
			input:   `123`,
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			var d ociDigest
			err := json.Unmarshal([]byte(tt.input), &d)
			if (err != nil) != tt.wantErr {
				t.Errorf("UnmarshalJSON error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if tt.wantErr {
				return
			}
			if d.Algorithm != tt.wantAlg {
				t.Errorf("Algorithm = %q, want %q", d.Algorithm, tt.wantAlg)
			}
			if d.Encoded != tt.wantEnc {
				t.Errorf("Encoded = %q, want %q", d.Encoded, tt.wantEnc)
			}
		})
	}
}

func TestIsOCIImageLayoutDir(t *testing.T) {
	t.Parallel()

	t.Run("valid OCI layout", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{"schemaVersion":2}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if !isOCIImageLayoutDir(dir) {
			t.Error("expected true for valid OCI layout directory")
		}
	})

	t.Run("missing oci-layout", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "index.json"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if isOCIImageLayoutDir(dir) {
			t.Error("expected false when oci-layout is missing")
		}
	})

	t.Run("missing index.json", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if err := os.WriteFile(filepath.Join(dir, "oci-layout"), []byte(`{}`), 0o644); err != nil {
			t.Fatal(err)
		}
		if isOCIImageLayoutDir(dir) {
			t.Error("expected false when index.json is missing")
		}
	})

	t.Run("empty directory", func(t *testing.T) {
		t.Parallel()
		dir := t.TempDir()
		if isOCIImageLayoutDir(dir) {
			t.Error("expected false for empty directory")
		}
	})

	t.Run("nonexistent directory", func(t *testing.T) {
		t.Parallel()
		if isOCIImageLayoutDir("/nonexistent/path") {
			t.Error("expected false for nonexistent directory")
		}
	})
}

func TestFormatImageTarget(t *testing.T) {
	t.Parallel()
	tests := []struct {
		target string
		ref    string
		want   string
	}{
		{"docker://alpine:3.19", "index.docker.io/library/alpine:3.19", "docker://index.docker.io/library/alpine:3.19"},
		{"oci://ghcr.io/owner/repo:v1", "ghcr.io/owner/repo:v1", "oci://ghcr.io/owner/repo:v1"},
		{"tarball:///tmp/image.tar", "/tmp/image.tar", "tarball:///tmp/image.tar"},
		{"no-scheme", "alpine", "alpine"}, // No scheme, return ref as-is
	}

	for _, tt := range tests {
		t.Run(tt.target, func(t *testing.T) {
			t.Parallel()
			got := formatImageTarget(tt.target, tt.ref)
			if got != tt.want {
				t.Errorf("formatImageTarget(%q, %q) = %q, want %q", tt.target, tt.ref, got, tt.want)
			}
		})
	}
}

func TestPlatformNotFoundShowsAvailablePlatforms(t *testing.T) {
	t.Parallel()
	manifests := []ociManifest{
		{
			Digest:   ociDigest{Algorithm: "sha256", Encoded: "amd64"},
			Platform: &ociPlatform{OS: "linux", Architecture: "amd64"},
		},
		{
			Digest:   ociDigest{Algorithm: "sha256", Encoded: "arm64v8"},
			Platform: &ociPlatform{OS: "linux", Architecture: "arm64", Variant: "v8"},
		},
	}
	_, err := selectOCIManifest(manifests, map[string]string{"platform": "windows/amd64"})
	if err == nil {
		t.Fatal("expected error for nonexistent platform")
	}
	// Verify error message includes available platforms
	errStr := err.Error()
	if !strings.Contains(errStr, "linux/amd64") {
		t.Errorf("error should mention available platform linux/amd64, got: %v", err)
	}
	if !strings.Contains(errStr, "linux/arm64/v8") {
		t.Errorf("error should mention available platform linux/arm64/v8, got: %v", err)
	}
}

func TestSelectOCIManifestPrefersLocalPlatform(t *testing.T) {
	t.Parallel()
	// Create manifests with multiple platforms including the local platform
	manifests := []ociManifest{
		{
			Digest:   ociDigest{Algorithm: "sha256", Encoded: "first"},
			Platform: &ociPlatform{OS: "windows", Architecture: "amd64"},
		},
		{
			Digest:   ociDigest{Algorithm: "sha256", Encoded: "local"},
			Platform: &ociPlatform{OS: runtime.GOOS, Architecture: runtime.GOARCH},
		},
		{
			Digest:   ociDigest{Algorithm: "sha256", Encoded: "last"},
			Platform: &ociPlatform{OS: "linux", Architecture: "ppc64le"},
		},
	}
	// Without explicit platform option, should select local platform (not first)
	got, err := selectOCIManifest(manifests, nil)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got.Digest.Encoded != "local" {
		t.Errorf("expected local platform manifest, got digest %q", got.Digest.Encoded)
	}
}

func TestWrapDockerDaemonError(t *testing.T) {
	t.Parallel()

	t.Run("connection error", func(t *testing.T) {
		t.Parallel()
		err := wrapDockerDaemonError(
			&testError{msg: "Cannot connect to Docker daemon at unix:///var/run/docker.sock"},
			"myapp:latest",
		)
		var daemonErr *DockerDaemonError
		if !errors.As(err, &daemonErr) {
			t.Fatalf("expected DockerDaemonError, got %T: %v", err, err)
		}
		if !strings.Contains(daemonErr.Hint, "docker ps") {
			t.Errorf("hint should suggest 'docker ps', got: %s", daemonErr.Hint)
		}
	})

	t.Run("image not found", func(t *testing.T) {
		t.Parallel()
		err := wrapDockerDaemonError(
			&testError{msg: "No such image: myapp:latest"},
			"myapp:latest",
		)
		var daemonErr *DockerDaemonError
		if !errors.As(err, &daemonErr) {
			t.Fatalf("expected DockerDaemonError, got %T: %v", err, err)
		}
		if !strings.Contains(daemonErr.Hint, "docker pull") {
			t.Errorf("hint should suggest 'docker pull', got: %s", daemonErr.Hint)
		}
	})

	t.Run("permission denied", func(t *testing.T) {
		t.Parallel()
		err := wrapDockerDaemonError(
			&testError{msg: "permission denied while trying to connect"},
			"myapp:latest",
		)
		var daemonErr *DockerDaemonError
		if !errors.As(err, &daemonErr) {
			t.Fatalf("expected DockerDaemonError, got %T: %v", err, err)
		}
		if !strings.Contains(daemonErr.Hint, "docker group") {
			t.Errorf("hint should mention docker group, got: %s", daemonErr.Hint)
		}
	})

	t.Run("generic error", func(t *testing.T) {
		t.Parallel()
		err := wrapDockerDaemonError(
			&testError{msg: "some other error"},
			"myapp:latest",
		)
		// Should not be a DockerDaemonError, just a wrapped error
		var daemonErr *DockerDaemonError
		if errors.As(err, &daemonErr) {
			t.Fatalf("generic error should not be DockerDaemonError")
		}
		if !strings.Contains(err.Error(), "myapp:latest") {
			t.Errorf("error should contain image name, got: %v", err)
		}
	})

	t.Run("nil error", func(t *testing.T) {
		t.Parallel()
		if err := wrapDockerDaemonError(nil, "myapp:latest"); err != nil {
			t.Errorf("nil input should return nil, got: %v", err)
		}
	})
}

func TestWrapRegistryError(t *testing.T) {
	t.Parallel()

	t.Run("rate limit", func(t *testing.T) {
		t.Parallel()
		err := wrapRegistryError(
			&testError{msg: "TOOMANYREQUESTS: rate limit exceeded"},
			"nginx:latest",
		)
		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T: %v", err, err)
		}
		if !strings.Contains(regErr.Hint, "docker login") {
			t.Errorf("hint should suggest docker login, got: %s", regErr.Hint)
		}
	})

	t.Run("unauthorized", func(t *testing.T) {
		t.Parallel()
		err := wrapRegistryError(
			&testError{msg: "UNAUTHORIZED: authentication required"},
			"private.registry.io/app:v1",
		)
		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T: %v", err, err)
		}
		if !strings.Contains(regErr.Message, "authentication") {
			t.Errorf("message should mention authentication, got: %s", regErr.Message)
		}
	})

	t.Run("not found", func(t *testing.T) {
		t.Parallel()
		err := wrapRegistryError(
			&testError{msg: "MANIFEST_UNKNOWN: manifest unknown"},
			"nonexistent:tag",
		)
		var regErr *RegistryError
		if !errors.As(err, &regErr) {
			t.Fatalf("expected RegistryError, got %T: %v", err, err)
		}
		if !strings.Contains(regErr.Message, "not found") {
			t.Errorf("message should mention not found, got: %s", regErr.Message)
		}
	})
}

// testError is a simple error type for testing error wrapping
type testError struct {
	msg string
}

func (e *testError) Error() string {
	return e.msg
}
