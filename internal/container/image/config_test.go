package image

import (
	"testing"
	"time"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/types"
)

// mockImage implements v1.Image for testing.
type mockImage struct {
	configFile *v1.ConfigFile
	layers     []v1.Layer
	digest     v1.Hash
	manifest   *v1.Manifest
}

func (m *mockImage) Layers() ([]v1.Layer, error) {
	return m.layers, nil
}

func (m *mockImage) MediaType() (types.MediaType, error) {
	return types.DockerManifestSchema2, nil
}

func (m *mockImage) Size() (int64, error) {
	return 100, nil
}

func (m *mockImage) ConfigName() (v1.Hash, error) {
	return v1.Hash{}, nil
}

func (m *mockImage) ConfigFile() (*v1.ConfigFile, error) {
	return m.configFile, nil
}

func (m *mockImage) RawConfigFile() ([]byte, error) {
	return nil, nil
}

func (m *mockImage) Digest() (v1.Hash, error) {
	return m.digest, nil
}

func (m *mockImage) Manifest() (*v1.Manifest, error) {
	return m.manifest, nil
}

func (m *mockImage) RawManifest() ([]byte, error) {
	return nil, nil
}

func (m *mockImage) LayerByDigest(v1.Hash) (v1.Layer, error) {
	return nil, nil
}

func (m *mockImage) LayerByDiffID(v1.Hash) (v1.Layer, error) {
	return nil, nil
}

func TestExtractImageInfo(t *testing.T) {
	tests := []struct {
		name       string
		configFile *v1.ConfigFile
		wantUser   string
		wantIsRoot bool
		wantEnvLen int
	}{
		{
			name: "root user (empty)",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "",
					Env:  []string{"PATH=/usr/bin"},
				},
			},
			wantUser:   "",
			wantIsRoot: true,
			wantEnvLen: 1,
		},
		{
			name: "root user explicit",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "root",
					Env:  []string{"PATH=/usr/bin"},
				},
			},
			wantUser:   "root",
			wantIsRoot: true,
			wantEnvLen: 1,
		},
		{
			name: "non-root user",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "nobody",
					Env:  []string{"PATH=/usr/bin", "HOME=/home/nobody"},
				},
			},
			wantUser:   "nobody",
			wantIsRoot: false,
			wantEnvLen: 2,
		},
		{
			name: "numeric root user",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "0",
				},
			},
			wantUser:   "0",
			wantIsRoot: true,
			wantEnvLen: 0,
		},
		{
			name: "user:group format root",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "root:root",
				},
			},
			wantUser:   "root:root",
			wantIsRoot: true,
			wantEnvLen: 0,
		},
		{
			name: "user:group format non-root",
			configFile: &v1.ConfigFile{
				Config: v1.Config{
					User: "app:app",
				},
			},
			wantUser:   "app:app",
			wantIsRoot: false,
			wantEnvLen: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := &mockImage{configFile: tt.configFile}
			info, err := Extract(img)
			if err != nil {
				t.Fatalf("ExtractImageInfo() error = %v", err)
			}
			if info == nil {
				t.Fatal("ExtractImageInfo() returned nil")
			}
			if info.Config.User != tt.wantUser {
				t.Errorf("User = %q, want %q", info.Config.User, tt.wantUser)
			}
			if info.Config.IsRootUser() != tt.wantIsRoot {
				t.Errorf("IsRootUser() = %v, want %v", info.Config.IsRootUser(), tt.wantIsRoot)
			}
			if len(info.Config.Env) != tt.wantEnvLen {
				t.Errorf("len(Env) = %d, want %d", len(info.Config.Env), tt.wantEnvLen)
			}
		})
	}
}

func TestExtractImageInfoNil(t *testing.T) {
	info, err := Extract(nil)
	if err != nil {
		t.Fatalf("ExtractImageInfo(nil) error = %v", err)
	}
	if info != nil {
		t.Error("ExtractImageInfo(nil) should return nil")
	}
}

func TestExtractBaseImageAnnotations(t *testing.T) {
	tests := []struct {
		name       string
		manifest   *v1.Manifest
		labels     map[string]string
		wantName   string
		wantDigest string
	}{
		{
			name:     "no annotations",
			manifest: &v1.Manifest{},
			wantName: "",
		},
		{
			name: "manifest annotations",
			manifest: &v1.Manifest{
				Annotations: map[string]string{
					"org.opencontainers.image.base.name":   "docker.io/library/alpine:3.19",
					"org.opencontainers.image.base.digest": "sha256:abc123",
				},
			},
			wantName:   "docker.io/library/alpine:3.19",
			wantDigest: "sha256:abc123",
		},
		{
			name:     "labels fallback",
			manifest: &v1.Manifest{},
			labels: map[string]string{
				"org.opencontainers.image.base.name":   "gcr.io/distroless/static:nonroot",
				"org.opencontainers.image.base.digest": "sha256:def456",
			},
			wantName:   "gcr.io/distroless/static:nonroot",
			wantDigest: "sha256:def456",
		},
		{
			name: "manifest takes precedence over labels",
			manifest: &v1.Manifest{
				Annotations: map[string]string{
					"org.opencontainers.image.base.name": "from-manifest",
				},
			},
			labels: map[string]string{
				"org.opencontainers.image.base.name": "from-labels",
			},
			wantName: "from-manifest",
		},
		{
			name: "name only without digest",
			manifest: &v1.Manifest{
				Annotations: map[string]string{
					"org.opencontainers.image.base.name": "alpine:3.19",
				},
			},
			wantName:   "alpine:3.19",
			wantDigest: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			img := &mockImage{
				configFile: &v1.ConfigFile{
					Config: v1.Config{
						Labels: tt.labels,
					},
				},
				manifest: tt.manifest,
			}
			info, err := Extract(img)
			if err != nil {
				t.Fatalf("Extract() error = %v", err)
			}

			if tt.wantName == "" && tt.wantDigest == "" {
				if info.BaseImage != nil {
					t.Errorf("BaseImage = %+v, want nil", info.BaseImage)
				}
				return
			}

			if info.BaseImage == nil {
				t.Fatal("BaseImage is nil, want non-nil")
			}
			if info.BaseImage.Name != tt.wantName {
				t.Errorf("BaseImage.Name = %q, want %q", info.BaseImage.Name, tt.wantName)
			}
			if info.BaseImage.Digest != tt.wantDigest {
				t.Errorf("BaseImage.Digest = %q, want %q", info.BaseImage.Digest, tt.wantDigest)
			}
		})
	}
}

func TestBaseImageToMap(t *testing.T) {
	t.Run("with base image", func(t *testing.T) {
		info := &Info{
			BaseImage: &BaseImageRef{
				Name:   "alpine:3.19",
				Digest: "sha256:abc",
			},
		}
		m := info.ToMap()
		baseImg, ok := m["base_image"].(map[string]any)
		if !ok || baseImg == nil {
			t.Fatal("base_image not in map or wrong type")
		}
		if baseImg["name"] != "alpine:3.19" {
			t.Errorf("base_image.name = %v, want alpine:3.19", baseImg["name"])
		}
		if baseImg["digest"] != "sha256:abc" {
			t.Errorf("base_image.digest = %v, want sha256:abc", baseImg["digest"])
		}
	})

	t.Run("without base image", func(t *testing.T) {
		info := &Info{}
		m := info.ToMap()
		// When BaseImage is nil, baseImageToMap returns nil (typed as map[string]any).
		// Due to Go's interface semantics, this becomes a non-nil interface holding
		// a nil map. CEL handles this correctly (accessing nil map returns nil).
		baseImg, ok := m["base_image"].(map[string]any)
		if !ok {
			t.Fatal("base_image should be convertible to map[string]any")
		}
		if baseImg != nil {
			// This checks if the underlying map is nil
			t.Errorf("base_image map = %v, want nil map", baseImg)
		}
	})

	t.Run("nil info", func(t *testing.T) {
		var info *Info
		m := info.ToMap()
		if m["base_image"] != nil {
			t.Errorf("base_image = %v, want nil", m["base_image"])
		}
	})
}

func TestImageConfigSensitiveEnv(t *testing.T) {
	tests := []struct {
		name     string
		env      []string
		wantKeys []string
	}{
		{
			name:     "no sensitive env",
			env:      []string{"PATH=/usr/bin", "HOME=/home/user"},
			wantKeys: nil,
		},
		{
			name:     "password in env",
			env:      []string{"PATH=/usr/bin", "DATABASE_PASSWORD=secret"},
			wantKeys: []string{"DATABASE_PASSWORD"},
		},
		{
			name:     "multiple sensitive vars",
			env:      []string{"API_KEY=xxx", "AWS_SECRET_ACCESS_KEY=yyy", "NORMAL_VAR=zzz"},
			wantKeys: []string{"API_KEY", "AWS_SECRET_ACCESS_KEY"},
		},
		{
			name:     "case insensitive detection",
			env:      []string{"my_secret_token=abc", "Github_Token=def"},
			wantKeys: []string{"my_secret_token", "Github_Token"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := &Config{Env: tt.env}
			sensitive := cfg.HasSensitiveEnv()

			if len(sensitive) != len(tt.wantKeys) {
				t.Errorf("HasSensitiveEnv() = %v, want %v", sensitive, tt.wantKeys)
				return
			}

			for i, want := range tt.wantKeys {
				if sensitive[i] != want {
					t.Errorf("HasSensitiveEnv()[%d] = %q, want %q", i, sensitive[i], want)
				}
			}
		})
	}
}

func TestImageConfigToMap(t *testing.T) {
	info := &Info{
		Config: Config{
			User:         "app",
			Env:          []string{"PATH=/usr/bin"},
			Entrypoint:   []string{"/app"},
			Cmd:          []string{"serve"},
			WorkingDir:   "/app",
			ExposedPorts: []string{"8080/tcp"},
			Labels:       map[string]string{"version": "1.0"},
		},
		Metadata: Metadata{
			Architecture: "amd64",
			OS:           "linux",
			LayerCount:   5,
			Size:         1024 * 1024 * 100,
			Created:      time.Date(2024, 1, 1, 0, 0, 0, 0, time.UTC),
		},
	}

	m := info.ToMap()
	if m == nil {
		t.Fatal("ToMap() returned nil")
	}

	// Check config
	cfg, ok := m["config"].(map[string]any)
	if !ok {
		t.Fatal("config is not a map")
	}
	if cfg["user"] != "app" {
		t.Errorf("config.user = %v, want 'app'", cfg["user"])
	}
	if cfg["is_root"] != false {
		t.Errorf("config.is_root = %v, want false", cfg["is_root"])
	}

	// Check metadata
	meta, ok := m["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata is not a map")
	}
	if meta["architecture"] != "amd64" {
		t.Errorf("metadata.architecture = %v, want 'amd64'", meta["architecture"])
	}
	if meta["os"] != "linux" {
		t.Errorf("metadata.os = %v, want 'linux'", meta["os"])
	}
	if meta["layer_count"] != 5 {
		t.Errorf("metadata.layer_count = %v, want 5", meta["layer_count"])
	}
}

func TestImageInfoNilToMap(t *testing.T) {
	var info *Info
	m := info.ToMap()
	// nil ImageInfo should return an empty structure (not nil) for CEL safety.
	// This allows CEL expressions like `has(image.config)` to work without panicking.
	if m == nil {
		t.Error("nil.ToMap() = nil, want empty structure")
	}
	// Verify structure has expected keys
	if _, ok := m["config"]; !ok {
		t.Error("nil.ToMap() missing 'config' key")
	}
	if _, ok := m["metadata"]; !ok {
		t.Error("nil.ToMap() missing 'metadata' key")
	}
	if _, ok := m["history"]; !ok {
		t.Error("nil.ToMap() missing 'history' key")
	}
}

func TestImageConfigExtractedPorts(t *testing.T) {
	cfg := v1.Config{
		ExposedPorts: map[string]struct{}{
			"8080/tcp": {},
			"443/tcp":  {},
		},
	}

	ic := extractConfig(cfg)
	if len(ic.ExposedPorts) != 2 {
		t.Errorf("len(ExposedPorts) = %d, want 2", len(ic.ExposedPorts))
	}
}

func TestImageConfigExtractedVolumes(t *testing.T) {
	cfg := v1.Config{
		Volumes: map[string]struct{}{
			"/data":  {},
			"/cache": {},
		},
	}

	ic := extractConfig(cfg)
	if len(ic.Volumes) != 2 {
		t.Errorf("len(Volumes) = %d, want 2", len(ic.Volumes))
	}
}

func TestImageConfigExtractedHealthcheck(t *testing.T) {
	cfg := v1.Config{
		Healthcheck: &v1.HealthConfig{
			Test:     []string{"CMD", "curl", "-f", "http://localhost/health"},
			Interval: 30 * time.Second,
			Timeout:  10 * time.Second,
			Retries:  3,
		},
	}

	ic := extractConfig(cfg)
	if ic.Healthcheck == nil {
		t.Fatal("Healthcheck is nil")
	}
	if len(ic.Healthcheck.Test) != 4 {
		t.Errorf("len(Healthcheck.Test) = %d, want 4", len(ic.Healthcheck.Test))
	}
	if ic.Healthcheck.Retries != 3 {
		t.Errorf("Healthcheck.Retries = %d, want 3", ic.Healthcheck.Retries)
	}
}

func TestRefFromProvenance(t *testing.T) {
	tests := []struct {
		name       string
		provenance map[string]string
		wantNil    bool
		wantImage  string
	}{
		{
			name:       "nil provenance",
			provenance: nil,
			wantNil:    true,
		},
		{
			name:       "empty provenance",
			provenance: map[string]string{},
			wantNil:    true,
		},
		{
			name: "full provenance",
			provenance: map[string]string{
				"registry":   "ghcr.io",
				"repository": "owner/app",
				"tag":        "v1.0.0",
				"digest":     "sha256:abc123",
				"image":      "ghcr.io/owner/app:v1.0.0",
			},
			wantImage: "ghcr.io/owner/app:v1.0.0",
		},
		{
			name: "uses image_input fallback",
			provenance: map[string]string{
				"registry":    "docker.io",
				"repository":  "library/nginx",
				"tag":         "1.25",
				"image_input": "nginx:1.25",
			},
			wantImage: "nginx:1.25",
		},
		{
			name: "reference from digest",
			provenance: map[string]string{
				"registry":   "gcr.io",
				"repository": "project/image",
				"digest":     "sha256:abc123",
			},
			wantImage: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := RefFromProvenance(tt.provenance)
			if tt.wantNil {
				if ref != nil {
					t.Errorf("expected nil ref, got %+v", ref)
				}
				return
			}
			if ref == nil {
				t.Fatal("unexpected nil ref")
			}
			if tt.wantImage != "" && ref.Image != tt.wantImage {
				t.Errorf("Image = %q, want %q", ref.Image, tt.wantImage)
			}
		})
	}
}

func TestRefToMap(t *testing.T) {
	ref := &Ref{
		Registry:   "docker.io",
		Repository: "library/nginx",
		Tag:        "1.25",
		Digest:     "",
		Reference:  "1.25",
		Image:      "docker.io/library/nginx:1.25",
	}

	m := ref.ToMap()

	if m["registry"] != "docker.io" {
		t.Errorf("registry = %v, want docker.io", m["registry"])
	}
	if m["tag"] != "1.25" {
		t.Errorf("tag = %v, want 1.25", m["tag"])
	}
	if m["image"] != "docker.io/library/nginx:1.25" {
		t.Errorf("image = %v, want docker.io/library/nginx:1.25", m["image"])
	}
}

func TestRefToMapNil(t *testing.T) {
	var ref *Ref
	m := ref.ToMap()

	if m["registry"] != "" {
		t.Errorf("registry should be empty for nil ref")
	}
	if m["image"] != "" {
		t.Errorf("image should be empty for nil ref")
	}
}

func TestRefString(t *testing.T) {
	tests := []struct {
		name string
		ref  *Ref
		want string
	}{
		{
			name: "nil ref",
			ref:  nil,
			want: "",
		},
		{
			name: "from image field",
			ref: &Ref{
				Image: "nginx:1.25",
			},
			want: "nginx:1.25",
		},
		{
			name: "build from components with tag",
			ref: &Ref{
				Registry:   "ghcr.io",
				Repository: "owner/app",
				Tag:        "v1.0.0",
			},
			want: "ghcr.io/owner/app:v1.0.0",
		},
		{
			name: "build from components with digest",
			ref: &Ref{
				Registry:   "gcr.io",
				Repository: "project/image",
				Digest:     "sha256:abc123",
			},
			want: "gcr.io/project/image@sha256:abc123",
		},
		{
			name: "repository only",
			ref: &Ref{
				Repository: "myapp",
			},
			want: "myapp",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ref.String()
			if got != tt.want {
				t.Errorf("String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestRefIsEmpty(t *testing.T) {
	tests := []struct {
		name string
		ref  *Ref
		want bool
	}{
		{
			name: "nil ref",
			ref:  nil,
			want: true,
		},
		{
			name: "empty ref",
			ref:  &Ref{},
			want: true,
		},
		{
			name: "has image",
			ref:  &Ref{Image: "nginx"},
			want: false,
		},
		{
			name: "has registry",
			ref:  &Ref{Registry: "docker.io"},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ref.IsEmpty()
			if got != tt.want {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestPolicyPayloadToMap(t *testing.T) {
	payload := &PolicyPayload{
		Ref: &Ref{
			Registry:   "docker.io",
			Repository: "library/nginx",
			Tag:        "1.25",
			Image:      "docker.io/library/nginx:1.25",
		},
		Info: &Info{
			Config: Config{
				User: "nginx",
			},
			Metadata: Metadata{
				Architecture: "amd64",
				LayerCount:   5,
			},
		},
	}

	m := payload.ToMap()

	// Check ref fields
	if m["registry"] != "docker.io" {
		t.Errorf("registry = %v, want docker.io", m["registry"])
	}
	if m["image"] != "docker.io/library/nginx:1.25" {
		t.Errorf("image = %v, want docker.io/library/nginx:1.25", m["image"])
	}

	// Check info fields
	config, ok := m["config"].(map[string]any)
	if !ok {
		t.Fatal("config should be map[string]any")
	}
	if config["user"] != "nginx" {
		t.Errorf("config.user = %v, want nginx", config["user"])
	}

	metadata, ok := m["metadata"].(map[string]any)
	if !ok {
		t.Fatal("metadata should be map[string]any")
	}
	if metadata["architecture"] != "amd64" {
		t.Errorf("metadata.architecture = %v, want amd64", metadata["architecture"])
	}
}

func TestPolicyPayloadToMapNilFields(t *testing.T) {
	payload := &PolicyPayload{}
	m := payload.ToMap()

	// Should have empty defaults for ref fields
	if m["registry"] != "" {
		t.Errorf("registry should be empty")
	}

	// Should have empty config/metadata
	if m["config"] == nil {
		t.Error("config should not be nil")
	}
	if m["metadata"] == nil {
		t.Error("metadata should not be nil")
	}
}
