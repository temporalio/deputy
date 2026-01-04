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
	return nil, nil
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
