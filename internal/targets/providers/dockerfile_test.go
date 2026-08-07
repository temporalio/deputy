package providers

import (
	"os"
	"path/filepath"
	"testing"
)

func TestDockerfileProviderDetect(t *testing.T) {
	// Create temp directory with test files
	tmpDir := t.TempDir()

	// Create test files
	files := map[string]bool{
		"Dockerfile":         true,
		"Dockerfile.prod":    true,
		"Dockerfile.dev":     true,
		"app.dockerfile":     true,
		"build.Dockerfile":   true,
		"Containerfile":      true,
		"Containerfile.dev":  true,
		"app.containerfile":  true,
		"README.md":          false,
		"main.go":            false,
		"docker-compose.yml": false,
	}

	for name := range files {
		path := filepath.Join(tmpDir, name)
		if err := os.WriteFile(path, []byte("FROM scratch\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	provider := dockerfileProvider{}
	ctx := t.Context()

	for name, expected := range files {
		path := filepath.Join(tmpDir, name)
		t.Run(name, func(t *testing.T) {
			got := provider.Detect(ctx, path)
			if got != expected {
				t.Errorf("Detect(%q) = %v, want %v", name, got, expected)
			}
		})
	}
}

func TestDockerfileProviderOpen(t *testing.T) {
	// Create temp Dockerfile
	tmpDir := t.TempDir()
	dockerfilePath := filepath.Join(tmpDir, "Dockerfile")
	content := `FROM golang:1.22 AS builder
WORKDIR /app
COPY . .
RUN go build -o main

FROM scratch
COPY --from=builder /app/main /main
ENTRYPOINT ["/main"]
`
	if err := os.WriteFile(dockerfilePath, []byte(content), 0644); err != nil {
		t.Fatal(err)
	}

	provider := dockerfileProvider{}
	ctx := t.Context()

	mat, err := provider.Open(ctx, dockerfilePath, nil)
	if err != nil {
		t.Fatalf("Open failed: %v", err)
	}

	data, ok := mat.Data.(*DockerfileData)
	if !ok {
		t.Fatalf("expected DockerfileData, got %T", mat.Data)
	}

	if data.Info == nil {
		t.Fatal("expected Info to be populated")
	}
	if data.Analysis == nil {
		t.Fatal("expected Analysis to be populated")
	}

	// Check parsed info
	if len(data.Info.Stages) != 2 {
		t.Errorf("expected 2 stages, got %d", len(data.Info.Stages))
	}
	if !data.Analysis.HasMultiStage {
		t.Error("expected HasMultiStage=true")
	}
	if data.Analysis.FinalStageIsScratch != true {
		t.Error("expected FinalStageIsScratch=true")
	}
}

func TestFindDockerfiles(t *testing.T) {
	tmpDir := t.TempDir()

	// Create directory structure
	subDir := filepath.Join(tmpDir, "subdir")
	if err := os.MkdirAll(subDir, 0755); err != nil {
		t.Fatal(err)
	}

	// Create dockerfiles
	files := []string{
		filepath.Join(tmpDir, "Dockerfile"),
		filepath.Join(tmpDir, "Dockerfile.dev"),
		filepath.Join(subDir, "Dockerfile"),
	}
	for _, f := range files {
		if err := os.WriteFile(f, []byte("FROM scratch\n"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	// Create non-dockerfiles
	nonDockerfiles := []string{
		filepath.Join(tmpDir, "main.go"),
		filepath.Join(tmpDir, "README.md"),
	}
	for _, f := range nonDockerfiles {
		if err := os.WriteFile(f, []byte("content"), 0644); err != nil {
			t.Fatal(err)
		}
	}

	found, err := FindDockerfiles(tmpDir)
	if err != nil {
		t.Fatalf("FindDockerfiles failed: %v", err)
	}

	if len(found) != 3 {
		t.Errorf("expected 3 dockerfiles, got %d: %v", len(found), found)
	}
}

func TestFindDockerfilesSkipsHidden(t *testing.T) {
	tmpDir := t.TempDir()

	// Create hidden directory with Dockerfile
	hiddenDir := filepath.Join(tmpDir, ".hidden")
	if err := os.MkdirAll(hiddenDir, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(hiddenDir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create visible Dockerfile
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	found, err := FindDockerfiles(tmpDir)
	if err != nil {
		t.Fatalf("FindDockerfiles failed: %v", err)
	}

	// Should only find the visible Dockerfile
	if len(found) != 1 {
		t.Errorf("expected 1 dockerfile (hidden should be skipped), got %d: %v", len(found), found)
	}
}

func TestFindDockerfilesSkipsNodeModules(t *testing.T) {
	tmpDir := t.TempDir()

	// Create node_modules with Dockerfile
	nodeModules := filepath.Join(tmpDir, "node_modules", "some-package")
	if err := os.MkdirAll(nodeModules, 0755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(nodeModules, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	// Create visible Dockerfile
	if err := os.WriteFile(filepath.Join(tmpDir, "Dockerfile"), []byte("FROM scratch\n"), 0644); err != nil {
		t.Fatal(err)
	}

	found, err := FindDockerfiles(tmpDir)
	if err != nil {
		t.Fatalf("FindDockerfiles failed: %v", err)
	}

	// Should only find the visible Dockerfile
	if len(found) != 1 {
		t.Errorf("expected 1 dockerfile (node_modules should be skipped), got %d: %v", len(found), found)
	}
}
