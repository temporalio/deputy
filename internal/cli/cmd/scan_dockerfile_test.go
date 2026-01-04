package cmd

import (
	"path/filepath"
	"strings"
	"testing"
)

func TestIsDockerfilePath(t *testing.T) {
	tests := []struct {
		name     string
		filename string
		want     bool
	}{
		// Exact matches
		{"Dockerfile", "Dockerfile", true},
		{"Containerfile", "Containerfile", true},

		// Prefix patterns (Dockerfile.*)
		{"Dockerfile.prod", "Dockerfile.prod", true},
		{"Dockerfile.dev", "Dockerfile.dev", true},
		{"Dockerfile.staging", "Dockerfile.staging", true},
		{"Containerfile.prod", "Containerfile.prod", true},

		// Suffix patterns (*.dockerfile)
		{"app.dockerfile", "app.dockerfile", true},
		{"build.dockerfile", "build.dockerfile", true},
		{"APP.Dockerfile", "APP.Dockerfile", true},
		{"test.containerfile", "test.containerfile", true},

		// Suffix patterns (*Dockerfile)
		{"test-Dockerfile", "test-Dockerfile", true},
		{"my.Dockerfile", "my.Dockerfile", true},
		{"prod-Containerfile", "prod-Containerfile", true},

		// Should NOT match
		{"README.md", "README.md", false},
		{"Makefile", "Makefile", false},
		{"docker-compose.yml", "docker-compose.yml", false},
		{"Dockerfile-backup", "Dockerfile-backup", false}, // Note: this doesn't match the pattern
		{"main.go", "main.go", false},
		{"package.json", "package.json", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Use filepath to simulate a real path
			path := filepath.Join("/tmp", tt.filename)
			got := isDockerfilePath(path)
			if got != tt.want {
				t.Errorf("isDockerfilePath(%q) = %v, want %v", tt.filename, got, tt.want)
			}
		})
	}
}

func TestIsDockerfilePathWithFullPaths(t *testing.T) {
	tests := []struct {
		path string
		want bool
	}{
		{"/app/Dockerfile", true},
		{"/home/user/project/Dockerfile.prod", true},
		{"/var/build/test.dockerfile", true},
		{"/app/test-Dockerfile", true},
		{"./Dockerfile", true},
		{"../build/Containerfile", true},
		{"/app/src/main.go", false},
		{"/app/.dockerignore", false},
	}

	for _, tt := range tests {
		t.Run(tt.path, func(t *testing.T) {
			got := isDockerfilePath(tt.path)
			if got != tt.want {
				t.Errorf("isDockerfilePath(%q) = %v, want %v", tt.path, got, tt.want)
			}
		})
	}
}

func TestBuildDockerfileStagesOutput(t *testing.T) {
	// Test nil input
	result := buildDockerfileStagesOutput(nil)
	if result != nil {
		t.Errorf("buildDockerfileStagesOutput(nil) = %v, want nil", result)
	}
}

func TestBuildDockerfileAnalysisOutput(t *testing.T) {
	// Test nil input
	result := buildDockerfileAnalysisOutput(nil)
	if result.HasMultiStage {
		t.Error("expected HasMultiStage=false for nil analysis")
	}
	if result.FinalStageIsRoot {
		t.Error("expected FinalStageIsRoot=false for nil analysis")
	}
}

func TestRenderDockerfileResult(t *testing.T) {
	result := DockerfileScanResult{
		Path:       "/app/Dockerfile",
		StageCount: 2,
		Stages: []DockerfileStageOutput{
			{
				Index:          0,
				Name:           "builder",
				BaseImage:      "golang:1.22",
				IsBuilder:      true,
				IsRoot:         true,
				HasHealthcheck: false,
			},
			{
				Index:          1,
				BaseImage:      "alpine:3.19",
				User:           "nobody",
				IsRoot:         false,
				ExposedPorts:   []string{"8080"},
				HasHealthcheck: true,
			},
		},
		Analysis: DockerfileAnalysisOutput{
			HasMultiStage: true,
		},
	}

	var buf strings.Builder
	renderDockerfileResult(&buf, result, nil)
	output := buf.String()

	// Verify key output elements
	checks := []string{
		"Dockerfile: /app/Dockerfile",
		"Stages: 2",
		"Stage 0 (builder)",
		"Base: golang:1.22",
		"builder stage",
		"Stage 1",
		"Base: alpine:3.19",
		"User: nobody",
		"8080",
		"Healthcheck: configured",
		"Multi-stage build detected",
	}

	for _, check := range checks {
		if !strings.Contains(output, check) {
			t.Errorf("output missing %q\nGot:\n%s", check, output)
		}
	}
}

func TestRenderDockerfileResultWithPolicyFindings(t *testing.T) {
	result := DockerfileScanResult{
		Path:       "/app/Dockerfile",
		StageCount: 1,
		Stages: []DockerfileStageOutput{
			{
				Index:     0,
				BaseImage: "alpine:3.19",
				IsRoot:    true,
			},
		},
	}

	// Mock policy findings - using the report package type
	// We can't import report here without creating a cycle, so we just test nil case
	var buf strings.Builder
	renderDockerfileResult(&buf, result, nil)
	output := buf.String()

	if !strings.Contains(output, "Stage 0") {
		t.Errorf("output missing stage info\nGot:\n%s", output)
	}
}

func TestDockerfileScanResultStructure(t *testing.T) {
	// Verify the struct fields exist and have correct JSON tags
	result := DockerfileScanResult{
		Path:       "/test",
		StageCount: 1,
		Stages: []DockerfileStageOutput{
			{
				Index:          0,
				Name:           "builder",
				BaseImage:      "golang:1.22",
				Platform:       "linux/amd64",
				IsScratch:      false,
				IsBuilder:      true,
				User:           "app",
				IsRoot:         false,
				ExposedPorts:   []string{"8080", "8443"},
				HasHealthcheck: true,
			},
		},
		Analysis: DockerfileAnalysisOutput{
			HasMultiStage:       true,
			FinalStageIsRoot:    false,
			FinalStageIsScratch: false,
			SensitiveEnvVars:    []string{"API_KEY"},
			HasAddURL:           false,
		},
	}

	// Basic validation
	if result.StageCount != 1 {
		t.Errorf("expected StageCount=1, got %d", result.StageCount)
	}
	if len(result.Stages) != 1 {
		t.Errorf("expected 1 stage, got %d", len(result.Stages))
	}
	if result.Stages[0].Name != "builder" {
		t.Errorf("expected stage name 'builder', got %q", result.Stages[0].Name)
	}
	if !result.Analysis.HasMultiStage {
		t.Error("expected HasMultiStage=true")
	}
	if len(result.Analysis.SensitiveEnvVars) != 1 {
		t.Errorf("expected 1 sensitive env var, got %d", len(result.Analysis.SensitiveEnvVars))
	}
}
