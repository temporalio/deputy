package dockerfile

import (
	"slices"
	"strings"
	"testing"
)

func TestParseSimple(t *testing.T) {
	dockerfile := `FROM alpine:3.19
RUN apk add --no-cache curl
COPY app /app
CMD ["/app"]
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(info.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(info.Stages))
	}

	stage := info.Stages[0]
	if stage.BaseImage != "alpine:3.19" {
		t.Errorf("expected base image alpine:3.19, got %s", stage.BaseImage)
	}
	if stage.IsScratch {
		t.Error("expected IsScratch=false for alpine")
	}
	if len(stage.RunCommands) != 1 {
		t.Errorf("expected 1 RUN command, got %d", len(stage.RunCommands))
	}
	if len(stage.CopyCommands) != 1 {
		t.Errorf("expected 1 COPY command, got %d", len(stage.CopyCommands))
	}
	if len(stage.Cmd) != 1 || stage.Cmd[0] != "/app" {
		t.Errorf("expected CMD [\"/app\"], got %v", stage.Cmd)
	}
}

func TestParseMultiStage(t *testing.T) {
	dockerfile := `FROM golang:1.22 AS builder
WORKDIR /src
COPY . .
RUN go build -o /app

FROM scratch
COPY --from=builder /app /app
ENTRYPOINT ["/app"]
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if len(info.Stages) != 2 {
		t.Fatalf("expected 2 stages, got %d", len(info.Stages))
	}

	// Builder stage
	builder := info.Stages[0]
	if builder.Name != "builder" {
		t.Errorf("expected stage name 'builder', got %s", builder.Name)
	}
	if !builder.IsBuilderStage {
		t.Error("expected builder stage to be marked as builder")
	}
	if builder.Workdir != "/src" {
		t.Errorf("expected workdir /src, got %s", builder.Workdir)
	}

	// Final stage
	final := info.Stages[1]
	if !final.IsScratch {
		t.Error("expected final stage to be scratch")
	}
	if final.IsBuilderStage {
		t.Error("final stage should not be marked as builder")
	}
	if len(final.CopyFromStages) != 1 || final.CopyFromStages[0] != "builder" {
		t.Errorf("expected COPY --from=builder, got %v", final.CopyFromStages)
	}

	// Check final stage pointer
	if info.FinalStage == nil {
		t.Fatal("FinalStage should not be nil")
	}
	if !info.FinalStage.IsScratch {
		t.Error("FinalStage should be scratch")
	}
}

func TestParseARGSubstitution(t *testing.T) {
	dockerfile := `ARG GO_VERSION=1.22
FROM golang:${GO_VERSION}
RUN go version
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	if info.Args["GO_VERSION"] != "1.22" {
		t.Errorf("expected ARG GO_VERSION=1.22, got %v", info.Args)
	}

	if len(info.Stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(info.Stages))
	}

	stage := info.Stages[0]
	// Raw base image has the variable reference
	if stage.BaseImage != "golang:${GO_VERSION}" {
		t.Errorf("expected raw base image golang:${GO_VERSION}, got %s", stage.BaseImage)
	}
	// Resolved should have the substituted value
	if stage.BaseImageResolved == nil {
		t.Fatal("BaseImageResolved should not be nil")
	}
	if stage.BaseImageResolved.Tag != "1.22" {
		t.Errorf("expected resolved tag 1.22, got %s", stage.BaseImageResolved.Tag)
	}
}

func TestParseENV(t *testing.T) {
	dockerfile := `FROM alpine
ENV APP_HOME=/app
ENV DB_PASSWORD=secret123
ENV PATH=/usr/local/bin:$PATH
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if stage.EnvVars["APP_HOME"] != "/app" {
		t.Errorf("expected APP_HOME=/app, got %s", stage.EnvVars["APP_HOME"])
	}
	if stage.EnvVars["DB_PASSWORD"] != "secret123" {
		t.Errorf("expected DB_PASSWORD=secret123, got %s", stage.EnvVars["DB_PASSWORD"])
	}

	// Check sensitive env detection
	sensitive := stage.HasSensitiveEnv()
	found := slices.Contains(sensitive, "DB_PASSWORD")
	if !found {
		t.Errorf("expected DB_PASSWORD to be detected as sensitive, got %v", sensitive)
	}
}

func TestParseUSER(t *testing.T) {
	tests := []struct {
		dockerfile string
		isRoot     bool
	}{
		{"FROM alpine", true},                       // No USER = root
		{"FROM alpine\nUSER root", true},            // Explicit root
		{"FROM alpine\nUSER 0", true},               // UID 0 = root
		{"FROM alpine\nUSER nobody", false},         // Named user
		{"FROM alpine\nUSER 1000", false},           // Non-root UID
		{"FROM alpine\nUSER app:app", false},        // User:group
		{"FROM alpine\nUSER root\nUSER app", false}, // Last USER wins
	}

	for _, tt := range tests {
		t.Run(tt.dockerfile, func(t *testing.T) {
			info, err := Parse(strings.NewReader(tt.dockerfile))
			if err != nil {
				t.Fatalf("Parse failed: %v", err)
			}
			stage := info.Stages[0]
			if stage.IsRoot() != tt.isRoot {
				t.Errorf("expected IsRoot=%v for user=%q, got %v", tt.isRoot, stage.User, stage.IsRoot())
			}
		})
	}
}

func TestParseADD(t *testing.T) {
	dockerfile := `FROM alpine
ADD https://example.com/file.tar.gz /tmp/
ADD local.txt /app/
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if len(stage.AddCommands) != 2 {
		t.Fatalf("expected 2 ADD commands, got %d", len(stage.AddCommands))
	}

	// URL ADD
	if !stage.AddCommands[0].FromURL {
		t.Error("expected first ADD to be from URL")
	}
	// Local ADD
	if stage.AddCommands[1].FromURL {
		t.Error("expected second ADD to not be from URL")
	}
}

func TestParseLABEL(t *testing.T) {
	dockerfile := `FROM alpine
LABEL maintainer="test@example.com"
LABEL org.opencontainers.image.source="https://github.com/org/repo"
LABEL version="1.0.0"
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	// Labels may include quotes in the value depending on Dockerfile syntax
	maintainer := stage.Labels["maintainer"]
	if maintainer != "test@example.com" && maintainer != `"test@example.com"` {
		t.Errorf("expected maintainer label, got %v", stage.Labels)
	}
	source := stage.Labels["org.opencontainers.image.source"]
	if source != "https://github.com/org/repo" && source != `"https://github.com/org/repo"` {
		t.Errorf("expected OCI source label, got %v", stage.Labels)
	}
}

func TestParseHEALTHCHECK(t *testing.T) {
	dockerfile := `FROM alpine
HEALTHCHECK --interval=30s --timeout=3s --retries=3 CMD curl -f http://localhost/ || exit 1
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if stage.Healthcheck == nil {
		t.Fatal("expected HEALTHCHECK to be parsed")
	}
	if stage.Healthcheck.Retries != 3 {
		t.Errorf("expected retries=3, got %d", stage.Healthcheck.Retries)
	}
	if stage.Healthcheck.Disabled {
		t.Error("expected healthcheck to not be disabled")
	}
}

func TestParseHEALTHCHECKNone(t *testing.T) {
	dockerfile := `FROM alpine
HEALTHCHECK NONE
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if stage.Healthcheck == nil {
		t.Fatal("expected HEALTHCHECK to be parsed")
	}
	if !stage.Healthcheck.Disabled {
		t.Error("expected HEALTHCHECK NONE to set Disabled=true")
	}
}

func TestParseEXPOSE(t *testing.T) {
	dockerfile := `FROM alpine
EXPOSE 8080
EXPOSE 443/tcp 53/udp
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if len(stage.ExposedPorts) != 3 {
		t.Errorf("expected 3 exposed ports, got %d: %v", len(stage.ExposedPorts), stage.ExposedPorts)
	}
}

func TestParseScratch(t *testing.T) {
	dockerfile := `FROM scratch
COPY app /app
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	stage := info.Stages[0]
	if !stage.IsScratch {
		t.Error("expected IsScratch=true for scratch base")
	}
	if stage.BaseImageResolved.Registry != "" {
		t.Errorf("expected empty registry for scratch, got %s", stage.BaseImageResolved.Registry)
	}
}

func TestParseImageRef(t *testing.T) {
	tests := []struct {
		input    string
		registry string
		repo     string
		tag      string
		digest   string
	}{
		{"nginx", "index.docker.io", "library/nginx", "latest", ""},
		{"nginx:1.25", "index.docker.io", "library/nginx", "1.25", ""},
		{"myuser/myapp:v1", "index.docker.io", "myuser/myapp", "v1", ""},
		{"gcr.io/project/app:latest", "gcr.io", "project/app", "latest", ""},
		{"ghcr.io/owner/repo@sha256:abc123", "ghcr.io", "owner/repo", "", "sha256:abc123"},
		{"localhost:5000/myapp:dev", "localhost:5000", "myapp", "dev", ""},
	}

	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			ref := parseImageRef(tt.input)
			if ref.Registry != tt.registry {
				t.Errorf("registry: expected %q, got %q", tt.registry, ref.Registry)
			}
			if ref.Repository != tt.repo {
				t.Errorf("repository: expected %q, got %q", tt.repo, ref.Repository)
			}
			if ref.Tag != tt.tag {
				t.Errorf("tag: expected %q, got %q", tt.tag, ref.Tag)
			}
			if ref.Digest != tt.digest {
				t.Errorf("digest: expected %q, got %q", tt.digest, ref.Digest)
			}
		})
	}
}

func TestToMap(t *testing.T) {
	dockerfile := `FROM alpine:3.19
ENV APP_VERSION=1.0
LABEL version="1.0"
USER app
EXPOSE 8080
CMD ["serve"]
`
	info, err := Parse(strings.NewReader(dockerfile))
	if err != nil {
		t.Fatalf("Parse failed: %v", err)
	}

	m := info.ToMap()

	// Check top-level structure
	if _, ok := m["stages"].([]any); !ok {
		t.Error("expected stages to be []any")
	}
	if _, ok := m["final_stage"].(map[string]any); !ok {
		t.Error("expected final_stage to be map[string]any")
	}

	// Check stage fields
	stages := m["stages"].([]any)
	if len(stages) != 1 {
		t.Fatalf("expected 1 stage, got %d", len(stages))
	}
	stage := stages[0].(map[string]any)
	if stage["base_image"] != "alpine:3.19" {
		t.Errorf("expected base_image alpine:3.19, got %v", stage["base_image"])
	}
	if stage["user"] != "app" {
		t.Errorf("expected user app, got %v", stage["user"])
	}
	if stage["is_root"] != false {
		t.Errorf("expected is_root=false, got %v", stage["is_root"])
	}
}

func TestNilInfoToMap(t *testing.T) {
	var info *Info
	m := info.ToMap()

	if m["stages"] == nil {
		t.Error("expected stages to be initialized")
	}
	if _, ok := m["stages"].([]any); !ok {
		t.Error("expected stages to be []any")
	}
}
