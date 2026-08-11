package remediation

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestIsDeputyInternalCommand(t *testing.T) {
	tests := []struct {
		cmd  string
		want bool
	}{
		{"deputy:action:update file.yml owner/repo v2", true},
		{"deputy:dockerfile:update Dockerfile nginx 1.25", true},
		{"deputy:", true},
		{"go get github.com/pkg@v1.0.0", false},
		{"npm install lodash@4.17.21", false},
		{"", false},
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			if got := IsDeputyInternalCommand(tt.cmd); got != tt.want {
				t.Errorf("IsDeputyInternalCommand(%q) = %v, want %v", tt.cmd, got, tt.want)
			}
		})
	}
}

func TestApplyActionUpdate(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		actionRef  string
		newVersion string
		want       string
		wantErr    bool
	}{
		{
			name: "simple action update",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
      - uses: actions/setup-go@v4
`,
			actionRef:  "actions/checkout",
			newVersion: "v4",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
      - uses: actions/setup-go@v4
`,
			wantErr: false,
		},
		{
			name: "action with commit SHA",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a1b2c3d4e5f6a7b8c9d0
`,
			actionRef:  "actions/checkout",
			newVersion: "v4",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "action with semver",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v3.8.1
`,
			actionRef:  "actions/setup-node",
			newVersion: "v4.0.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-node@v4.0.0
`,
			wantErr: false,
		},
		{
			name: "multiple occurrences",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`,
			actionRef:  "actions/checkout",
			newVersion: "v4",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
  test:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			wantErr: false,
		},
		{
			name: "action with quotes",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: "actions/checkout@v3"
`,
			actionRef:  "actions/checkout",
			newVersion: "v4",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: "actions/checkout@v4"
`,
			wantErr: false,
		},
		{
			name: "action not found",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@v4
`,
			actionRef:  "actions/checkout",
			newVersion: "v4",
			wantErr:    true,
		},
		{
			name: "subpath action",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4
`,
			actionRef:  "aws-actions/configure-aws-credentials",
			newVersion: "v4.1.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: aws-actions/configure-aws-credentials@v4.1.0
`,
			wantErr: false,
		},
		{
			name: "SHA pinned with version comment",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.6
`,
			actionRef:  "actions/checkout",
			newVersion: "v4.2.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.2.0
`,
			wantErr: false,
		},
		{
			name: "SHA pinned with v-prefixed comment",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@cdcb36043654635271a94b9a6d1392de5bb323a7 # v5.0.1
`,
			actionRef:  "actions/setup-go",
			newVersion: "v5.1.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/setup-go@cdcb36043654635271a94b9a6d1392de5bb323a7 # v5.1.0
`,
			wantErr: false,
		},
		{
			name: "SHA pinned without v prefix in comment",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # 4.1.6
`,
			actionRef:  "actions/checkout",
			newVersion: "v4.2.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.2.0
`,
			wantErr: false,
		},
		{
			name: "multiple SHA pinned actions with comments",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.6
      - uses: actions/setup-go@cdcb36043654635271a94b9a6d1392de5bb323a7 # v5.0.1
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.1.6
`,
			actionRef:  "actions/checkout",
			newVersion: "v4.2.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.2.0
      - uses: actions/setup-go@cdcb36043654635271a94b9a6d1392de5bb323a7 # v5.0.1
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29 # v4.2.0
`,
			wantErr: false,
		},
		{
			name: "SHA pinned with extra spacing",
			content: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  #  v4.1.6
`,
			actionRef:  "actions/checkout",
			newVersion: "v4.2.0",
			want: `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@a5ac7e51b41094c92402da3b24376905380afc29  #  v4.2.0
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "workflow.yml")
			if err := os.WriteFile(filePath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			err := applyActionUpdate(t.Context(), filePath, tt.actionRef, tt.newVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyActionUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Read back and compare
			got, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("applyActionUpdate() result mismatch\ngot:\n%s\nwant:\n%s", string(got), tt.want)
			}
		})
	}
}

func TestApplyDockerfileUpdate(t *testing.T) {
	tests := []struct {
		name       string
		content    string
		image      string
		newVersion string
		want       string
		wantErr    bool
	}{
		{
			name: "simple FROM update",
			content: `FROM nginx:1.24
COPY . /usr/share/nginx/html
`,
			image:      "nginx",
			newVersion: "1.25",
			want: `FROM nginx:1.25
COPY . /usr/share/nginx/html
`,
			wantErr: false,
		},
		{
			name: "FROM with no tag",
			content: `FROM nginx
COPY . /usr/share/nginx/html
`,
			image:      "nginx",
			newVersion: "1.25",
			want: `FROM nginx:1.25
COPY . /usr/share/nginx/html
`,
			wantErr: false,
		},
		{
			name: "FROM with digest",
			content: `FROM nginx@sha256:abc123def456
COPY . /usr/share/nginx/html
`,
			image:      "nginx",
			newVersion: "1.25",
			want: `FROM nginx:1.25
COPY . /usr/share/nginx/html
`,
			wantErr: false,
		},
		{
			name: "FROM with AS alias",
			content: `FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /app /app
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM golang:1.22 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /app /app
`,
			wantErr: false,
		},
		{
			name: "FROM with platform",
			content: `FROM --platform=linux/amd64 golang:1.21
RUN go build -o /app .
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM --platform=linux/amd64 golang:1.22
RUN go build -o /app .
`,
			wantErr: false,
		},
		{
			name: "FROM with platform and AS",
			content: `FROM --platform=linux/amd64 golang:1.21 AS builder
RUN go build -o /app .
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM --platform=linux/amd64 golang:1.22 AS builder
RUN go build -o /app .
`,
			wantErr: false,
		},
		{
			name: "registry-prefixed image",
			content: `FROM gcr.io/distroless/static:nonroot
COPY app /app
`,
			image:      "gcr.io/distroless/static",
			newVersion: "latest",
			want: `FROM gcr.io/distroless/static:latest
COPY app /app
`,
			wantErr: false,
		},
		{
			name: "image not found",
			content: `FROM ubuntu:22.04
RUN apt-get update
`,
			image:      "alpine",
			newVersion: "3.19",
			wantErr:    true,
		},
		{
			name: "multi-stage only update target",
			content: `FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.18
COPY --from=builder /app /app
`,
			image:      "alpine",
			newVersion: "3.19",
			want: `FROM golang:1.21 AS builder
RUN go build -o /app .

FROM alpine:3.19
COPY --from=builder /app /app
`,
			wantErr: false,
		},
		{
			name: "case insensitive FROM",
			content: `from nginx:1.24
COPY . /usr/share/nginx/html
`,
			image:      "nginx",
			newVersion: "1.25",
			want: `from nginx:1.25
COPY . /usr/share/nginx/html
`,
			wantErr: false,
		},
		{
			name: "tag+digest best practice",
			content: `FROM alpine:3.18@sha256:c78ded0fee4493809c8ca71d4a6057a46237763d952fae15ea418f6d14137f2d
RUN apk add --no-cache ca-certificates
`,
			image:      "alpine",
			newVersion: "3.19",
			want: `FROM alpine:3.19@sha256:c78ded0fee4493809c8ca71d4a6057a46237763d952fae15ea418f6d14137f2d
RUN apk add --no-cache ca-certificates
`,
			wantErr: false,
		},
		{
			name: "tag+digest with platform",
			content: `FROM --platform=linux/amd64 golang:1.21@sha256:abc123def456
RUN go build -o /app .
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM --platform=linux/amd64 golang:1.22@sha256:abc123def456
RUN go build -o /app .
`,
			wantErr: false,
		},
		{
			name: "tag+digest with AS alias",
			content: `FROM golang:1.21@sha256:abc123def456 AS builder
RUN go build -o /app .
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM golang:1.22@sha256:abc123def456 AS builder
RUN go build -o /app .
`,
			wantErr: false,
		},
		{
			name: "digest with version comment",
			content: `FROM nginx@sha256:abc123def456 # 1.24
COPY . /usr/share/nginx/html
`,
			image:      "nginx",
			newVersion: "1.25",
			want: `FROM nginx@sha256:abc123def456 # 1.25
COPY . /usr/share/nginx/html
`,
			wantErr: false,
		},
		{
			name: "digest with version comment and AS",
			content: `FROM golang@sha256:abc123def456 AS builder # 1.21
RUN go build -o /app .
`,
			image:      "golang",
			newVersion: "1.22",
			want: `FROM golang@sha256:abc123def456 AS builder # 1.22
RUN go build -o /app .
`,
			wantErr: false,
		},
		{
			name: "registry-prefixed with tag+digest",
			content: `FROM gcr.io/distroless/static:nonroot@sha256:abc123def456
COPY app /app
`,
			image:      "gcr.io/distroless/static",
			newVersion: "debug",
			want: `FROM gcr.io/distroless/static:debug@sha256:abc123def456
COPY app /app
`,
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Create temp file
			tmpDir := t.TempDir()
			filePath := filepath.Join(tmpDir, "Dockerfile")
			if err := os.WriteFile(filePath, []byte(tt.content), 0644); err != nil {
				t.Fatalf("failed to write test file: %v", err)
			}

			err := applyDockerfileUpdate(t.Context(), filePath, tt.image, tt.newVersion)
			if (err != nil) != tt.wantErr {
				t.Errorf("applyDockerfileUpdate() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Read back and compare
			got, err := os.ReadFile(filePath)
			if err != nil {
				t.Fatalf("failed to read result: %v", err)
			}

			if string(got) != tt.want {
				t.Errorf("applyDockerfileUpdate() result mismatch\ngot:\n%s\nwant:\n%s", string(got), tt.want)
			}
		})
	}
}

func TestApplyDeputyCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		setup   map[string]string // filename -> content
		want    map[string]string // filename -> expected content
		wantErr bool
	}{
		{
			name: "action update command",
			cmd:  "deputy:action:update .github/workflows/ci.yml actions/checkout v4",
			setup: map[string]string{
				".github/workflows/ci.yml": `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v3
`,
			},
			want: map[string]string{
				".github/workflows/ci.yml": `name: CI
on: push
jobs:
  build:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
`,
			},
			wantErr: false,
		},
		{
			name: "dockerfile update command",
			cmd:  "deputy:dockerfile:update Dockerfile nginx 1.25",
			setup: map[string]string{
				"Dockerfile": `FROM nginx:1.24
COPY . /usr/share/nginx/html
`,
			},
			want: map[string]string{
				"Dockerfile": `FROM nginx:1.25
COPY . /usr/share/nginx/html
`,
			},
			wantErr: false,
		},
		{
			name:    "unknown command",
			cmd:     "deputy:unknown:command arg1 arg2",
			wantErr: true,
		},
		{
			name:    "invalid action command (missing args)",
			cmd:     "deputy:action:update file.yml",
			wantErr: true,
		},
		{
			name:    "invalid dockerfile command (missing args)",
			cmd:     "deputy:dockerfile:update Dockerfile",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tmpDir := t.TempDir()

			// Setup test files
			for filename, content := range tt.setup {
				fullPath := filepath.Join(tmpDir, filename)
				if err := os.MkdirAll(filepath.Dir(fullPath), 0755); err != nil {
					t.Fatalf("failed to create directory: %v", err)
				}
				if err := os.WriteFile(fullPath, []byte(content), 0644); err != nil {
					t.Fatalf("failed to write test file: %v", err)
				}
			}

			err := ApplyDeputyCommand(t.Context(), tmpDir, tt.cmd)
			if (err != nil) != tt.wantErr {
				t.Errorf("ApplyDeputyCommand() error = %v, wantErr %v", err, tt.wantErr)
				return
			}

			if tt.wantErr {
				return
			}

			// Verify results
			for filename, wantContent := range tt.want {
				fullPath := filepath.Join(tmpDir, filename)
				got, err := os.ReadFile(fullPath)
				if err != nil {
					t.Fatalf("failed to read result file %s: %v", filename, err)
				}
				if string(got) != wantContent {
					t.Errorf("file %s content mismatch\ngot:\n%s\nwant:\n%s", filename, string(got), wantContent)
				}
			}
		})
	}
}

// TestValidateDeputyCommand pins the non-mutating validation that dry runs
// rely on to predict whether ApplyDeputyCommand would accept a command:
// opcode and arity are checked without touching the filesystem.
func TestValidateDeputyCommand(t *testing.T) {
	tests := []struct {
		name    string
		cmd     string
		wantErr string // substring; empty means the command must validate
	}{
		{
			name: "action update with all arguments",
			cmd:  "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
		},
		{
			name: "action pin with all arguments",
			cmd:  "deputy:action:pin .github/workflows/ci.yml actions/checkout abc123 v4",
		},
		{
			name: "dockerfile update with all arguments",
			cmd:  "deputy:dockerfile:update Dockerfile golang 1.24",
		},
		{
			name:    "unknown opcode",
			cmd:     "deputy:unknown foo",
			wantErr: "unknown deputy command: deputy:unknown",
		},
		{
			name:    "action update missing arguments",
			cmd:     "deputy:action:update file.yml",
			wantErr: "expected 4 parts, got 2",
		},
		{
			name:    "action pin missing tag",
			cmd:     "deputy:action:pin file.yml actions/checkout abc123",
			wantErr: "expected 5 parts, got 4",
		},
		{
			name:    "unterminated quote",
			cmd:     `deputy:action:update "unclosed`,
			wantErr: "invalid command",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			parts, err := ValidateDeputyCommand(tt.cmd)
			if tt.wantErr == "" {
				if err != nil {
					t.Fatalf("ValidateDeputyCommand(%q) = %v, want success", tt.cmd, err)
				}
				if len(parts) == 0 {
					t.Fatal("ValidateDeputyCommand returned no parts on success")
				}
				return
			}
			if err == nil {
				t.Fatalf("ValidateDeputyCommand(%q) succeeded, want error containing %q", tt.cmd, tt.wantErr)
			}
			if !strings.Contains(err.Error(), tt.wantErr) {
				t.Fatalf("error = %v, want it to contain %q", err, tt.wantErr)
			}
		})
	}
}

// TestApplyDeputyCommandRejectsWhatValidationRejects pins that the apply path
// shares the validator, so a dry run's prediction cannot drift from what
// applying actually does.
func TestApplyDeputyCommandRejectsWhatValidationRejects(t *testing.T) {
	invalid := []string{
		"deputy:unknown foo",
		"deputy:action:update file.yml",
		"deputy:action:pin file.yml actions/checkout abc123",
	}
	for _, cmd := range invalid {
		t.Run(cmd, func(t *testing.T) {
			if _, err := ValidateDeputyCommand(cmd); err == nil {
				t.Fatalf("ValidateDeputyCommand(%q) unexpectedly succeeded", cmd)
			}
			if err := ApplyDeputyCommand(t.Context(), t.TempDir(), cmd); err == nil {
				t.Fatalf("ApplyDeputyCommand(%q) unexpectedly succeeded", cmd)
			}
		})
	}
}

// TestApplyDeputyCommandThroughSymlinkedRepoDir pins that a deputy-internal
// command works when the repository directory is reached through a symlink.
// resolveDeputyCommand resolves the target path's symlinks, so any step that
// relates that path back to the caller's unresolved repoDir computes a path
// that leaves the repository and comes back in, which os.Root refuses. macOS
// puts every temporary directory behind such a symlink (/var -> /private/var),
// so this is the ordinary case there rather than an exotic one.
func TestApplyDeputyCommandThroughSymlinkedRepoDir(t *testing.T) {
	const (
		workflow   = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
		dockerfile = "FROM alpine:3.18\n"
		sha        = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)
	tests := []struct {
		name        string
		file        string
		content     string
		cmd         string
		wantApplied string
	}{
		{
			name:        "action update",
			file:        ".github/workflows/ci.yml",
			content:     workflow,
			cmd:         "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
			wantApplied: "actions/checkout@v5",
		},
		{
			name:        "action pin",
			file:        ".github/workflows/ci.yml",
			content:     workflow,
			cmd:         "deputy:action:pin .github/workflows/ci.yml actions/checkout " + sha + " v4.2.2",
			wantApplied: "actions/checkout@" + sha + " # v4.2.2",
		},
		{
			name:        "dockerfile update",
			file:        "Dockerfile",
			content:     dockerfile,
			cmd:         "deputy:dockerfile:update Dockerfile alpine 3.19",
			wantApplied: "FROM alpine:3.19",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Build the repository under a real directory, then hand the
			// command a symlink to it so repoDir and the resolved file path
			// disagree in exactly the way a macOS temp directory makes them.
			realDir := filepath.Join(t.TempDir(), "real")
			target := filepath.Join(realDir, tt.file)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			if err := os.WriteFile(target, []byte(tt.content), 0o644); err != nil {
				t.Fatalf("WriteFile failed: %v", err)
			}
			linkDir := filepath.Join(t.TempDir(), "link")
			if err := os.Symlink(realDir, linkDir); err != nil {
				t.Skipf("symlinks unsupported: %v", err)
			}

			if err := ApplyDeputyCommand(t.Context(), linkDir, tt.cmd); err != nil {
				t.Fatalf("ApplyDeputyCommand() through symlinked repoDir failed: %v", err)
			}
			got, err := os.ReadFile(target)
			if err != nil {
				t.Fatalf("ReadFile failed: %v", err)
			}
			if !strings.Contains(string(got), tt.wantApplied) {
				t.Fatalf("edit not applied: want %q in:\n%s", tt.wantApplied, got)
			}
		})
	}
}

// TestApplyDeputyCommandHonorsContext pins the execution timeout for
// deputy-internal steps. These commands are applied in process, so no
// subprocess machinery enforces the caller's deadline on them: if the apply
// path ignored its context, a step whose deadline expired while it ran would
// still commit its rewrite, and the caller that was already told the step
// timed out would find the workspace modified anyway.
//
// Each opcode is checked with a context that is already done and with a live
// one. The live case is the positive control: without it, an apply path that
// refused every command would pass the cancelled cases.
func TestApplyDeputyCommandHonorsContext(t *testing.T) {
	const (
		workflow   = "jobs:\n  build:\n    steps:\n      - uses: actions/checkout@v4\n"
		dockerfile = "FROM alpine:3.18\nRUN echo hi\n"
		sha        = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)
	tests := []struct {
		name string
		// file is the workspace-relative path the command edits.
		file string
		// content is what that file holds before the command runs.
		content string
		cmd     string
		// wantApplied is a substring the live run must produce, so a
		// silently-skipped edit cannot masquerade as success.
		wantApplied string
	}{
		{
			name:        "action update",
			file:        ".github/workflows/ci.yml",
			content:     workflow,
			cmd:         "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
			wantApplied: "actions/checkout@v5",
		},
		{
			name:        "action pin",
			file:        ".github/workflows/ci.yml",
			content:     workflow,
			cmd:         "deputy:action:pin .github/workflows/ci.yml actions/checkout " + sha + " v4.2.2",
			wantApplied: "actions/checkout@" + sha + " # v4.2.2",
		},
		{
			name:        "dockerfile update",
			file:        "Dockerfile",
			content:     dockerfile,
			cmd:         "deputy:dockerfile:update Dockerfile alpine 3.19",
			wantApplied: "FROM alpine:3.19",
		},
	}

	// writeWorkspace lays down one command's target file in a fresh directory
	// and returns that directory and the absolute path of the file.
	writeWorkspace := func(t *testing.T, relPath, content string) (dir, path string) {
		t.Helper()
		dir = t.TempDir()
		path = filepath.Join(dir, relPath)
		if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
			t.Fatalf("MkdirAll failed: %v", err)
		}
		if err := os.WriteFile(path, []byte(content), 0o644); err != nil {
			t.Fatalf("WriteFile failed: %v", err)
		}
		return dir, path
	}

	// requireUnmodified fails when the command touched the workspace.
	requireUnmodified := func(t *testing.T, path, want string) {
		t.Helper()
		got, err := os.ReadFile(path)
		if err != nil {
			t.Fatalf("ReadFile failed: %v", err)
		}
		if string(got) != want {
			t.Fatalf("workspace modified despite a dead context:\n%s", got)
		}
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Run("cancelled context modifies nothing", func(t *testing.T) {
				dir, path := writeWorkspace(t, tt.file, tt.content)
				ctx, cancel := context.WithCancel(t.Context())
				cancel()

				if err := ApplyDeputyCommand(ctx, dir, tt.cmd); !errors.Is(err, context.Canceled) {
					t.Fatalf("ApplyDeputyCommand() error = %v, want context.Canceled", err)
				}
				requireUnmodified(t, path, tt.content)
			})

			t.Run("expired deadline modifies nothing", func(t *testing.T) {
				dir, path := writeWorkspace(t, tt.file, tt.content)
				ctx, cancel := context.WithTimeout(t.Context(), -time.Second)
				defer cancel()

				if err := ApplyDeputyCommand(ctx, dir, tt.cmd); !errors.Is(err, context.DeadlineExceeded) {
					t.Fatalf("ApplyDeputyCommand() error = %v, want context.DeadlineExceeded", err)
				}
				requireUnmodified(t, path, tt.content)
			})

			t.Run("live context applies the edit", func(t *testing.T) {
				dir, path := writeWorkspace(t, tt.file, tt.content)
				if err := ApplyDeputyCommand(t.Context(), dir, tt.cmd); err != nil {
					t.Fatalf("ApplyDeputyCommand() failed: %v", err)
				}
				got, err := os.ReadFile(path)
				if err != nil {
					t.Fatalf("ReadFile failed: %v", err)
				}
				if !strings.Contains(string(got), tt.wantApplied) {
					t.Fatalf("edit not applied, positive control is vacuous: want %q in:\n%s", tt.wantApplied, got)
				}
			})
		})
	}
}

// TestDeputyCommandRefusesIrregularTarget pins that a deputy-internal command
// refuses a target that is not a regular file, and that preflight refuses it on
// the same terms so a dry run cannot preview a step execution would reject.
//
// The refusal has to happen before the read. A FIFO with no writer blocks the
// opening read indefinitely, and no context can interrupt a read already
// blocked in the kernel, so a plan naming one would hold its step past any
// execution timeout. The test enforces that with its own deadline: it fails
// rather than hangs if the guard regresses.
func TestDeputyCommandRefusesIrregularTarget(t *testing.T) {
	commands := []struct {
		name string
		file string
		cmd  string
	}{
		{
			name: "action update",
			file: ".github/workflows/ci.yml",
			cmd:  "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
		},
		{
			name: "action pin",
			file: ".github/workflows/ci.yml",
			cmd:  "deputy:action:pin .github/workflows/ci.yml actions/checkout 11bd71901bbe5b1630ceea73d27597364c9af683 v4.2.2",
		},
		{
			name: "dockerfile update",
			file: "Dockerfile",
			cmd:  "deputy:dockerfile:update Dockerfile alpine 3.19",
		},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			target := filepath.Join(dir, tc.file)
			if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
				t.Fatalf("MkdirAll failed: %v", err)
			}
			if err := syscall.Mkfifo(target, 0o644); err != nil {
				t.Skipf("mkfifo unsupported: %v", err)
			}

			// Run both paths off the test goroutine so a regression shows up
			// as a failure instead of hanging the package until its timeout.
			type result struct {
				preflight error
				apply     error
			}
			done := make(chan result, 1)
			go func() {
				var got result
				got.preflight = PreflightDeputyCommand(dir, tc.cmd)
				got.apply = ApplyDeputyCommand(context.Background(), dir, tc.cmd)
				done <- got
			}()

			select {
			case got := <-done:
				if got.preflight == nil {
					t.Errorf("PreflightDeputyCommand(%q) accepted a FIFO target", tc.cmd)
				}
				if got.apply == nil {
					t.Errorf("ApplyDeputyCommand(%q) accepted a FIFO target", tc.cmd)
				}
				if got.preflight != nil && got.apply != nil && got.preflight.Error() != got.apply.Error() {
					t.Errorf("dry run and execution refused differently:\npreflight: %v\napply:     %v", got.preflight, got.apply)
				}
			case <-time.After(10 * time.Second):
				// The goroutine stays blocked on the FIFO; the test binary
				// exits and takes it with it.
				t.Fatalf("blocked reading a FIFO target: the execution timeout cannot bound this step")
			}
		})
	}
}

// TestDeputyCommandRefusesMissingTarget pins that preflight refuses a command
// whose target is not there, on the same terms and in the same words as the
// apply path. Reporting the edit as one that would apply, and then failing on
// the first read, is the disagreement a dry run exists to prevent: the preview
// counts the step as satisfied and goes on to describe its dependents running
// against a plan that cannot be applied.
func TestDeputyCommandRefusesMissingTarget(t *testing.T) {
	commands := []struct {
		name string
		file string
		cmd  string
	}{
		{
			name: "action update",
			file: ".github/workflows/ci.yml",
			cmd:  "deputy:action:update .github/workflows/ci.yml actions/checkout v5",
		},
		{
			name: "action pin",
			file: ".github/workflows/ci.yml",
			cmd:  "deputy:action:pin .github/workflows/ci.yml actions/checkout 11bd71901bbe5b1630ceea73d27597364c9af683 v4.2.2",
		},
		{
			name: "dockerfile update",
			file: "Dockerfile",
			cmd:  "deputy:dockerfile:update Dockerfile alpine 3.19",
		},
	}

	// A plan can name a path whose parent directory is gone as easily as one
	// whose file alone is gone, and the two reach the check by different
	// routes through symlink resolution, so both are exercised.
	layouts := []struct {
		name       string
		makeParent bool
	}{
		{name: "target missing", makeParent: true},
		{name: "parent directory missing", makeParent: false},
	}

	for _, tc := range commands {
		t.Run(tc.name, func(t *testing.T) {
			for _, layout := range layouts {
				t.Run(layout.name, func(t *testing.T) {
					dir := t.TempDir()
					if layout.makeParent {
						if err := os.MkdirAll(filepath.Dir(filepath.Join(dir, tc.file)), 0o755); err != nil {
							t.Fatalf("MkdirAll failed: %v", err)
						}
					}

					preflight := PreflightDeputyCommand(dir, tc.cmd)
					if preflight == nil {
						t.Fatalf("PreflightDeputyCommand(%q) accepted a missing target", tc.cmd)
					}
					apply := ApplyDeputyCommand(t.Context(), dir, tc.cmd)
					if apply == nil {
						t.Fatalf("ApplyDeputyCommand(%q) accepted a missing target", tc.cmd)
					}
					if preflight.Error() != apply.Error() {
						t.Errorf("dry run and execution refused differently:\npreflight: %v\napply:     %v", preflight, apply)
					}
					if !errors.Is(preflight, os.ErrNotExist) {
						t.Errorf("refusal %v does not report a missing file", preflight)
					}
					if !strings.Contains(preflight.Error(), tc.file) {
						t.Errorf("refusal %v does not name the target %q", preflight, tc.file)
					}
				})
			}
		})
	}
}
