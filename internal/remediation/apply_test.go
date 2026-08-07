package remediation

import (
	"os"
	"path/filepath"
	"testing"
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

			err := applyActionUpdate(filePath, tt.actionRef, tt.newVersion)
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

			err := applyDockerfileUpdate(filePath, tt.image, tt.newVersion)
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
			name: "mise update scalar preserves comments and layout",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				"mise.toml": `[tools]
go = "1.22.12" # pinned toolchain
node = "20.11.1"
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = "1.24.3" # pinned toolchain
node = "20.11.1"
`,
			},
			wantErr: false,
		},
		{
			// Pins the array contract: only the vulnerable element is replaced
			// and the other pinned versions survive. `mise use` would collapse
			// the whole array to a scalar, which is why remediation must not
			// shell out to it.
			name: "mise update replaces only the vulnerable array element",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				"mise.toml": `[tools]
go = ["1.22.12", "1.23.8"]
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = ["1.24.3", "1.23.8"]
`,
			},
			wantErr: false,
		},
		{
			// Fail closed: a multi-version array with no known current version
			// must not be rewritten at all.
			name: "mise update multi-version array without current version fails",
			cmd:  "deputy:mise:update mise.toml go 1.24.3",
			setup: map[string]string{
				"mise.toml": `[tools]
go = ["1.22.12", "1.23.8"]
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = ["1.22.12", "1.23.8"]
`,
			},
			wantErr: true,
		},
		{
			name: "mise update backend-prefixed tool in hidden manifest",
			cmd:  "deputy:mise:update .mise.toml npm:lodash 4.17.21 4.17.20",
			setup: map[string]string{
				".mise.toml": `[tools]
"npm:lodash" = "4.17.20"
`,
			},
			want: map[string]string{
				".mise.toml": `[tools]
"npm:lodash" = "4.17.21"
`,
			},
			wantErr: false,
		},
		{
			name: "mise update targets nested config path",
			cmd:  "deputy:mise:update .config/mise/config.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				".config/mise/config.toml": `[tools]
go = "1.22.12"
`,
			},
			want: map[string]string{
				".config/mise/config.toml": `[tools]
go = "1.24.3"
`,
			},
			wantErr: false,
		},
		{
			name: "mise update quoted path with spaces",
			cmd:  `deputy:mise:update "tool config/mise.toml" go 1.24.3 1.22.12`,
			setup: map[string]string{
				"tool config/mise.toml": `[tools]
go = "1.22.12"
`,
			},
			want: map[string]string{
				"tool config/mise.toml": `[tools]
go = "1.24.3"
`,
			},
			wantErr: false,
		},
		{
			name: "mise update tool not declared fails",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				"mise.toml": `[tools]
node = "20.11.1"
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
node = "20.11.1"
`,
			},
			wantErr: true,
		},
		{
			name:    "invalid mise command (missing args)",
			cmd:     "deputy:mise:update mise.toml go",
			wantErr: true,
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

			err := ApplyDeputyCommand(tmpDir, tt.cmd)
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
