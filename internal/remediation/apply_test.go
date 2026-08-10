package remediation

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/temporalio/deputy/internal/inventory/plugins/mise/misex"
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

// TestApplyMiseUpdatePrunesStaleLock pins the lockfile half of the mise fix:
// after the config edit, a sibling mise.lock entry still pinning the old
// version must be removed, otherwise the extractor substitutes the locked
// version (falling back to the sole stale entry) and the applied fix keeps
// scanning as vulnerable. Unrelated lock entries survive untouched.
func TestApplyMiseUpdatePrunesStaleLock(t *testing.T) {
	t.Parallel()

	tmpDir := t.TempDir()
	writeFile := func(name, content string) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmpDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	writeFile("mise.toml", `[tools]
go = "1.22.12"
node = "20.11.0"
`)
	writeFile("mise.lock", `[[tools.go]]
version = "1.22.12"
backend = "core:go"

[tools.go.platforms.linux-x64]
checksum = "sha256:oldgo"
size = 123

[[tools.node]]
version = "20.11.0"
backend = "core:node"

[tools.node.platforms.linux-x64]
checksum = "sha256:node"
`)

	if err := ApplyDeputyCommand(tmpDir, "deputy:mise:update mise.toml go 1.24.3 1.22.12"); err != nil {
		t.Fatalf("ApplyDeputyCommand: %v", err)
	}

	lock, err := os.ReadFile(filepath.Join(tmpDir, "mise.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lock), "1.22.12") || strings.Contains(string(lock), "sha256:oldgo") {
		t.Errorf("stale go lock entry survived:\n%s", lock)
	}
	if !strings.Contains(string(lock), "20.11.0") || !strings.Contains(string(lock), "sha256:node") {
		t.Errorf("unrelated node lock entry was damaged:\n%s", lock)
	}

	// The real proof: the extractor must no longer report the old version.
	fsys := fstest.MapFS{}
	for _, name := range []string{"mise.toml", "mise.lock"} {
		data, err := os.ReadFile(filepath.Join(tmpDir, name))
		if err != nil {
			t.Fatal(err)
		}
		fsys[name] = &fstest.MapFile{Data: data}
	}
	f, err := fsys.Open("mise.toml")
	if err != nil {
		t.Fatal(err)
	}
	inv, err := misex.New().Extract(t.Context(), &filesystem.ScanInput{
		Path:   "mise.toml",
		Reader: f,
		FS:     fsys,
	})
	if err != nil {
		t.Fatalf("Extract: %v", err)
	}
	var goVersion string
	for _, pkg := range inv.Packages {
		if pkg.Name == "go" {
			goVersion = pkg.Version
		}
	}
	if goVersion != "1.24.3" {
		t.Errorf("extractor reports go %q after fix, want 1.24.3", goVersion)
	}
}

// TestApplyMiseUpdateLockKeyPrecision pins which lock entries a fix may
// touch. A config can declare a backend-qualified tool and its short name as
// separate tools with independent lock entries, so fixing one must not prune
// the other's integrity metadata. The backend-stripped name is only a
// fallback, used when the lock has no entry under the exact configured key and
// the config does not declare that short name itself.
func TestApplyMiseUpdateLockKeyPrecision(t *testing.T) {
	t.Parallel()

	const npmNodeEntry = `[[tools."npm:node"]]
version = "20.11.0"
backend = "npm:node"

[tools."npm:node"."platforms.linux-x64"]
checksum = "sha256:npmnode"
`
	const coreNodeEntry = `[[tools.node]]
version = "20.11.0"
backend = "core:node"

[tools.node.platforms.linux-x64]
checksum = "sha256:corenode"
`

	tests := []struct {
		name     string
		config   string
		lock     string
		cmd      string
		wantGone []string
		wantKept []string
	}{
		{
			// Both spellings declared and locked: only the edited one is pruned.
			name: "separate declarations keep their own lock entries",
			config: `[tools]
"npm:node" = "20.11.0"
node = "20.11.0"
`,
			lock:     npmNodeEntry + "\n" + coreNodeEntry,
			cmd:      `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			wantGone: []string{"sha256:npmnode"},
			wantKept: []string{"sha256:corenode"},
		},
		{
			// Only the qualified tool is declared and the lock keys it by the
			// short name: the fallback applies, so the stale entry is pruned.
			name: "short-name fallback when exact key absent",
			config: `[tools]
"npm:node" = "20.11.0"
`,
			lock:     coreNodeEntry,
			cmd:      `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			wantGone: []string{"sha256:corenode"},
		},
		{
			// The exact key is locked, so no fallback: an unrelated short-name
			// entry is left alone even though the config does not declare it.
			name: "no fallback when exact key is locked",
			config: `[tools]
"npm:node" = "20.11.0"
`,
			lock:     npmNodeEntry + "\n" + coreNodeEntry,
			cmd:      `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			wantGone: []string{"sha256:npmnode"},
			wantKept: []string{"sha256:corenode"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			for name, content := range map[string]string{"mise.toml": tt.config, "mise.lock": tt.lock} {
				if err := os.WriteFile(filepath.Join(dir, name), []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			if err := ApplyDeputyCommand(dir, tt.cmd); err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}
			lock, err := os.ReadFile(filepath.Join(dir, "mise.lock"))
			if err != nil {
				t.Fatal(err)
			}
			for _, marker := range tt.wantGone {
				if strings.Contains(string(lock), marker) {
					t.Errorf("expected %q to be pruned:\n%s", marker, lock)
				}
			}
			for _, marker := range tt.wantKept {
				if !strings.Contains(string(lock), marker) {
					t.Errorf("expected %q to survive:\n%s", marker, lock)
				}
			}
		})
	}
}

// TestApplyMiseUpdateRetryAfterLockFailure pins recovery from a partial
// apply. The config is written before the lockfile is pruned, so a lockfile
// failure leaves the config edited and the lock stale; re-running the same
// command must recognize the config edit as already applied and finish the
// pruning rather than failing with "could not rewrite".
func TestApplyMiseUpdateRetryAfterLockFailure(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	configPath := filepath.Join(dir, "mise.toml")
	lockPath := filepath.Join(dir, "mise.lock")
	if err := os.WriteFile(configPath, []byte("[tools]\ngo = \"1.22.12\"\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(lockPath, []byte("[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n"), 0o444); err != nil {
		t.Fatal(err)
	}

	const cmd = "deputy:mise:update mise.toml go 1.24.3 1.22.12"
	if err := ApplyDeputyCommand(dir, cmd); err == nil {
		t.Fatal("expected the read-only lockfile to fail the apply")
	}
	config, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(config), "1.24.3") {
		t.Fatalf("config should already carry the fix:\n%s", config)
	}

	// The operator fixes whatever blocked the lockfile write and retries.
	if err := os.Chmod(lockPath, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := ApplyDeputyCommand(dir, cmd); err != nil {
		t.Fatalf("retry after partial failure: %v", err)
	}
	lock, err := os.ReadFile(lockPath)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(lock), "1.22.12") {
		t.Errorf("retry did not prune the stale lock entry:\n%s", lock)
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
			// Multiline arrays are a first-class layout for multi-version
			// pins; the vulnerable element is replaced in place.
			name: "mise update multiline array element",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				"mise.toml": `[tools]
go = [
  "1.22.12",
  "1.23.8",
]
node = "20.11.1"
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = [
  "1.24.3",
  "1.23.8",
]
node = "20.11.1"
`,
			},
			wantErr: false,
		},
		{
			// The corruption regression: an unmatched multiline array must
			// fail closed with the file byte-identical, never a half-replaced
			// bracket.
			name: "mise update multiline array unmatched fails byte-identical",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.21.0",
			setup: map[string]string{
				"mise.toml": `[tools]
go = [
  "1.22.12",
  "1.23.8",
]
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = [
  "1.22.12",
  "1.23.8",
]
`,
			},
			wantErr: true,
		},
		{
			// Several vulnerable versions in one array: the command carries
			// every current and each matching element is replaced.
			name: "mise update replaces every vulnerable array element",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12 1.23.8",
			setup: map[string]string{
				"mise.toml": `[tools]
go = ["1.22.12", "1.23.8", "1.24.0"]
`,
			},
			want: map[string]string{
				"mise.toml": `[tools]
go = ["1.24.3", "1.24.3", "1.24.0"]
`,
			},
			wantErr: false,
		},
		{
			// mise's parser accepts root-level dotted keys; the rewriter must
			// handle what inventory can emit a fix for.
			name: "mise update root dotted key",
			cmd:  "deputy:mise:update mise.toml go 1.24.3 1.22.12",
			setup: map[string]string{
				"mise.toml": `tools.go = "1.22.12"
`,
			},
			want: map[string]string{
				"mise.toml": `tools.go = "1.24.3"
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
