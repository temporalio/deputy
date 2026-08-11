package remediation

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"sync"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/temporalio/deputy/internal/inventory/plugins/mise/misex"
	"github.com/temporalio/deputy/internal/mise"
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

// TestApplyMiseUpdatePrunesLockForLayouts pins lock discovery across the
// manifest layouts mise supports. The lockfile is not simply the manifest with
// a .lock suffix: mise reads mise.lock for a .mise.toml config and
// <dir>/mise.lock for a .config/mise/config.toml, so deriving the name from
// the basename pruned a file mise ignores and left the real lock pinning the
// vulnerable version. Each case asserts the stale entry is gone and that the
// extractor, which substitutes the locked version, now reports the fixed one.
func TestApplyMiseUpdatePrunesLockForLayouts(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		configPath string
		lockPath   string
	}{
		{name: "flat manifest", configPath: "mise.toml", lockPath: "mise.lock"},
		{name: "hidden manifest", configPath: ".mise.toml", lockPath: "mise.lock"},
		{name: "environment manifest", configPath: "mise.production.toml", lockPath: "mise.production.lock"},
		{name: "nested config", configPath: ".config/mise/config.toml", lockPath: ".config/mise/mise.lock"},
		{name: "dotted nested config", configPath: ".mise/config.toml", lockPath: ".mise/mise.lock"},
		{name: "nested environment config", configPath: ".config/mise/config.production.toml", lockPath: ".config/mise/mise.production.lock"},
		{name: "dotted nested environment config", configPath: ".mise/config.staging.toml", lockPath: ".mise/mise.staging.lock"},
		{name: "conf.d drop-in", configPath: ".config/mise/conf.d/tools.toml", lockPath: ".config/mise/mise.lock"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(rel, content string) {
				t.Helper()
				full := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			write(tt.configPath, "[tools]\ngo = \"1.22.12\"\n")
			write(tt.lockPath, "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n")

			cmd := "deputy:mise:update " + tt.configPath + " go 1.24.3 1.22.12"
			if err := ApplyDeputyCommand(dir, cmd); err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}

			lock, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tt.lockPath)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(lock), "1.22.12") {
				t.Errorf("stale entry survived in %s:\n%s", tt.lockPath, lock)
			}

			// The extractor prefers the locked version, so it is the honest
			// check that the fix actually took effect.
			fsys := fstest.MapFS{}
			for _, rel := range []string{tt.configPath, tt.lockPath} {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
				if err != nil {
					t.Fatal(err)
				}
				fsys[rel] = &fstest.MapFile{Data: data}
			}
			f, err := fsys.Open(tt.configPath)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := misex.New().Extract(t.Context(), &filesystem.ScanInput{
				Path:   tt.configPath,
				Reader: f,
				FS:     fsys,
			})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			var got string
			for _, pkg := range inv.Packages {
				if pkg.Name == "go" {
					got = pkg.Version
				}
			}
			if got != "1.24.3" {
				t.Errorf("extractor reports go %q after fix, want 1.24.3", got)
			}
		})
	}
}

// TestApplyMiseUpdateSymlinkedManifest pins which manifest path decides the
// lockfile. A detected manifest that is an in-repository symlink has its own
// sibling lockfile, and that is the one mise (and Deputy's own inventory)
// reads, so following the link to the target's directory would edit the config
// while leaving the lock that is actually in effect still pinning the
// vulnerable version. The symlink itself must survive the edit, and a link
// that leaves the repository must still be refused.
func TestApplyMiseUpdateSymlinkedManifest(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// link is the detected manifest; target is where it points, relative
		// to the repository unless escapes is set.
		link      string
		target    string
		lockPath  string
		staleLock string
		escapes   bool
	}{
		{
			name: "root symlink to a nested config",
			link: "mise.toml", target: "configs/shared.toml",
			lockPath: "mise.lock", staleLock: "configs/shared.lock",
		},
		{
			name: "nested symlink to a root config",
			link: "envs/mise.toml", target: "shared.toml",
			lockPath: "envs/mise.lock", staleLock: "mise.lock",
		},
		{
			name: "symlink escaping the repository is refused",
			link: "mise.toml", escapes: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(base, rel, content string) string {
				t.Helper()
				full := filepath.Join(base, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				return full
			}
			const config = "[tools]\ngo = \"1.22.12\"\n"
			const lock = "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n"

			linkFull := filepath.Join(dir, filepath.FromSlash(tt.link))
			if err := os.MkdirAll(filepath.Dir(linkFull), 0o755); err != nil {
				t.Fatal(err)
			}

			if tt.escapes {
				outside := write(t.TempDir(), "victim.toml", config)
				if err := os.Symlink(outside, linkFull); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
				err := ApplyDeputyCommand(dir, "deputy:mise:update "+tt.link+" go 1.24.3 1.22.12")
				if err == nil {
					t.Fatal("expected an error for a manifest symlinked outside the repository")
				}
				got, readErr := os.ReadFile(outside)
				if readErr != nil {
					t.Fatal(readErr)
				}
				if string(got) != config {
					t.Errorf("wrote outside the repository: %q", got)
				}
				return
			}

			targetFull := write(dir, tt.target, config)
			write(dir, tt.lockPath, lock)
			write(dir, tt.staleLock, lock)
			linkTo, err := filepath.Rel(filepath.Dir(linkFull), targetFull)
			if err != nil {
				t.Fatal(err)
			}
			if err := os.Symlink(linkTo, linkFull); err != nil {
				t.Skipf("symlinks unavailable: %v", err)
			}

			if err := ApplyDeputyCommand(dir, "deputy:mise:update "+tt.link+" go 1.24.3 1.22.12"); err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}

			if got, err := os.ReadFile(targetFull); err != nil {
				t.Fatal(err)
			} else if !strings.Contains(string(got), "1.24.3") {
				t.Errorf("config not updated through the symlink:\n%s", got)
			}
			fi, err := os.Lstat(linkFull)
			if err != nil {
				t.Fatal(err)
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("%s is no longer a symlink after the edit", tt.link)
			}
			sibling, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tt.lockPath)))
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(sibling), "1.22.12") {
				t.Errorf("stale entry survived in the detected manifest's lock %s:\n%s", tt.lockPath, sibling)
			}
			other, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(tt.staleLock)))
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(other), "1.22.12") {
				t.Errorf("pruned the link target's lock %s, which is not in effect:\n%s", tt.staleLock, other)
			}
		})
	}
}

// TestResolveLinkTarget covers the resolution rules directly, including the
// refusals an end-to-end apply reaches only after some earlier read has
// already failed on the same link.
func TestResolveLinkTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name string
		// links map a repository-relative path to the target text stored in it.
		links map[string]string
		// outsideLink, when set, is a link to a path outside the repository.
		outsideLink string
		in          string
		want        string
		wantErr     bool
	}{
		{name: "a regular file resolves to itself", in: "mise.lock", want: "mise.lock"},
		{name: "a missing path resolves to itself", in: "absent.lock", want: "absent.lock"},
		{
			name:  "a link resolves to its target",
			links: map[string]string{"link.lock": "shared/mise.lock"},
			in:    "link.lock", want: "shared/mise.lock",
		},
		{
			name: "a chain resolves to its final target",
			links: map[string]string{
				"link.lock":     "hop/next.lock",
				"hop/next.lock": "../shared/mise.lock",
			},
			in: "link.lock", want: "shared/mise.lock",
		},
		{
			name:  "a link out of the repository is refused",
			links: map[string]string{"link.lock": "../escape.lock"},
			in:    "link.lock", wantErr: true,
		},
		{
			name:  "a nested link climbing past the root is refused",
			links: map[string]string{"hop/next.lock": "../../outside/mise.lock"},
			in:    "hop/next.lock", wantErr: true,
		},
		{
			name: "an absolute link is refused", outsideLink: "link.lock",
			in: "link.lock", wantErr: true,
		},
		{
			name: "a cycle is refused",
			links: map[string]string{
				"a.lock": "b.lock",
				"b.lock": "a.lock",
			},
			in: "a.lock", wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.MkdirAll(filepath.Join(dir, "shared"), 0o755); err != nil {
				t.Fatal(err)
			}
			for _, rel := range []string{"mise.lock", "shared/mise.lock"} {
				if err := os.WriteFile(filepath.Join(dir, filepath.FromSlash(rel)), []byte("x"), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for from, to := range tt.links {
				full := filepath.Join(dir, filepath.FromSlash(from))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.FromSlash(to), full); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			if tt.outsideLink != "" {
				outside := filepath.Join(t.TempDir(), "mise.lock")
				if err := os.Symlink(outside, filepath.Join(dir, filepath.FromSlash(tt.outsideLink))); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}

			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			got, err := resolveLinkTarget(root, tt.in)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("resolveLinkTarget(%q) = %q, want an error", tt.in, got)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveLinkTarget(%q): %v", tt.in, err)
			}
			if got != tt.want {
				t.Errorf("resolveLinkTarget(%q) = %q, want %q", tt.in, got, tt.want)
			}
		})
	}
}

// TestApplyMiseUpdateSymlinkedLock pins that pruning a lockfile which is
// itself an in-repository symlink updates what the link points at instead of
// replacing the link with a regular file. Severing the link would leave the
// shared target stale, so every other config pointing at it keeps resolving
// the vulnerable version, and the repository quietly loses a deliberate layout
// choice. A link that leaves the repository must still be refused.
func TestApplyMiseUpdateSymlinkedLock(t *testing.T) {
	t.Parallel()

	const config = "[tools]\ngo = \"1.22.12\"\n"
	const lock = "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n"

	tests := []struct {
		name string
		// links are symlinks to create, each as a repository-relative path and
		// the target text to store in it. target is the regular lockfile the
		// chain ends at, which is the file that must end up pruned; it is
		// empty when the chain is not expected to resolve.
		links   map[string]string
		target  string
		wantErr bool
		escapes bool
	}{
		{
			name:   "lock symlinked to a shared target",
			links:  map[string]string{"mise.lock": "shared/mise.lock"},
			target: "shared/mise.lock",
		},
		{
			name: "lock symlinked through a chain",
			links: map[string]string{
				"mise.lock":      "link/mise.lock",
				"link/mise.lock": "../shared/mise.lock",
			},
			target: "shared/mise.lock",
		},
		{
			name: "a cycle of lock symlinks is refused",
			links: map[string]string{
				"mise.lock":  "other.lock",
				"other.lock": "mise.lock",
			},
			wantErr: true,
		},
		{name: "lock symlinked outside the repository is refused", escapes: true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(base, rel, content string) string {
				t.Helper()
				full := filepath.Join(base, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
				return full
			}
			link := func(from, to string) {
				t.Helper()
				if err := os.MkdirAll(filepath.Dir(from), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.FromSlash(to), from); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}
			write(dir, "mise.toml", config)
			lockFull := filepath.Join(dir, "mise.lock")

			if tt.escapes {
				outside := write(t.TempDir(), "shared.lock", lock)
				link(lockFull, outside)
				if err := ApplyDeputyCommand(dir, "deputy:mise:update mise.toml go 1.24.3 1.22.12"); err == nil {
					t.Fatal("expected an error for a lockfile symlinked outside the repository")
				}
				got, err := os.ReadFile(outside)
				if err != nil {
					t.Fatal(err)
				}
				if string(got) != lock {
					t.Errorf("wrote outside the repository: %q", got)
				}
				return
			}

			var targetFull string
			if tt.target != "" {
				targetFull = write(dir, tt.target, lock)
			}
			for from, to := range tt.links {
				link(filepath.Join(dir, filepath.FromSlash(from)), to)
			}

			err := ApplyDeputyCommand(dir, "deputy:mise:update mise.toml go 1.24.3 1.22.12")
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected an error for a lockfile symlink that does not resolve")
				}
				return
			}
			if err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}

			fi, lstatErr := os.Lstat(lockFull)
			if lstatErr != nil {
				t.Fatal(lstatErr)
			}
			if fi.Mode()&os.ModeSymlink == 0 {
				t.Errorf("mise.lock is no longer a symlink after the fix")
			}
			got, err := os.ReadFile(targetFull)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(got), "1.22.12") {
				t.Errorf("stale entry survived in the link target %s:\n%s", tt.target, got)
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
// the other's integrity metadata. The backend-stripped name is pruned too when
// no other declaration in the config could own it, whether or not the exact
// configured key is also locked.
//
// Every case additionally checks the outcome the pruning exists for: the
// edited tool must not resolve back to a locked entry at the version the fix
// removed. That is what a following scan does, and a fix that leaves such an
// entry behind reports success while the vulnerability stands.
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
		tool     string
		fixed    string
		stale    string
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
			lock: npmNodeEntry + "\n" + coreNodeEntry,
			cmd:  `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			tool: "npm:node", fixed: "20.12.0", stale: "20.11.0",
			wantGone: []string{"sha256:npmnode"},
			wantKept: []string{"sha256:corenode"},
		},
		{
			// Only the qualified tool is declared and the lock keys it by the
			// short name: the short name is uncontested, so the stale entry is
			// pruned.
			name: "short name pruned when exact key absent",
			config: `[tools]
"npm:node" = "20.11.0"
`,
			lock: coreNodeEntry,
			cmd:  `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			tool: "npm:node", fixed: "20.12.0", stale: "20.11.0",
			wantGone: []string{"sha256:corenode"},
		},
		{
			// Both spellings locked but only one declared: an entry under the
			// exact key does not make the legacy short-name entry someone
			// else's. Nothing else claims the short name, so lock resolution
			// would fall back to it once the exact entry is gone and hand the
			// fixed tool its old version back; both spellings go.
			name: "uncontested short name pruned even when the exact key is locked",
			config: `[tools]
"npm:node" = "20.11.0"
`,
			lock: npmNodeEntry + "\n" + coreNodeEntry,
			cmd:  `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			tool: "npm:node", fixed: "20.12.0", stale: "20.11.0",
			wantGone: []string{"sha256:npmnode", "sha256:corenode"},
		},
		{
			// Two qualified declarations strip to the same short name, so no
			// bare key appears in the config, yet the legacy short-name lock
			// entry could belong to either. Claimants must be matched on the
			// stripped name, not on a literal bare key, or fixing one tool
			// discards the other's checksums.
			name: "short name contested by another qualified declaration",
			config: `[tools]
"npm:node" = "20.11.0"
"ubi:node" = "20.11.0"
`,
			lock: coreNodeEntry,
			cmd:  `deputy:mise:update mise.toml "npm:node" 20.12.0 20.11.0`,
			tool: "npm:node", fixed: "20.12.0", stale: "20.11.0",
			wantKept: []string{"sha256:corenode"},
		},
		{
			// Tool options do not create a distinct claimant name, and the
			// edited declaration must not count as contesting itself.
			name: "option-bearing key still gets the fallback",
			config: `[tools]
"npm:node[exe=node]" = "20.11.0"
`,
			lock: coreNodeEntry,
			cmd:  `deputy:mise:update mise.toml "npm:node[exe=node]" 20.12.0 20.11.0`,
			tool: "npm:node[exe=node]", fixed: "20.12.0", stale: "20.11.0",
			wantGone: []string{"sha256:corenode"},
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
			if got := lockedVersionAfterFix(t, dir, tt.tool, tt.fixed); got == tt.stale {
				t.Errorf("edited tool %q resolves back to the pruned version %s:\n%s", tt.tool, tt.stale, lock)
			}
		})
	}
}

// lockedVersionAfterFix resolves the edited tool against the pruned lockfile
// the way a following scan does, returning the version lock resolution would
// substitute for the declaration ("" when it substitutes nothing). It reads
// both files back from disk and goes through mise.Lockfile.Lookup rather than
// re-deriving the answer, so the test measures what inventory will actually
// see rather than what pruning intended.
func lockedVersionAfterFix(t *testing.T, dir, tool, version string) string {
	t.Helper()

	cfgData, err := os.ReadFile(filepath.Join(dir, "mise.toml"))
	if err != nil {
		t.Fatal(err)
	}
	lockData, err := os.ReadFile(filepath.Join(dir, "mise.lock"))
	if err != nil {
		t.Fatal(err)
	}
	cfg, err := mise.Parse("mise.toml", cfgData)
	if err != nil {
		t.Fatalf("parse config: %v", err)
	}
	lf, err := mise.ParseLock("mise.lock", lockData)
	if err != nil {
		t.Fatalf("parse lock: %v", err)
	}
	// The same claim count inventory uses, over every config sharing the
	// lockfile, so the helper cannot pass a fix that the real extractor would
	// still see as vulnerable.
	claims, err := mise.LockClaims(os.DirFS(dir), "mise.toml")
	if err != nil {
		t.Fatalf("lock claims: %v", err)
	}
	for _, spec := range cfg.Tools {
		if spec.Key != tool {
			continue
		}
		if locked := lf.Lookup(spec, version, claims); locked != nil {
			return locked.Version
		}
		return ""
	}
	t.Fatalf("tool %q not declared in the config after the fix:\n%s", tool, cfgData)
	return ""
}

// TestApplyMiseUpdateMatchesVPrefixedCurrentVersion pins the apply against the
// vocabulary the plan is actually written in. Deputy reports the Go runtime
// with the module convention, so the emitted command carries the current
// version as "v1.22.12", while the mise config and its lockfile write
// "1.22.12". Comparing those byte-for-byte breaks the command Deputy itself
// emitted: an array declaration is refused outright with "could not rewrite",
// and a scalar one is rewritten while the stale lock entry survives, which is
// the worse half. Lock resolution substitutes the locked version for the
// declared one, so that apply reports success and the very next scan still
// reports the version the fix was supposed to remove.
func TestApplyMiseUpdateMatchesVPrefixedCurrentVersion(t *testing.T) {
	t.Parallel()

	const lockBody = "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n"

	tests := []struct {
		name       string
		config     string
		cmd        string
		wantConfig string
	}{
		{
			name:       "scalar declaration",
			config:     "[tools]\ngo = \"1.22.12\"\n",
			cmd:        "deputy:mise:update mise.toml go 1.25.12 v1.22.12",
			wantConfig: "[tools]\ngo = \"1.25.12\"\n",
		},
		{
			name:       "array declaration",
			config:     "[tools]\ngo = [\"1.22.12\", \"1.21.0\"]\n",
			cmd:        "deputy:mise:update mise.toml go 1.25.12 v1.22.12",
			wantConfig: "[tools]\ngo = [\"1.25.12\", \"1.21.0\"]\n",
		},
		{
			// The mirror image: a config that spells the version with the
			// leading "v" and a plan that does not.
			name:       "v-prefixed declaration and a bare current version",
			config:     "[tools]\ngo = \"v1.22.12\"\n",
			cmd:        "deputy:mise:update mise.toml go 1.25.12 1.22.12",
			wantConfig: "[tools]\ngo = \"1.25.12\"\n",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			configPath := filepath.Join(dir, "mise.toml")
			lockPath := filepath.Join(dir, "mise.lock")
			if err := os.WriteFile(configPath, []byte(tt.config), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, []byte(lockBody), 0o644); err != nil {
				t.Fatal(err)
			}

			if err := ApplyDeputyCommand(dir, tt.cmd); err != nil {
				t.Fatalf("apply: %v", err)
			}

			config, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if string(config) != tt.wantConfig {
				t.Errorf("config mismatch:\n--- got ---\n%s\n--- want ---\n%s", config, tt.wantConfig)
			}
			// The stale lock entry has to go, or the fix does not take: the
			// extractor substitutes the locked version for the declared one.
			lock, err := os.ReadFile(lockPath)
			if err != nil {
				t.Fatal(err)
			}
			if strings.Contains(string(lock), "1.22.12") {
				t.Errorf("stale lock entry survived the apply:\n%s", lock)
			}
		})
	}
}

// TestApplyMiseUpdateRetryAfterLockFailure pins recovery from a partial
// apply. The config is written before the lockfile is pruned, so a lockfile
// failure leaves the config edited and the lock stale; re-running the same
// command must recognize the config edit as already applied and finish the
// pruning rather than failing with "could not rewrite".
//
// What blocks the lockfile is a parameter, not the point. The first fault is
// deterministic and holds for any user, so the recovery path keeps its
// coverage where the suite runs as root; the second is the read-only directory
// an operator is likeliest to actually hit, which only blocks anyone whose
// privileges do not bypass mode bits.
func TestApplyMiseUpdateRetryAfterLockFailure(t *testing.T) {
	t.Parallel()

	const lockBody = "[[tools.go]]\nversion = \"1.22.12\"\nbackend = \"core:go\"\n"

	tests := []struct {
		name string
		// block makes the lockfile replacement fail; repair undoes it, as an
		// operator would before retrying.
		block  func(t *testing.T, dir, lockPath string)
		repair func(t *testing.T, dir, lockPath string)
	}{
		{
			// The lockfile resolves out of the repository, which os.Root
			// refuses to follow. Reads through the repository root fail while
			// the config, an ordinary file, is still rewritten in place.
			name: "lockfile escaping the repository",
			block: func(t *testing.T, dir, lockPath string) {
				t.Helper()
				outside := filepath.Join(t.TempDir(), "shared.lock")
				if err := os.WriteFile(outside, []byte(lockBody), 0o644); err != nil {
					t.Fatal(err)
				}
				if err := os.Remove(lockPath); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(outside, lockPath); err != nil {
					t.Fatal(err)
				}
			},
			repair: func(t *testing.T, dir, lockPath string) {
				t.Helper()
				if err := os.Remove(lockPath); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(lockPath, []byte(lockBody), 0o644); err != nil {
					t.Fatal(err)
				}
			},
		},
		{
			// A read-only directory blocks the lockfile replacement (its
			// temporary sibling cannot be created) while still allowing the
			// in-place config rewrite.
			name: "read-only directory",
			block: func(t *testing.T, dir, lockPath string) {
				t.Helper()
				makeDirUnwritable(t, dir)
			},
			repair: func(t *testing.T, dir, lockPath string) {
				t.Helper()
				if err := os.Chmod(dir, 0o755); err != nil {
					t.Fatal(err)
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			configPath := filepath.Join(dir, "mise.toml")
			lockPath := filepath.Join(dir, "mise.lock")
			if err := os.WriteFile(configPath, []byte("[tools]\ngo = \"1.22.12\"\n"), 0o644); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(lockPath, []byte(lockBody), 0o644); err != nil {
				t.Fatal(err)
			}
			tt.block(t, dir, lockPath)

			const cmd = "deputy:mise:update mise.toml go 1.24.3 1.22.12"
			if err := ApplyDeputyCommand(dir, cmd); err == nil {
				t.Fatal("expected the blocked lockfile to fail the apply")
			}
			config, err := os.ReadFile(configPath)
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(string(config), "1.24.3") {
				t.Fatalf("config should already carry the fix:\n%s", config)
			}
			// The failure must leave the lockfile exactly as it was, never
			// truncated.
			if got, err := os.ReadFile(lockPath); err != nil {
				t.Fatal(err)
			} else if string(got) != lockBody {
				t.Errorf("failed apply damaged the lockfile:\n--- got ---\n%s\n--- want ---\n%s", got, lockBody)
			}

			// The operator fixes whatever blocked the lockfile write and
			// retries.
			tt.repair(t, dir, lockPath)
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
		})
	}
}

// makeDirUnwritable strips the write bit from dir for the rest of the test,
// restoring it afterwards, and skips the test when the caller can create files
// there anyway.
//
// Mode bits do not bind a process holding CAP_DAC_OVERRIDE, which is every
// process in the root-by-default containers that CI and isolated agents run
// in. A test that chmods a directory to 0555 and then asserts a write failed
// is asserting something untrue there, and fails for a reason that has nothing
// to do with the code under test. The probe measures whether the bits bind on
// this host instead of guessing from the UID, so a capability set that grants
// the bypass some other way is caught too.
func makeDirUnwritable(t *testing.T, dir string) {
	t.Helper()

	if err := os.Chmod(dir, 0o555); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })

	probe := filepath.Join(dir, ".deputy-writability-probe")
	f, err := os.OpenFile(probe, os.O_WRONLY|os.O_CREATE|os.O_EXCL, 0o600)
	if err != nil {
		return // the bits bind: the directory really is unwritable
	}
	_ = f.Close()
	_ = os.Remove(probe)
	t.Skip("this process writes to a 0555 directory, so mode bits cannot block the write under test")
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

// TestReplaceFileAtomically pins the durability contract for lockfile writes:
// the file is either its old content or its new content, a failure leaves the
// original intact rather than a truncated remnant, no temporary file is left
// behind, and an existing temporary beside the target neither blocks the write
// nor gets destroyed, since it may be a concurrent apply's in-flight file.
func TestReplaceFileAtomically(t *testing.T) {
	t.Parallel()

	const original = "[[tools.go]]\nversion = \"1.22.12\"\n"
	const replacement = "[[tools.node]]\nversion = \"20.11.0\"\n"
	// Deliberately the fixed name an earlier implementation cleared before
	// writing, so reintroducing clear-by-known-name goes red here.
	const inFlight = ".mise.lock.deputy-tmp"

	tests := []struct {
		name      string
		setup     func(t *testing.T, dir string)
		wantErr   bool
		wantAfter string
		// wantIntact names a sibling file that must still hold its original
		// bytes after the call.
		wantIntact string
	}{
		{
			name:      "replaces content",
			wantAfter: replacement,
		},
		{
			name: "another apply's temporary is neither reused nor removed",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				if err := os.WriteFile(filepath.Join(dir, inFlight), []byte("in flight"), 0o644); err != nil {
					t.Fatal(err)
				}
			},
			wantAfter:  replacement,
			wantIntact: inFlight,
		},
		{
			name: "unwritable directory leaves the original intact",
			setup: func(t *testing.T, dir string) {
				t.Helper()
				makeDirUnwritable(t, dir)
			},
			wantErr:   true,
			wantAfter: original,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "mise.lock"), []byte(original), 0o644); err != nil {
				t.Fatal(err)
			}
			if tt.setup != nil {
				tt.setup(t, dir)
			}
			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			err = replaceFileAtomically(root, "mise.lock", []byte(replacement), 0o644)
			if tt.wantErr && err == nil {
				t.Fatal("expected an error")
			}
			if !tt.wantErr && err != nil {
				t.Fatalf("replaceFileAtomically: %v", err)
			}
			got, err := os.ReadFile(filepath.Join(dir, "mise.lock"))
			if err != nil {
				t.Fatal(err)
			}
			if string(got) != tt.wantAfter {
				t.Errorf("content = %q, want %q", got, tt.wantAfter)
			}
			if tt.wantIntact != "" {
				kept, err := os.ReadFile(filepath.Join(dir, tt.wantIntact))
				if err != nil {
					t.Fatalf("%s was removed: %v", tt.wantIntact, err)
				}
				if string(kept) != "in flight" {
					t.Errorf("%s was overwritten: %q", tt.wantIntact, kept)
				}
			}
			// Any temporary this call created must be gone, whatever it was
			// named; only a pre-existing one may remain.
			entries, err := os.ReadDir(dir)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range entries {
				name := entry.Name()
				if strings.HasPrefix(name, ".mise.lock.deputy-") && name != tt.wantIntact {
					t.Errorf("temporary file left behind: %s", name)
				}
			}
		})
	}
}

// TestReplaceFileAtomicallyPreservesMode pins that publishing a replacement
// keeps the target's permissions. The temporary is created with the umask
// applied, so a group-writable lockfile in a shared workspace would come back
// read-only for the group and the next `mise lock` there would fail. The mode
// has to be set on the temporary rather than merely requested at creation.
func TestReplaceFileAtomicallyPreservesMode(t *testing.T) {
	t.Parallel()

	for _, perm := range []os.FileMode{0o600, 0o644, 0o664, 0o666} {
		t.Run(perm.String(), func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			lock := filepath.Join(dir, "mise.lock")
			if err := os.WriteFile(lock, []byte("[[tools.go]]\nversion = \"1.22.12\"\n"), perm); err != nil {
				t.Fatal(err)
			}
			// os.WriteFile is subject to the umask, which is the very thing
			// under test, so chmod the fixture to the exact mode and confirm
			// it took before asserting on what replacement does to it.
			if err := os.Chmod(lock, perm); err != nil {
				t.Fatal(err)
			}
			before, err := os.Stat(lock)
			if err != nil {
				t.Fatal(err)
			}
			if before.Mode().Perm() != perm {
				t.Skipf("umask reduced the fixture to %v, cannot test %v", before.Mode().Perm(), perm)
			}

			root, err := os.OpenRoot(dir)
			if err != nil {
				t.Fatal(err)
			}
			defer root.Close()

			if err := replaceFileAtomically(root, "mise.lock", []byte("[[tools.go]]\n"), perm); err != nil {
				t.Fatalf("replaceFileAtomically: %v", err)
			}
			after, err := os.Stat(lock)
			if err != nil {
				t.Fatal(err)
			}
			if got := after.Mode().Perm(); got != perm {
				t.Errorf("mode after replacement = %v, want %v", got, perm)
			}
		})
	}
}

// TestReplaceFileAtomicallyConcurrent pins that two applies pruning the same
// lockfile cannot corrupt each other. With a shared temporary name one call
// unlinks the other's open file, refills the name, and has the refill renamed
// into place mid-write; every call must therefore end with the target holding
// exactly one caller's complete content and no temporary left over.
func TestReplaceFileAtomicallyConcurrent(t *testing.T) {
	t.Parallel()

	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mise.lock"), []byte("original"), 0o644); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	const writers = 8
	contents := make([]string, writers)
	for i := range contents {
		contents[i] = strings.Repeat(fmt.Sprintf("writer-%d\n", i), 4096)
	}
	var wg sync.WaitGroup
	errs := make([]error, writers)
	for i := range writers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			errs[i] = replaceFileAtomically(root, "mise.lock", []byte(contents[i]), 0o644)
		}()
	}
	wg.Wait()

	for i, err := range errs {
		if err != nil {
			t.Errorf("writer %d: %v", i, err)
		}
	}
	got, err := os.ReadFile(filepath.Join(dir, "mise.lock"))
	if err != nil {
		t.Fatal(err)
	}
	if !slices.Contains(contents, string(got)) {
		t.Errorf("lockfile holds no writer's complete content (%d bytes)", len(got))
	}
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, entry := range entries {
		if strings.HasPrefix(entry.Name(), ".mise.lock.deputy-") {
			t.Errorf("temporary file left behind: %s", entry.Name())
		}
	}
}

// TestApplyMiseUpdateSharedConfdLock pins ownership of a lock entry shared by
// several config fragments. A mise directory's conf.d drop-ins all write to
// one mise.lock (mise 2026.7.3 names ".config/mise/mise.lock" as the lock
// target for a tool declared only in a drop-in), so a legacy short-name entry
// in it may belong to a fragment this fix never opened. Counting claimants in
// the edited fragment alone reads such an entry as unowned and deletes another
// declaration's integrity metadata.
//
// Pruning and enrichment are checked together, because they have to give the
// same answer: an entry left in place as contested must also be refused by the
// extractor, or the fixed tool comes back reporting its old version.
func TestApplyMiseUpdateSharedConfdLock(t *testing.T) {
	t.Parallel()

	const legacyLock = `[[tools.foo]]
version = "1.0.0"
backend = "ubi:foo"

[tools.foo.platforms.linux-x64]
checksum = "sha256:legacyfoo"
`
	tests := []struct {
		name     string
		files    map[string]string
		wantGone []string
		wantKept []string
	}{
		{
			// b.toml shares the lockfile and strips to the same short name, so
			// the legacy entry may be its own.
			name: "a sibling drop-in contests the short name",
			files: map[string]string{
				".config/mise/conf.d/a.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				".config/mise/conf.d/b.toml": "[tools]\n\"ubi:foo\" = \"1.0.0\"\n",
			},
			wantKept: []string{"sha256:legacyfoo"},
		},
		{
			// The directory's own config.toml shares the lockfile too.
			name: "the directory config contests the short name",
			files: map[string]string{
				".config/mise/conf.d/a.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				".config/mise/config.toml":   "[tools]\nfoo = \"1.0.0\"\n",
			},
			wantKept: []string{"sha256:legacyfoo"},
		},
		{
			// Nothing else claims foo, so the stale entry is the edited tool's
			// and has to go, or lock resolution hands it its old version back.
			name: "a lone drop-in owns the short name",
			files: map[string]string{
				".config/mise/conf.d/a.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
			},
			wantGone: []string{"sha256:legacyfoo"},
		},
		{
			// A fragment sharing the lockfile that will not parse is exactly
			// the one that might have claimed the name.
			name: "an unparsable sibling is contested, not absent",
			files: map[string]string{
				".config/mise/conf.d/a.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				".config/mise/conf.d/b.toml": "[tools\nbroken\n",
			},
			wantKept: []string{"sha256:legacyfoo"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(rel, content string) {
				t.Helper()
				full := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for rel, content := range tt.files {
				write(rel, content)
			}
			write(".config/mise/mise.lock", legacyLock)

			const configRel = ".config/mise/conf.d/a.toml"
			cmd := `deputy:mise:update ` + configRel + ` "npm:foo" 1.0.1 1.0.0`
			if err := ApplyDeputyCommand(dir, cmd); err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}

			lock, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(".config/mise/mise.lock")))
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

			// What the next scan sees. A surviving entry that enrichment still
			// borrows would report the fixed tool at its old version, which is
			// the failure pruning was widened to avoid in the first place.
			fsys := fstest.MapFS{}
			for rel := range tt.files {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
				if err != nil {
					t.Fatal(err)
				}
				fsys[rel] = &fstest.MapFile{Data: data}
			}
			fsys[".config/mise/mise.lock"] = &fstest.MapFile{Data: lock}
			f, err := fsys.Open(configRel)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := misex.New().Extract(t.Context(), &filesystem.ScanInput{
				Path:   configRel,
				Reader: f,
				FS:     fsys,
			})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			var got string
			for _, pkg := range inv.Packages {
				if pkg.Name == "npm:foo" {
					got = pkg.Version
				}
			}
			if got != "1.0.1" {
				t.Errorf("extractor reports npm:foo %q after fix, want 1.0.1\nlock:\n%s", got, lock)
			}
		})
	}
}

// TestApplyMiseUpdateSymlinkedSharedLock pins ownership of a lock entry that
// several config directories share through symlinks. mise resolves a config's
// lockfile through the link: with a/mise.toml declaring node = "20", b/mise.toml
// declaring go = "1.22", and both a/mise.lock and b/mise.lock symlinked to one
// ../shared.lock recording 20.11.0 and 1.22.12, mise 2026.7.3 reports
//
//	node  20.11.0 (missing)  /private/tmp/miselink/a/mise.toml  20
//	go    1.22.12 (missing)  /private/tmp/miselink/b/mise.toml  1.22
//
// so the entries in that file belong to two directories at once. Counting
// claimants by listing the directory beside the link therefore counts the
// wrong set: the fix publishes its edit through the link to the shared target,
// where the other config's declaration is the one that loses its integrity
// metadata.
func TestApplyMiseUpdateSymlinkedSharedLock(t *testing.T) {
	t.Parallel()

	const legacyLock = `[[tools.foo]]
version = "1.0.0"
backend = "ubi:foo"

[tools.foo.platforms.linux-x64]
checksum = "sha256:legacyfoo"
`
	tests := []struct {
		name string
		// files are configs to write, by repository-relative path.
		files map[string]string
		// links map a repository-relative lockfile path to the link text it
		// holds; the shared target is written at sharedLock.
		links map[string]string
		// wantKept says the legacy short-name entry must survive because
		// another config sharing the target could own it.
		wantKept bool
	}{
		{
			// b/mise.toml resolves to the same lockfile and strips to the same
			// short name, so the legacy entry may be its own.
			name: "a config sharing the link target contests the short name",
			files: map[string]string{
				"a/mise.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				"b/mise.toml": "[tools]\n\"ubi:foo\" = \"1.0.0\"\n",
			},
			links:    map[string]string{"a/mise.lock": "../shared.lock", "b/mise.lock": "../shared.lock"},
			wantKept: true,
		},
		{
			// A config beside the target itself claims the name too.
			name: "the target's own directory contests the short name",
			files: map[string]string{
				"a/mise.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				"mise.toml":   "[tools]\nfoo = \"1.0.0\"\n",
			},
			links:    map[string]string{"a/mise.lock": "../mise.lock"},
			wantKept: true,
		},
		{
			// Nothing else resolves to the target, so the stale entry is the
			// edited tool's and has to go.
			name: "a lone config owns the short name",
			files: map[string]string{
				"a/mise.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				"b/mise.toml": "[tools]\n\"ubi:bar\" = \"2.0.0\"\n",
			},
			links: map[string]string{"a/mise.lock": "../shared.lock", "b/mise.lock": "../shared.lock"},
		},
		{
			// A config resolving to a different lockfile claims nothing here.
			name: "a config with its own lockfile does not contest",
			files: map[string]string{
				"a/mise.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				"b/mise.toml": "[tools]\n\"ubi:foo\" = \"1.0.0\"\n",
			},
			links: map[string]string{"a/mise.lock": "../shared.lock"},
		},
		{
			// A config sharing the target that will not parse is exactly the
			// one that might have claimed the name.
			name: "an unparsable sharing config is contested, not absent",
			files: map[string]string{
				"a/mise.toml": "[tools]\n\"npm:foo\" = \"1.0.0\"\n",
				"b/mise.toml": "[tools\nbroken\n",
			},
			links:    map[string]string{"a/mise.lock": "../shared.lock", "b/mise.lock": "../shared.lock"},
			wantKept: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()

			dir := t.TempDir()
			write := func(rel, content string) {
				t.Helper()
				full := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.WriteFile(full, []byte(content), 0o644); err != nil {
					t.Fatal(err)
				}
			}
			for rel, content := range tt.files {
				write(rel, content)
			}
			// The shared target is named mise.lock so a config beside it
			// resolves there lexically, which is what makes that directory a
			// claimant in its own right.
			target := "shared.lock"
			if _, ok := tt.files["mise.toml"]; ok {
				target = "mise.lock"
			}
			write(target, legacyLock)
			for rel, to := range tt.links {
				full := filepath.Join(dir, filepath.FromSlash(rel))
				if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(filepath.FromSlash(to), full); err != nil {
					t.Skipf("symlinks unavailable: %v", err)
				}
			}

			cmd := `deputy:mise:update a/mise.toml "npm:foo" 1.0.1 1.0.0`
			if err := ApplyDeputyCommand(dir, cmd); err != nil {
				t.Fatalf("ApplyDeputyCommand: %v", err)
			}

			lock, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(target)))
			if err != nil {
				t.Fatal(err)
			}
			if kept := strings.Contains(string(lock), "sha256:legacyfoo"); kept != tt.wantKept {
				t.Errorf("legacy entry kept = %v, want %v:\n%s", kept, tt.wantKept, lock)
			}

			// What the next scan sees. Pruning and enrichment answer "who owns
			// this name" with the same count, so an entry kept here as
			// contested must also be one the extractor refuses to borrow;
			// otherwise the fixed tool comes back reporting its old version.
			fsys := fstest.MapFS{target: &fstest.MapFile{Data: lock}}
			for rel := range tt.files {
				data, err := os.ReadFile(filepath.Join(dir, filepath.FromSlash(rel)))
				if err != nil {
					t.Fatal(err)
				}
				fsys[rel] = &fstest.MapFile{Data: data}
			}
			for rel, to := range tt.links {
				fsys[rel] = &fstest.MapFile{Mode: os.ModeSymlink, Data: []byte(to)}
			}
			const configRel = "a/mise.toml"
			f, err := fsys.Open(configRel)
			if err != nil {
				t.Fatal(err)
			}
			inv, err := misex.New().Extract(t.Context(), &filesystem.ScanInput{
				Path:   configRel,
				Reader: f,
				FS:     fsys,
			})
			if err != nil {
				t.Fatalf("Extract: %v", err)
			}
			var got string
			for _, pkg := range inv.Packages {
				if pkg.Name == "npm:foo" {
					got = pkg.Version
				}
			}
			if got != "1.0.1" {
				t.Errorf("extractor reports npm:foo %q after fix, want 1.0.1\nlock:\n%s", got, lock)
			}
		})
	}
}
