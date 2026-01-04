package cmd

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"
)

func TestIsContainerDiffInContext(t *testing.T) {
	// Create a temporary Git repository with some tags
	tmpDir, err := os.MkdirTemp("", "deputy-test-git-*")
	if err != nil {
		t.Fatalf("failed to create temp dir: %v", err)
	}
	defer os.RemoveAll(tmpDir)

	// Initialize a git repo with some commits and tags
	cmds := [][]string{
		{"git", "init"},
		{"git", "config", "user.email", "test@example.com"},
		{"git", "config", "user.name", "Test User"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\n%s", args, err, out)
		}
	}

	// Create a file and commit
	if err := os.WriteFile(filepath.Join(tmpDir, "test.txt"), []byte("test"), 0644); err != nil {
		t.Fatalf("failed to write test file: %v", err)
	}
	cmds = [][]string{
		{"git", "add", "."},
		{"git", "commit", "-m", "Initial commit"},
		{"git", "tag", "v1.28.1"},
		{"git", "tag", "v1.29.2"},
	}
	for _, args := range cmds {
		cmd := exec.Command(args[0], args[1:]...)
		cmd.Dir = tmpDir
		if out, err := cmd.CombinedOutput(); err != nil {
			t.Fatalf("command %v failed: %v\n%s", args, err, out)
		}
	}

	tests := []struct {
		name    string
		base    string
		target  string
		repoDir string
		want    bool
	}{
		{
			name:    "Git tags in a Git repo should prefer Git diff",
			base:    "v1.28.1",
			target:  "v1.29.2",
			repoDir: tmpDir,
			want:    false, // Should be Git diff, not container diff
		},
		{
			name:    "Explicit image schemes always container diff",
			base:    "docker://nginx:1.24",
			target:  "docker://nginx:1.25",
			repoDir: tmpDir,
			want:    true,
		},
		{
			name:    "Container refs without Git repo context",
			base:    "nginx:1.24",
			target:  "nginx:1.25",
			repoDir: "",
			want:    true,
		},
		{
			name:    "Registry refs in Git repo are still container diff",
			base:    "ghcr.io/owner/app:v1.0",
			target:  "ghcr.io/owner/app:v2.0",
			repoDir: tmpDir,
			want:    true,
		},
		{
			name:    "HEAD refs should be Git diff",
			base:    "HEAD~1",
			target:  "HEAD",
			repoDir: tmpDir,
			want:    false,
		},
		{
			name:    "Non-existent tags in Git repo fall back to container detection",
			base:    "nginx:1.24",
			target:  "nginx:1.25",
			repoDir: tmpDir,
			want:    true, // nginx:1.24 is not a valid Git ref
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isContainerDiffInContext(tt.base, tt.target, tt.repoDir)
			if got != tt.want {
				t.Errorf("isContainerDiffInContext(%q, %q, %q) = %v, want %v",
					tt.base, tt.target, tt.repoDir, got, tt.want)
			}
		})
	}
}

func TestIsContainerDiff(t *testing.T) {
	tests := []struct {
		name   string
		base   string
		target string
		want   bool
	}{
		{
			name:   "both Docker Hub library images with tags",
			base:   "nginx:1.24",
			target: "nginx:1.25",
			want:   true,
		},
		{
			name:   "both GHCR images",
			base:   "ghcr.io/owner/app:v1.0",
			target: "ghcr.io/owner/app:v2.0",
			want:   true,
		},
		{
			name:   "explicit OCI scheme",
			base:   "oci://alpine:3.18",
			target: "oci://alpine:3.19",
			want:   true,
		},
		{
			name:   "explicit docker scheme",
			base:   "docker://nginx:1.24",
			target: "docker://nginx:1.25",
			want:   true,
		},
		{
			name:   "localhost registry",
			base:   "localhost:5000/myapp:v1",
			target: "localhost:5000/myapp:v2",
			want:   true,
		},
		{
			name:   "github repo path (known git host)",
			base:   "github.com/owner/repo",
			target: "github.com/owner/repo",
			want:   false,
		},
		{
			name:   "git special refs",
			base:   "HEAD",
			target: "HEAD~3",
			want:   false,
		},
		{
			name:   "ambiguous owner/repo without tag",
			base:   "owner/repo",
			target: "owner/other",
			want:   false,
		},
		{
			name:   "owner/repo with explicit tags",
			base:   "owner/repo:v1.0",
			target: "owner/repo:v2.0",
			want:   true,
		},
		{
			name:   "ECR registry",
			base:   "123456789.dkr.ecr.us-east-1.amazonaws.com/app:v1",
			target: "123456789.dkr.ecr.us-east-1.amazonaws.com/app:v2",
			want:   true,
		},
		// Note: Simple names like "main" and "nginx" are both valid Docker Hub library
		// images and git branch names. The detection considers them as images because
		// they parse as valid Docker references. Users should use explicit oci:// or
		// docker:// prefixes for clarity when names are ambiguous.
		{
			name:   "simple names treated as Docker Hub images",
			base:   "nginx",
			target: "alpine",
			want:   true, // Docker Hub library images
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isContainerDiff(tt.base, tt.target)
			if got != tt.want {
				t.Errorf("isContainerDiff(%q, %q) = %v, want %v", tt.base, tt.target, got, tt.want)
			}
		})
	}
}

func TestIsContainerImageRef(t *testing.T) {
	tests := []struct {
		ref  string
		want bool
	}{
		// Clear container image references
		{"nginx:1.25", true},
		{"alpine:3.19", true},
		{"oci://nginx:1.25", true},
		{"docker://nginx:1.25", true},
		{"ghcr.io/owner/app:v1", true},
		{"quay.io/repo/image:tag", true},
		{"localhost:5000/app:dev", true},
		{"gcr.io/project/image:tag", true},
		{"owner/repo:v1.0", true},

		// Clear non-container references
		{"HEAD", false},        // Git special ref (contains uppercase not valid in Docker refs)
		{"HEAD~3", false},      // Git special ref
		{"origin/main", false}, // origin is not a valid Docker registry
		{"github.com/owner/repo", false},
		{"gitlab.com/owner/repo", false},
		{"./relative/path", false},
		{"/absolute/path", false},
		{"git@github.com:owner/repo.git", false},

		// Docker Hub library images (simple names parse as valid Docker refs)
		{"nginx", true},
		{"alpine", true},

		// Ambiguous cases
		{"owner/repo", false}, // No tag, could be GitHub path
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			got := isContainerImageRef(tt.ref)
			if got != tt.want {
				t.Errorf("isContainerImageRef(%q) = %v, want %v", tt.ref, got, tt.want)
			}
		})
	}
}

func TestNormalizeImageReference(t *testing.T) {
	tests := []struct {
		input          string
		useLocalDaemon bool
		want           string
	}{
		{"nginx:1.25", false, "oci://nginx:1.25"},
		{"ghcr.io/owner/app:v1", false, "oci://ghcr.io/owner/app:v1"},
		{"oci://alpine:3.19", false, "oci://alpine:3.19"},
		{"docker://nginx:1.25", false, "docker://nginx:1.25"},
		{"", false, ""},
		{"  nginx:1.25  ", false, "oci://nginx:1.25"},
		// With local daemon
		{"nginx:1.25", true, "docker-daemon://nginx:1.25"},
		{"ghcr.io/owner/app:v1", true, "docker-daemon://ghcr.io/owner/app:v1"},
		{"docker://nginx:1.25", true, "docker://nginx:1.25"}, // Existing scheme preserved
	}

	for _, tt := range tests {
		name := tt.input
		if tt.useLocalDaemon {
			name += " (local)"
		}
		t.Run(name, func(t *testing.T) {
			got := normalizeImageReference(tt.input, tt.useLocalDaemon)
			if got != tt.want {
				t.Errorf("normalizeImageReference(%q, %v) = %q, want %q", tt.input, tt.useLocalDaemon, got, tt.want)
			}
		})
	}
}

func TestFindBestFixVersion(t *testing.T) {
	tests := []struct {
		name          string
		fixedVersions []string
		currentVer    string
		want          string
	}{
		// Basic cases
		{
			name:          "empty fix list",
			fixedVersions: []string{},
			currentVer:    "1.0.0",
			want:          "",
		},
		{
			name:          "single fix version",
			fixedVersions: []string{"1.1.0"},
			currentVer:    "1.0.0",
			want:          "1.1.0",
		},
		{
			name:          "no current version",
			fixedVersions: []string{"1.1.0", "2.0.0"},
			currentVer:    "",
			want:          "1.1.0", // Returns first available
		},

		// In-band upgrades (prefer same major)
		{
			name:          "prefer in-band upgrade over major version jump",
			fixedVersions: []string{"1.3.0", "2.0.0", "3.0.0"},
			currentVer:    "1.2.0",
			want:          "1.3.0", // Same major version
		},
		{
			name:          "multiple in-band fixes, pick smallest >= current",
			fixedVersions: []string{"1.5.0", "1.3.0", "1.4.0"},
			currentVer:    "1.2.0",
			want:          "1.3.0", // Smallest that's >= 1.2.0
		},

		// Alpine-style versions (1.37.0-r18)
		{
			name:          "Alpine revision upgrade",
			fixedVersions: []string{"1.37.0-r20", "1.37.0-r19"},
			currentVer:    "1.37.0-r18",
			want:          "1.37.0-r19", // Smallest fix >= current
		},
		{
			name:          "Alpine with backport (fix version < current)",
			fixedVersions: []string{"1.36.1-r21"},
			currentVer:    "1.37.0-r18",
			want:          "1.36.1-r21", // Only available fix, even if "older"
		},

		// Go module versions
		{
			name:          "Go semver upgrade",
			fixedVersions: []string{"v0.35.0", "v0.43.0", "v0.45.0"},
			currentVer:    "v0.32.0",
			want:          "v0.35.0", // Smallest fix >= current
		},
		{
			name:          "Go module major version preference",
			fixedVersions: []string{"v1.20.0", "v2.0.0"},
			currentVer:    "v1.18.0",
			want:          "v1.20.0", // Stay in v1.x band
		},

		// No in-band fixes available
		{
			name:          "only higher major available",
			fixedVersions: []string{"2.0.0", "3.0.0"},
			currentVer:    "1.5.0",
			want:          "2.0.0", // Smallest available
		},

		// Real-world case from busybox
		{
			name:          "busybox backport scenario",
			fixedVersions: []string{"1.36.1-r21"},
			currentVer:    "1.37.0-r18",
			want:          "1.36.1-r21", // This is the only fix
		},

		// Multiple vulns with different fixes - pick best unified fix
		{
			name:          "busybox with newer fix available",
			fixedVersions: []string{"1.36.1-r31", "1.37.0-r20"},
			currentVer:    "1.37.0-r18",
			want:          "1.37.0-r20", // Prefer >= current over backport
		},
		{
			name:          "multiple fixes pick minimum >= current",
			fixedVersions: []string{"1.37.0-r20", "1.37.0-r25", "1.38.0-r0"},
			currentVer:    "1.37.0-r18",
			want:          "1.37.0-r20", // Smallest that's >= current
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findBestFixVersion(tt.fixedVersions, tt.currentVer)
			if got != tt.want {
				t.Errorf("findBestFixVersion(%v, %q) = %q, want %q",
					tt.fixedVersions, tt.currentVer, got, tt.want)
			}
		})
	}
}

func TestExtractMajorVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"1.2.3", "1"},
		{"v1.2.3", "1"},
		{"1.37.0-r18", "1"},
		{"10.2.3", "10"},
		{"", ""},
		{"v0.35.0", "0"},
		{"2.0.0-alpha", "2"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			got := extractMajorVersion(tt.version)
			if got != tt.want {
				t.Errorf("extractMajorVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestCompareVersionStrings(t *testing.T) {
	tests := []struct {
		a, b     string
		wantSign int // -1, 0, or 1
	}{
		{"1.0.0", "1.0.0", 0},
		{"1.0.0", "2.0.0", -1},
		{"2.0.0", "1.0.0", 1},
		{"1.1.0", "1.2.0", -1},
		{"1.2.0", "1.1.0", 1},

		// Alpine revision comparisons
		{"1.37.0-r18", "1.37.0-r19", -1},
		{"1.37.0-r19", "1.37.0-r18", 1},
		{"1.37.0-r18", "1.37.0-r18", 0},
		{"1.36.1-r21", "1.37.0-r18", -1}, // 1.36 < 1.37

		// Go versions
		{"v0.32.0", "v0.35.0", -1},
		{"v1.0.0", "v0.99.0", 1},

		// Mixed formats
		{"1.0.0", "v1.0.0", 0},
	}

	for _, tt := range tests {
		name := tt.a + "_vs_" + tt.b
		t.Run(name, func(t *testing.T) {
			got := compareVersionStrings(tt.a, tt.b)
			gotSign := 0
			if got > 0 {
				gotSign = 1
			} else if got < 0 {
				gotSign = -1
			}
			if gotSign != tt.wantSign {
				t.Errorf("compareVersionStrings(%q, %q) = %d (sign %d), want sign %d",
					tt.a, tt.b, got, gotSign, tt.wantSign)
			}
		})
	}
}

func TestCategorizePackageSourceWithPkg(t *testing.T) {
	tests := []struct {
		name       string
		cmd        string
		inBase     bool
		pkgName    string
		wantType   string
		wantAction string
	}{
		{
			name:       "Go module in COPY binary",
			cmd:        "COPY --from=builder /app/server /usr/local/bin/",
			pkgName:    "golang.org/x/crypto",
			wantType:   "Go dep in binary",
			wantAction: "go get golang.org/x/crypto@latest",
		},
		{
			name:       "Go module github path",
			cmd:        "COPY --from=builder /app/mybin /usr/bin/mybin",
			pkgName:    "github.com/spiffe/go-spiffe/v2",
			wantType:   "Go dep in binary",
			wantAction: "go get github.com/spiffe/go-spiffe/v2@latest",
		},
		{
			name:       "Regular binary COPY",
			cmd:        "COPY myapp /usr/local/bin/myapp",
			pkgName:    "busybox",
			wantType:   "binary (myapp)",
			wantAction: "rebuild binary",
		},
		{
			name:       "APK package",
			cmd:        "apk add curl openssl",
			pkgName:    "curl",
			wantType:   "apk",
			wantAction: "run apk upgrade",
		},
		{
			name:       "APT package",
			cmd:        "/bin/sh -c apt-get install -y curl",
			pkgName:    "curl",
			wantType:   "apt",
			wantAction: "run apt-get upgrade",
		},
		{
			name:       "pip install",
			cmd:        "pip install requests",
			pkgName:    "requests",
			wantType:   "pip",
			wantAction: "update requirements.txt",
		},
		{
			name:       "npm install",
			cmd:        "npm install lodash",
			pkgName:    "lodash",
			wantType:   "npm",
			wantAction: "update package.json",
		},
		{
			name:       "go build with Go module",
			cmd:        "go build -o /app/server .",
			pkgName:    "go.temporal.io/api",
			wantType:   "Go dep",
			wantAction: "go get go.temporal.io/api@latest",
		},
		{
			name:       "Unknown command but Go module",
			cmd:        "",
			pkgName:    "golang.org/x/net",
			wantType:   "Go dep",
			wantAction: "go get golang.org/x/net@latest",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotType, gotAction := categorizePackageSourceWithPkg(tt.cmd, tt.inBase, tt.pkgName)
			if gotType != tt.wantType {
				t.Errorf("categorizePackageSourceWithPkg() type = %q, want %q", gotType, tt.wantType)
			}
			if gotAction != tt.wantAction {
				t.Errorf("categorizePackageSourceWithPkg() action = %q, want %q", gotAction, tt.wantAction)
			}
		})
	}
}

func TestExtractBinaryFromCopy(t *testing.T) {
	tests := []struct {
		cmd  string
		want string
	}{
		{"COPY --from=builder /app/mybin /usr/local/bin/", "mybin"},
		{"COPY myapp /usr/bin/myapp", "myapp"},
		{"COPY server /opt/server", "server"},
		{"ADD https://example.com/tool.tar.gz /opt/", "tool"},
		{"COPY . /app", ""}, // Single dot isn't meaningful
		{"COPY", ""},        // Invalid
	}

	for _, tt := range tests {
		t.Run(tt.cmd, func(t *testing.T) {
			got := extractBinaryFromCopy(tt.cmd)
			if got != tt.want {
				t.Errorf("extractBinaryFromCopy(%q) = %q, want %q", tt.cmd, got, tt.want)
			}
		})
	}
}
