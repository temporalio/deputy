package manifests

import (
	"testing"

	"github.com/temporalio/deputy/internal/purlx"
)

func TestDetectManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name         string
		location     string
		purlType     string
		wantManager  string
		wantManifest string
		wantOK       bool
	}{
		// Go
		{
			name:         "go.mod",
			location:     "go.mod",
			wantManager:  "go",
			wantManifest: "go.mod",
			wantOK:       true,
		},
		{
			name:         "go.mod in subdirectory",
			location:     "internal/pkg/go.mod",
			wantManager:  "go",
			wantManifest: "internal/pkg/go.mod",
			wantOK:       true,
		},

		// NPM
		{
			name:         "package-lock.json",
			location:     "package-lock.json",
			wantManager:  "npm",
			wantManifest: "package.json",
			wantOK:       true,
		},
		{
			name:         "package-lock.json in subdirectory",
			location:     "frontend/package-lock.json",
			wantManager:  "npm",
			wantManifest: "frontend/package.json",
			wantOK:       true,
		},
		{
			name:         "npm-shrinkwrap.json",
			location:     "npm-shrinkwrap.json",
			wantManager:  "npm",
			wantManifest: "package.json",
			wantOK:       true,
		},
		{
			name:         "package.json with npm purlType",
			location:     "package.json",
			purlType:     "npm",
			wantManager:  "npm",
			wantManifest: "package.json",
			wantOK:       true,
		},
		{
			name:         "package.json without purlType",
			location:     "package.json",
			purlType:     "",
			wantManager:  "",
			wantManifest: "",
			wantOK:       false,
		},

		// Yarn
		{
			name:         "yarn.lock",
			location:     "yarn.lock",
			wantManager:  "yarn",
			wantManifest: "package.json",
			wantOK:       true,
		},
		{
			name:         "yarn.lock in subdirectory",
			location:     "packages/app/yarn.lock",
			wantManager:  "yarn",
			wantManifest: "packages/app/package.json",
			wantOK:       true,
		},

		// pnpm
		{
			name:         "pnpm-lock.yaml",
			location:     "pnpm-lock.yaml",
			wantManager:  "pnpm",
			wantManifest: "package.json",
			wantOK:       true,
		},
		{
			name:         "pnpm-lock.yml",
			location:     "pnpm-lock.yml",
			wantManager:  "pnpm",
			wantManifest: "package.json",
			wantOK:       true,
		},

		// Python - pip
		{
			name:         "requirements.txt",
			location:     "requirements.txt",
			wantManager:  "pip",
			wantManifest: "requirements.txt",
			wantOK:       true,
		},
		{
			name:         "requirements.txt in subdirectory",
			location:     "backend/requirements.txt",
			wantManager:  "pip",
			wantManifest: "backend/requirements.txt",
			wantOK:       true,
		},

		// Python - pipenv
		{
			name:         "Pipfile.lock",
			location:     "Pipfile.lock",
			wantManager:  "pipenv",
			wantManifest: "Pipfile",
			wantOK:       true,
		},

		// Python - poetry
		{
			name:         "poetry.lock",
			location:     "poetry.lock",
			wantManager:  "poetry",
			wantManifest: "pyproject.toml",
			wantOK:       true,
		},

		// Ruby - gem/bundler
		{
			name:         "Gemfile.lock",
			location:     "Gemfile.lock",
			wantManager:  "gem",
			wantManifest: "Gemfile",
			wantOK:       true,
		},
		{
			name:         "gems.locked",
			location:     "gems.locked",
			wantManager:  "gem",
			wantManifest: "Gemfile",
			wantOK:       true,
		},
		{
			name:         "gemspec file",
			location:     "myapp.gemspec",
			wantManager:  "gem",
			wantManifest: "myapp.gemspec",
			wantOK:       true,
		},

		// PHP - composer
		{
			name:         "composer.lock",
			location:     "composer.lock",
			wantManager:  "composer",
			wantManifest: "composer.json",
			wantOK:       true,
		},

		// Rust - cargo
		{
			name:         "Cargo.toml",
			location:     "Cargo.toml",
			wantManager:  "cargo",
			wantManifest: "Cargo.toml",
			wantOK:       true,
		},
		{
			name:         "Cargo.lock",
			location:     "Cargo.lock",
			wantManager:  "cargo",
			wantManifest: "Cargo.toml",
			wantOK:       true,
		},

		// Python - uv
		{
			name:         "uv.lock",
			location:     "uv.lock",
			wantManager:  "uv",
			wantManifest: "uv.lock",
			wantOK:       true,
		},

		// GitHub Actions
		{
			name:         "GitHub workflow yaml",
			location:     ".github/workflows/ci.yaml",
			wantManager:  purlx.TypeGitHubActions,
			wantManifest: ".github/workflows/ci.yaml",
			wantOK:       true,
		},
		{
			name:         "GitHub workflow yml",
			location:     ".github/workflows/build.yml",
			wantManager:  purlx.TypeGitHubActions,
			wantManifest: ".github/workflows/build.yml",
			wantOK:       true,
		},
		{
			name:         "GitHub workflow uppercase",
			location:     ".github/workflows/CI.YML",
			wantManager:  purlx.TypeGitHubActions,
			wantManifest: ".github/workflows/CI.YML",
			wantOK:       true,
		},
		{
			name:         "action.yml",
			location:     "action.yml",
			wantManager:  purlx.TypeGitHubActions,
			wantManifest: "action.yml",
			wantOK:       true,
		},
		{
			name:         "action.yaml",
			location:     "action.yaml",
			wantManager:  purlx.TypeGitHubActions,
			wantManifest: "action.yaml",
			wantOK:       true,
		},

		// Docker
		{
			name:         "Dockerfile",
			location:     "Dockerfile",
			wantManager:  "docker",
			wantManifest: "Dockerfile",
			wantOK:       true,
		},
		{
			name:         "Containerfile",
			location:     "Containerfile",
			wantManager:  "docker",
			wantManifest: "Containerfile",
			wantOK:       true,
		},
		{
			name:         "Dockerfile in subdirectory",
			location:     "build/Dockerfile",
			wantManager:  "docker",
			wantManifest: "build/Dockerfile",
			wantOK:       true,
		},
		{
			name:         "prod.Dockerfile",
			location:     "prod.Dockerfile",
			wantManager:  "docker",
			wantManifest: "prod.Dockerfile",
			wantOK:       true,
		},
		{
			name:         "prod.dockerfile extension",
			location:     "prod.dockerfile",
			wantManager:  "docker",
			wantManifest: "prod.dockerfile",
			wantOK:       true,
		},
		{
			name:         "app.containerfile extension",
			location:     "app.containerfile",
			wantManager:  "docker",
			wantManifest: "app.containerfile",
			wantOK:       true,
		},
		{
			name:         "suffixed Dockerfile",
			location:     "Dockerfile.prod",
			wantManager:  "",
			wantManifest: "",
			wantOK:       false, // suffix-based detection only works for *Dockerfile pattern
		},

		// Not recognized
		{
			name:         "unknown file",
			location:     "README.md",
			wantManager:  "",
			wantManifest: "",
			wantOK:       false,
		},
		{
			name:         "random yaml file",
			location:     "config.yaml",
			wantManager:  "",
			wantManifest: "",
			wantOK:       false,
		},
		{
			name:         "non-workflow yaml in .github",
			location:     ".github/dependabot.yml",
			wantManager:  "",
			wantManifest: "",
			wantOK:       false,
		},

		// Paths with forward slashes (cross-platform)
		{
			name:         "forward slash path",
			location:     "src/app/go.mod",
			wantManager:  "go",
			wantManifest: "src/app/go.mod",
			wantOK:       true,
		},

		// mise / asdf toolchains
		{
			name:         "mise.toml",
			location:     "mise.toml",
			purlType:     "mise",
			wantManager:  "mise",
			wantManifest: "mise.toml",
			wantOK:       true,
		},
		{
			name:         "nested .config/mise/config.toml",
			location:     "sub/.config/mise/config.toml",
			purlType:     "mise",
			wantManager:  "mise",
			wantManifest: "sub/.config/mise/config.toml",
			wantOK:       true,
		},
		{
			name:         ".tool-versions is asdf",
			location:     ".tool-versions",
			purlType:     "asdf",
			wantManager:  "asdf",
			wantManifest: ".tool-versions",
			wantOK:       true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			manager, manifest, ok := DetectManager(tt.location, tt.purlType)
			if ok != tt.wantOK {
				t.Errorf("DetectManager() ok = %v, want %v", ok, tt.wantOK)
			}
			if manager != tt.wantManager {
				t.Errorf("DetectManager() manager = %q, want %q", manager, tt.wantManager)
			}
			if manifest != tt.wantManifest {
				t.Errorf("DetectManager() manifest = %q, want %q", manifest, tt.wantManifest)
			}
		})
	}
}

func TestIsDockerfilePath(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		input  string
		expect bool
	}{
		// Exact matches (case-insensitive)
		{"Dockerfile", "Dockerfile", true},
		{"dockerfile lowercase", "dockerfile", true},
		{"DOCKERFILE uppercase", "DOCKERFILE", true},
		{"Containerfile", "Containerfile", true},
		{"containerfile lowercase", "containerfile", true},

		// Extension patterns
		{"app.dockerfile", "app.dockerfile", true},
		{"prod.Dockerfile (extension)", "prod.Dockerfile", true}, // both suffix and extension match
		{"test.containerfile", "test.containerfile", true},
		{"build.DOCKERFILE", "build.DOCKERFILE", true},

		// Suffix patterns (case-sensitive suffix)
		{"devDockerfile", "devDockerfile", true},
		{"prodContainerfile", "prodContainerfile", true},
		{"MyDockerfile", "MyDockerfile", true},

		// Not dockerfiles
		{"random file", "random.txt", false},
		{"dockerfile.bak (has suffix)", "dockerfile.bak", false},
		{"Dockerfile.prod (prefix match only)", "Dockerfile.prod", false},
		{"dockerfiler (suffix typo)", "dockerfiler", false},
		{"container", "container", false},
		{"docker-compose.yml", "docker-compose.yml", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := isDockerfilePath(tt.input)
			if got != tt.expect {
				t.Errorf("isDockerfilePath(%q) = %v, want %v", tt.input, got, tt.expect)
			}
		})
	}
}

func TestHasRuntimeDependencyGroup(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		groups []string
		expect bool
	}{
		{"empty groups", []string{}, false},
		{"nil groups", nil, false},
		{"dependencies exact match", []string{"dependencies"}, true},
		{"Dependencies mixed case", []string{"Dependencies"}, true},
		{"DEPENDENCIES uppercase", []string{"DEPENDENCIES"}, true},
		{"devDependencies only", []string{"devDependencies"}, false},
		{"multiple groups with dependencies", []string{"devDependencies", "dependencies"}, true},
		{"dependencies with whitespace", []string{" dependencies "}, true},
		{"peerDependencies only", []string{"peerDependencies"}, false},
		{"optionalDependencies only", []string{"optionalDependencies"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := HasRuntimeDependencyGroup(tt.groups)
			if got != tt.expect {
				t.Errorf("HasRuntimeDependencyGroup(%v) = %v, want %v", tt.groups, got, tt.expect)
			}
		})
	}
}

func TestMarksDirectByDefault(t *testing.T) {
	t.Parallel()

	tests := []struct {
		manager string
		expect  bool
	}{
		// True cases
		{"pip", true},
		{"pipenv", true},
		{"poetry", true},
		{"gem", true},
		{"docker", true},

		// Case-insensitive
		{"PIP", true},
		{"Pip", true},
		{"POETRY", true},

		// With whitespace
		{" pip ", true},
		{"  gem  ", true},

		// False cases
		{"npm", false},
		{"yarn", false},
		{"pnpm", false},
		{"go", false},
		{"cargo", false},
		{"composer", false},
		{"maven", false},
		{"gradle", false},
		{"", false},
		{"unknown", false},
	}

	for _, tt := range tests {
		t.Run(tt.manager, func(t *testing.T) {
			t.Parallel()
			got := MarksDirectByDefault(tt.manager)
			if got != tt.expect {
				t.Errorf("MarksDirectByDefault(%q) = %v, want %v", tt.manager, got, tt.expect)
			}
		})
	}
}

func TestInferArtifactManager(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name             string
		pathStr          string
		manifestManagers map[string]string
		dirManagers      map[string]string
		expect           string
	}{
		// Direct manifest mapping
		{
			name:             "exact manifest match",
			pathStr:          "go.mod",
			manifestManagers: map[string]string{"go.mod": "go"},
			dirManagers:      nil,
			expect:           "go",
		},
		{
			name:             "exact manifest match in subdir",
			pathStr:          "backend/go.mod",
			manifestManagers: map[string]string{"backend/go.mod": "go"},
			dirManagers:      nil,
			expect:           "go",
		},

		// Directory-based mapping
		{
			name:             "directory manager match",
			pathStr:          "frontend/index.js",
			manifestManagers: nil,
			dirManagers:      map[string]string{"frontend": "npm"},
			expect:           "npm",
		},
		{
			name:             "directory manager with ./ prefix",
			pathStr:          "./frontend/index.js",
			manifestManagers: nil,
			dirManagers:      map[string]string{"frontend": "npm"},
			expect:           "npm",
		},
		{
			name:             "root directory",
			pathStr:          "main.go",
			manifestManagers: nil,
			dirManagers:      map[string]string{"": "go"},
			expect:           "go",
		},
		{
			name:             "current directory notation",
			pathStr:          "./main.go",
			manifestManagers: nil,
			dirManagers:      map[string]string{"": "go"},
			expect:           "go",
		},

		// go.sum special case
		{
			name:             "go.sum with matching go.mod",
			pathStr:          "go.sum",
			manifestManagers: map[string]string{"go.mod": "go"},
			dirManagers:      nil,
			expect:           "go",
		},
		{
			name:             "go.sum in subdir with matching go.mod",
			pathStr:          "pkg/go.sum",
			manifestManagers: map[string]string{"pkg/go.mod": "go"},
			dirManagers:      nil,
			expect:           "go",
		},
		{
			name:             "go.sum fallback without go.mod",
			pathStr:          "go.sum",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "go",
		},

		// Lockfile suffix fallback
		{
			name:             "package-lock.json fallback",
			pathStr:          "package-lock.json",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "npm",
		},
		{
			name:             "yarn.lock fallback",
			pathStr:          "yarn.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "yarn",
		},
		{
			name:             "pnpm-lock.yaml fallback",
			pathStr:          "pnpm-lock.yaml",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "pnpm",
		},
		{
			name:             "composer.lock fallback",
			pathStr:          "composer.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "composer",
		},
		{
			name:             "Gemfile.lock fallback",
			pathStr:          "Gemfile.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "bundler",
		},
		{
			name:             "Cargo.lock fallback",
			pathStr:          "Cargo.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "cargo",
		},
		{
			name:             "requirements.txt fallback",
			pathStr:          "requirements.txt",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "pip",
		},
		{
			name:             "poetry.lock fallback",
			pathStr:          "poetry.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "poetry",
		},
		{
			name:             "package.json fallback",
			pathStr:          "package.json",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "npm",
		},

		// Lockfile in subdirectory
		{
			name:             "nested package-lock.json fallback",
			pathStr:          "frontend/package-lock.json",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "npm",
		},

		// Priority: manifest > directory > go.sum > lockfile
		{
			name:             "manifest takes priority over directory",
			pathStr:          "frontend/package.json",
			manifestManagers: map[string]string{"frontend/package.json": "yarn"},
			dirManagers:      map[string]string{"frontend": "npm"},
			expect:           "yarn",
		},

		// Unknown
		{
			name:             "unknown file",
			pathStr:          "README.md",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "",
		},
		{
			name:             "unknown lockfile type",
			pathStr:          "unknown.lock",
			manifestManagers: nil,
			dirManagers:      nil,
			expect:           "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := InferArtifactManager(tt.pathStr, tt.manifestManagers, tt.dirManagers)
			if got != tt.expect {
				t.Errorf("InferArtifactManager(%q, %v, %v) = %q, want %q",
					tt.pathStr, tt.manifestManagers, tt.dirManagers, got, tt.expect)
			}
		})
	}
}

func TestSlicesContainsFold(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		values []string
		target string
		expect bool
	}{
		{"exact match", []string{"foo", "bar"}, "foo", true},
		{"case insensitive", []string{"FOO", "bar"}, "foo", true},
		{"case insensitive reverse", []string{"foo", "bar"}, "FOO", true},
		{"mixed case", []string{"Foo", "Bar"}, "foo", true},
		{"with whitespace", []string{" foo ", "bar"}, "foo", true},
		{"target with whitespace", []string{"foo", "bar"}, " foo ", false}, // target is not trimmed
		{"not found", []string{"foo", "bar"}, "baz", false},
		{"empty slice", []string{}, "foo", false},
		{"nil slice", nil, "foo", false},
		{"empty target", []string{"foo", ""}, "", true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := slicesContainsFold(tt.values, tt.target)
			if got != tt.expect {
				t.Errorf("slicesContainsFold(%v, %q) = %v, want %v", tt.values, tt.target, got, tt.expect)
			}
		})
	}
}
