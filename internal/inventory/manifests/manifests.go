package manifests

import (
	"path"
	"path/filepath"
	"strings"

	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
)

// DetectManager identifies the package manager and manifest path for a given location.
func DetectManager(location, purlType string) (string, string, bool) {
	loc := filepath.ToSlash(location)
	if strings.HasPrefix(loc, ".github/workflows/") {
		ext := strings.ToLower(path.Ext(loc))
		if ext == ".yml" || ext == ".yaml" {
			return purlx.TypeGitHubActions, loc, true
		}
	}
	base := path.Base(loc)
	dir := path.Dir(loc)
	switch base {
	case "go.mod":
		return "go", loc, true
	case "package-lock.json", "npm-shrinkwrap.json":
		return "npm", path.Join(dir, "package.json"), true
	case "yarn.lock":
		return "yarn", path.Join(dir, "package.json"), true
	case "pnpm-lock.yaml", "pnpm-lock.yml":
		return "pnpm", path.Join(dir, "package.json"), true
	case "requirements.txt":
		return "pip", loc, true
	case "Pipfile.lock":
		return "pipenv", path.Join(dir, "Pipfile"), true
	case "poetry.lock":
		return "poetry", path.Join(dir, "pyproject.toml"), true
	case "Gemfile.lock", "gems.locked":
		return "gem", path.Join(dir, "Gemfile"), true
	case "composer.lock":
		return "composer", path.Join(dir, "composer.json"), true
	case "Cargo.toml":
		return "cargo", loc, true
	case "Cargo.lock":
		return "cargo", path.Join(dir, "Cargo.toml"), true
	case "uv.lock":
		return "uv", loc, true
	case "package.json":
		if strings.EqualFold(purlType, "npm") {
			return "npm", loc, true
		}
	case "action.yml", "action.yaml":
		return purlx.TypeGitHubActions, loc, true
	default:
		if strings.HasSuffix(base, ".gemspec") {
			return "gem", loc, true
		}
		if isDockerfilePath(base) {
			return "docker", loc, true
		}
		// mise / asdf toolchain configs. The config file is itself the manifest
		// to edit, so fixes target it directly (mise.toml / .tool-versions).
		if format, ok := mise.IsConfigPath(loc); ok {
			if format == mise.FormatToolVersions {
				return "asdf", loc, true
			}
			return "mise", loc, true
		}
	}
	return "", "", false
}

// isDockerfilePath checks if a filename looks like a Dockerfile or Containerfile.
func isDockerfilePath(name string) bool {
	lower := strings.ToLower(name)

	// Exact matches (case-insensitive)
	if lower == "dockerfile" || lower == "containerfile" {
		return true
	}

	// Extension patterns: *.dockerfile, *.containerfile
	if strings.HasSuffix(lower, ".dockerfile") || strings.HasSuffix(lower, ".containerfile") {
		return true
	}

	// Suffix patterns: *Dockerfile, *Containerfile (case-sensitive for suffix)
	if strings.HasSuffix(name, "Dockerfile") || strings.HasSuffix(name, "Containerfile") {
		return true
	}

	return false
}

// HasRuntimeDependencyGroup checks if any of the groups indicate a runtime dependency.
func HasRuntimeDependencyGroup(groups []string) bool {
	return slicesContainsFold(groups, "dependencies")
}

// MarksDirectByDefault returns true if the package manager considers dependencies direct by default.
func MarksDirectByDefault(manager string) bool {
	switch strings.ToLower(strings.TrimSpace(manager)) {
	case "pip", "pipenv", "poetry", "gem", "docker":
		return true
	default:
		return false
	}
}

// InferArtifactManager attempts to determine the package manager for a given artifact path.
func InferArtifactManager(pathStr string, manifestManagers map[string]string, dirManagers map[string]string) string {
	if mgr := manifestManagers[pathStr]; mgr != "" {
		return mgr
	}
	dir := strings.TrimPrefix(path.Dir(pathStr), "./")
	if dir == "." {
		dir = ""
	}
	if mgr := dirManagers[dir]; mgr != "" {
		return mgr
	}
	if before, ok := strings.CutSuffix(pathStr, "go.sum"); ok {
		candidate := before + "go.mod"
		if mgr := manifestManagers[candidate]; mgr != "" {
			return mgr
		}
		return "go"
	}
	for suffix, mgr := range lockfileManagers {
		if strings.HasSuffix(pathStr, suffix) {
			return mgr
		}
	}
	return ""
}

var lockfileManagers = map[string]string{
	"package-lock.json": "npm",
	"yarn.lock":         "yarn",
	"pnpm-lock.yaml":    "pnpm",
	"composer.lock":     "composer",
	"Gemfile.lock":      "bundler",
	"Cargo.lock":        "cargo",
	"requirements.txt":  "pip",
	"poetry.lock":       "poetry",
	"package.json":      "npm",
}

func slicesContainsFold(values []string, target string) bool {
	for _, v := range values {
		if strings.EqualFold(strings.TrimSpace(v), target) {
			return true
		}
	}
	return false
}
