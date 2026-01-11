package compare

import (
	"encoding/json"
	"io/fs"
	"path/filepath"
	"strings"

	"github.com/picatz/deputy/internal/repository/workspace"
)

// CollectDirectDependenciesFromWorkspace scans the workspace for manifest files
// across multiple ecosystems and extracts direct dependencies. Returns a map
// where keys are package identifiers (PURLs for non-Go, module paths for Go)
// and values indicate if the dependency is direct (true) or indirect (false).
//
// Supported ecosystems:
//   - Go (go.mod)
//   - npm (package.json)
//   - Cargo (Cargo.toml)
//   - PyPI (pyproject.toml, setup.py, requirements.txt)
//
// For Go, this delegates to CollectGoDirectModulesFromWorkspace for its
// specialized handling of module roots and the stdlib pseudo-dependency.
func CollectDirectDependenciesFromWorkspace(ws workspace.FS) map[string]bool {
	if ws == nil {
		return make(map[string]bool)
	}

	// Start with Go direct dependencies (handles stdlib specially)
	direct := CollectGoDirectModulesFromWorkspace(ws)

	// Walk workspace looking for other ecosystem manifests
	_ = fs.WalkDir(ws, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == "vendor" || name == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)

		// Skip vendored paths
		if strings.Contains(path, "/vendor/") || strings.Contains(path, "/node_modules/") {
			return nil
		}

		switch base {
		case "package.json":
			data, err := ws.ReadFile(path)
			if err == nil {
				mergeDirectDependencies(direct, getNpmDirectDeps(data))
			}
		case "Cargo.toml":
			data, err := ws.ReadFile(path)
			if err == nil {
				mergeDirectDependencies(direct, getCargoDirectDeps(data))
			}
		case "pyproject.toml":
			data, err := ws.ReadFile(path)
			if err == nil {
				mergeDirectDependencies(direct, getPyprojectDirectDeps(data))
			}
		case "requirements.txt":
			data, err := ws.ReadFile(path)
			if err == nil {
				mergeDirectDependencies(direct, getRequirementsDirectDeps(data))
			}
		}
		return nil
	})

	return direct
}

// getNpmDirectDeps extracts direct dependencies from package.json.
// Returns map of package names to true (direct).
// devDependencies are marked as direct=true since they're explicitly declared.
func getNpmDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	var pkg struct {
		Dependencies    map[string]string `json:"dependencies"`
		DevDependencies map[string]string `json:"devDependencies"`
	}
	if err := json.Unmarshal(data, &pkg); err != nil {
		return deps
	}

	for name := range pkg.Dependencies {
		// Use package name as key - will be matched against PURL name
		deps[name] = true
	}
	for name := range pkg.DevDependencies {
		deps[name] = true
	}
	return deps
}

// getCargoDirectDeps extracts direct dependencies from Cargo.toml.
// Returns map of crate names to true (direct).
// Uses simple TOML parsing without external dependencies.
func getCargoDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	// Simple TOML parsing for [dependencies] and [dev-dependencies] sections
	lines := strings.Split(string(data), "\n")
	inDeps := false
	inDevDeps := false
	inBuildDeps := false

	for _, line := range lines {
		line = strings.TrimSpace(line)

		// Track which section we're in
		if strings.HasPrefix(line, "[") {
			inDeps = line == "[dependencies]"
			inDevDeps = line == "[dev-dependencies]"
			inBuildDeps = line == "[build-dependencies]"
			continue
		}

		// Skip if not in a dependencies section
		if !inDeps && !inDevDeps && !inBuildDeps {
			continue
		}

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Parse "crate_name = ..." or "crate_name = { version = ... }"
		parts := strings.SplitN(line, "=", 2)
		if len(parts) != 2 {
			continue
		}

		crateName := strings.TrimSpace(parts[0])
		if crateName != "" {
			deps[crateName] = true
		}
	}

	return deps
}

// getPyprojectDirectDeps extracts direct dependencies from pyproject.toml.
// Supports both PEP 621 [project.dependencies] and Poetry [tool.poetry.dependencies].
func getPyprojectDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	lines := strings.Split(string(data), "\n")
	inProjectSection := false
	inPoetryDeps := false
	inDepsArray := false // Inside a multi-line dependencies = [ ... ] array

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)

		// Track which section we're in
		if strings.HasPrefix(trimmed, "[") {
			// Exiting any array we were in
			inDepsArray = false

			inProjectSection = trimmed == "[project]"
			inPoetryDeps = trimmed == "[tool.poetry.dependencies]"
			continue
		}

		// Handle PEP 621 dependencies array start
		if inProjectSection && strings.HasPrefix(trimmed, "dependencies") && strings.Contains(trimmed, "=") {
			if idx := strings.Index(trimmed, "["); idx != -1 {
				// Check if it's a single-line array that also closes
				if strings.Contains(trimmed[idx:], "]") {
					parseInlineDepsArray(trimmed[idx:], deps)
				} else {
					// Multi-line array starting
					inDepsArray = true
					// Parse any deps on the opening line after [
					parseInlineDepsArray(trimmed[idx:]+"]", deps)
				}
			}
			continue
		}

		// Handle multi-line PEP 621 dependencies array
		if inDepsArray {
			if strings.Contains(trimmed, "]") {
				// Array closing - parse any remaining deps on this line
				if idx := strings.Index(trimmed, "]"); idx > 0 {
					parseInlineDepsArray("["+trimmed[:idx]+"]", deps)
				}
				inDepsArray = false
			} else if trimmed != "" && !strings.HasPrefix(trimmed, "#") {
				// Parse individual dependency line: "celery>=5.3.0",
				entry := strings.Trim(trimmed, ",\"'")
				if entry != "" {
					parsePyPIDep(entry, deps)
				}
			}
			continue
		}

		// Handle optional-dependencies section (key = [...] format)
		if strings.HasPrefix(trimmed, "[project.optional-dependencies") ||
			(inProjectSection && strings.Contains(line, "optional-dependencies")) {
			// Skip section header
			continue
		}

		// Handle Poetry-style dependencies
		if inPoetryDeps && !strings.HasPrefix(trimmed, "#") && trimmed != "" {
			parts := strings.SplitN(trimmed, "=", 2)
			if len(parts) == 2 {
				pkgName := strings.TrimSpace(parts[0])
				if pkgName != "" && pkgName != "python" {
					// Normalize package name (PEP 503: lowercase, replace - with _)
					pkgName = strings.ToLower(strings.ReplaceAll(pkgName, "-", "_"))
					deps[pkgName] = true
				}
			}
		}
	}

	return deps
}

// parsePyPIDep extracts and normalizes a single PyPI dependency string.
func parsePyPIDep(entry string, deps map[string]bool) {
	// Extract package name (before any version specifier)
	// Valid specifiers: >=, <=, ==, !=, ~=, <, >, [extras], ;
	pkgName := entry
	for _, sep := range []string{">=", "<=", "==", "!=", "~=", "<", ">", "[", ";"} {
		if idx := strings.Index(pkgName, sep); idx != -1 {
			pkgName = pkgName[:idx]
		}
	}
	pkgName = strings.TrimSpace(pkgName)

	if pkgName != "" {
		// Normalize package name (PEP 503)
		pkgName = strings.ToLower(strings.ReplaceAll(pkgName, "-", "_"))
		deps[pkgName] = true
	}
}

// parseInlineDepsArray parses a Python dependency array like ["pkg1>=1.0", "pkg2"]
func parseInlineDepsArray(line string, deps map[string]bool) {
	// Find array content between [ ]
	start := strings.Index(line, "[")
	end := strings.LastIndex(line, "]")
	if start == -1 || end == -1 || end <= start {
		return
	}

	content := line[start+1 : end]
	// Split by comma and parse each entry
	for _, entry := range strings.Split(content, ",") {
		entry = strings.TrimSpace(entry)
		entry = strings.Trim(entry, "\"'")

		// Extract package name (before any version specifier)
		// Valid specifiers: >=, <=, ==, !=, ~=, <, >, [extras]
		pkgName := entry
		for _, sep := range []string{">=", "<=", "==", "!=", "~=", "<", ">", "[", ";"} {
			if idx := strings.Index(pkgName, sep); idx != -1 {
				pkgName = pkgName[:idx]
			}
		}
		pkgName = strings.TrimSpace(pkgName)

		if pkgName != "" {
			// Normalize package name (PEP 503)
			pkgName = strings.ToLower(strings.ReplaceAll(pkgName, "-", "_"))
			deps[pkgName] = true
		}
	}
}

// getRequirementsDirectDeps extracts package names from requirements.txt.
// All entries in requirements.txt are considered direct dependencies.
func getRequirementsDirectDeps(data []byte) map[string]bool {
	deps := make(map[string]bool)

	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip -r, -e, --index-url, etc.
		if strings.HasPrefix(line, "-") {
			continue
		}

		// Extract package name (before any version specifier or extras)
		pkgName := line
		for _, sep := range []string{">=", "<=", "==", "!=", "~=", "<", ">", "[", "@", ";"} {
			if idx := strings.Index(pkgName, sep); idx != -1 {
				pkgName = pkgName[:idx]
			}
		}
		pkgName = strings.TrimSpace(pkgName)

		if pkgName != "" {
			// Normalize package name (PEP 503)
			pkgName = strings.ToLower(strings.ReplaceAll(pkgName, "-", "_"))
			deps[pkgName] = true
		}
	}

	return deps
}
