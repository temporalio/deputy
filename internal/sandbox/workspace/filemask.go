// Package workspace provides file masking for sandbox isolation.
package workspace

import (
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"strings"

	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
)

// FileMasker handles file masking for sandboxed execution.
// It creates a view of the workspace where sensitive files are hidden,
// emptied, or replaced with placeholders.
type FileMasker struct {
	config *sandboxv1.FileMaskConfig
	rules  []maskRule
}

type maskRule struct {
	pattern string
	mode    sandboxv1.FileMaskMode
	reason  string
}

// NewFileMasker creates a new file masker from configuration.
func NewFileMasker(config *sandboxv1.FileMaskConfig) *FileMasker {
	if config == nil {
		config = &sandboxv1.FileMaskConfig{}
	}

	fm := &FileMasker{config: config}

	// Add rules from presets first (lowest priority)
	for _, preset := range config.GetPresets() {
		fm.addPresetRules(preset)
	}

	// Add explicit rules (higher priority)
	for _, rule := range config.GetMaskRules() {
		fm.rules = append(fm.rules, maskRule{
			pattern: rule.GetPattern(),
			mode:    rule.GetMode(),
			reason:  rule.GetReason(),
		})
	}

	return fm
}

// ShouldMask determines if a file should be masked and how.
// Returns the mask mode and reason.
func (fm *FileMasker) ShouldMask(path string) (sandboxv1.FileMaskMode, string) {
	// First check expose patterns (whitelist)
	for _, pattern := range fm.config.GetExposePatterns() {
		if matchPattern(path, pattern) {
			return sandboxv1.FileMaskMode_FILE_MASK_MODE_UNSPECIFIED, ""
		}
	}

	// Check rules in reverse order (later rules have higher priority)
	for _, rule := range slices.Backward(fm.rules) {

		if matchPattern(path, rule.pattern) {
			return rule.mode, rule.reason
		}
	}

	// Fall back to default mode
	if fm.config.GetDefaultMode() != sandboxv1.FileMaskMode_FILE_MASK_MODE_UNSPECIFIED {
		return fm.config.GetDefaultMode(), "default masking policy"
	}

	return sandboxv1.FileMaskMode_FILE_MASK_MODE_UNSPECIFIED, ""
}

// CreateMaskedWorkspace creates a copy of the workspace with masked files.
// SECURITY: Uses os.Root (Go 1.24+) for traversal-resistant file operations.
// Returns the path to the masked workspace.
func (fm *FileMasker) CreateMaskedWorkspace(srcDir, dstDir string) error {
	// Open source as a root for traversal-resistant access
	srcRoot, err := os.OpenRoot(srcDir)
	if err != nil {
		return fmt.Errorf("open source root: %w", err)
	}
	defer srcRoot.Close()

	srcFS := srcRoot.FS()

	return fs.WalkDir(srcFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}

		// Skip root
		if path == "." {
			return nil
		}

		dstPath := filepath.Join(dstDir, path)

		info, err := d.Info()
		if err != nil {
			return err
		}

		// SECURITY: Skip symlinks entirely
		if info.Mode()&os.ModeSymlink != 0 {
			return nil
		}

		// Handle directories
		if d.IsDir() {
			// Check if entire directory should be hidden
			mode, _ := fm.ShouldMask(path)
			if mode == sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
				return fs.SkipDir
			}
			return os.MkdirAll(dstPath, info.Mode())
		}

		// Handle files based on mask mode
		mode, reason := fm.ShouldMask(path)
		switch mode {
		case sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN:
			// Don't create the file at all
			return nil

		case sandboxv1.FileMaskMode_FILE_MASK_MODE_EMPTY:
			// Create empty file with same permissions
			return createEmptyFile(dstPath, info.Mode())

		case sandboxv1.FileMaskMode_FILE_MASK_MODE_PLACEHOLDER:
			// Create file with placeholder content
			content := fmt.Sprintf("[MASKED] %s\n\nReason: %s\n", path, reason)
			return os.WriteFile(dstPath, []byte(content), info.Mode())

		case sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY:
			// Copy file but mark read-only using os.Root
			return copyFileWithRootToPath(srcRoot, path, dstPath, info.Mode()&0444)

		default:
			// No masking - copy file normally using os.Root
			return copyFileWithRootToPath(srcRoot, path, dstPath, info.Mode())
		}
	})
}

// copyFileWithRootToPath copies a file from an os.Root to a destination path.
func copyFileWithRootToPath(srcRoot *os.Root, relPath, dstPath string, mode os.FileMode) error {
	// Open source file through root (traversal-resistant)
	srcFile, err := srcRoot.Open(relPath)
	if err != nil {
		return err
	}
	defer srcFile.Close()

	// Ensure destination directory exists
	if err := os.MkdirAll(filepath.Dir(dstPath), 0755); err != nil {
		return err
	}

	// Create destination file
	dstFile, err := os.OpenFile(dstPath, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	defer dstFile.Close()

	_, err = io.Copy(dstFile, srcFile)
	return err
}

// GenerateDockerIgnore generates a .dockerignore-style list of patterns to exclude.
// Useful for Docker's --ignore option or building exclusion lists.
func (fm *FileMasker) GenerateDockerIgnore() []string {
	var patterns []string
	for _, rule := range fm.rules {
		if rule.mode == sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
			patterns = append(patterns, rule.pattern)
		}
	}
	return patterns
}

// GenerateHiddenPaths returns paths that should be hidden via tmpfs mounts.
// SECURITY: Uses os.Root (Go 1.24+) for traversal-resistant file operations.
// Useful for Docker's --tmpfs option for hiding paths.
func (fm *FileMasker) GenerateHiddenPaths(workspaceDir string) []string {
	var paths []string
	seen := make(map[string]bool)

	// Open workspace as a root for traversal-resistant access
	root, err := os.OpenRoot(workspaceDir)
	if err != nil {
		return nil // Return empty on error
	}
	defer root.Close()

	rootFS := root.FS()

	fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}

		if path == "." {
			return nil
		}

		mode, _ := fm.ShouldMask(path)

		if mode == sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN {
			// For directories, we can hide the entire thing
			if d.IsDir() {
				absPath := filepath.Join("/workspace", path)
				if !seen[absPath] {
					paths = append(paths, absPath)
					seen[absPath] = true
				}
				return fs.SkipDir
			}
			// For files, add the file path
			absPath := filepath.Join("/workspace", path)
			if !seen[absPath] {
				paths = append(paths, absPath)
				seen[absPath] = true
			}
		}

		return nil
	})

	return paths
}

// addPresetRules adds rules from a preset configuration.
func (fm *FileMasker) addPresetRules(preset sandboxv1.FileMaskPreset) {
	switch preset {
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS:
		fm.addSecretsPreset()
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_GIT:
		fm.addGitPreset()
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_IDE:
		fm.addIDEPreset()
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_BUILD_ARTIFACTS:
		fm.addBuildArtifactsPreset()
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_NODE_MODULES:
		fm.addNodeModulesPreset()
	case sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SUPPLY_CHAIN:
		fm.addSupplyChainPreset()
	}
}

func (fm *FileMasker) addSecretsPreset() {
	secretPatterns := []string{
		"**/.env",
		"**/.env.*",
		"**/*.pem",
		"**/*.key",
		"**/*.p12",
		"**/*.pfx",
		"**/id_rsa",
		"**/id_ed25519",
		"**/id_ecdsa",
		"**/.ssh/*",
		"**/credentials.json",
		"**/service-account*.json",
		"**/.npmrc",
		"**/.pypirc",
		"**/.netrc",
		"**/secrets.yaml",
		"**/secrets.yml",
		"**/*secret*",
		"**/*credential*",
		"**/.aws/credentials",
		"**/.aws/config",
	}

	for _, pattern := range secretPatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			reason:  "secrets preset",
		})
	}
}

func (fm *FileMasker) addGitPreset() {
	// Hide git internals except what's needed for commits
	gitHiddenPatterns := []string{
		"**/.git/objects/**",
		"**/.git/hooks/**",
		"**/.git/logs/**",
		"**/.git/refs/stash",
	}

	for _, pattern := range gitHiddenPatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			reason:  "git preset",
		})
	}

	// Make git config read-only
	gitReadOnlyPatterns := []string{
		"**/.git/config",
		"**/.git/HEAD",
		"**/.git/index",
	}

	for _, pattern := range gitReadOnlyPatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
			reason:  "git preset",
		})
	}
}

func (fm *FileMasker) addIDEPreset() {
	idePatterns := []string{
		"**/.vscode/**",
		"**/.idea/**",
		"**/*.swp",
		"**/*.swo",
		"**/*~",
		"**/.DS_Store",
		"**/Thumbs.db",
		"**/*.sublime-*",
	}

	for _, pattern := range idePatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			reason:  "IDE preset",
		})
	}
}

func (fm *FileMasker) addBuildArtifactsPreset() {
	buildPatterns := []string{
		"**/dist/**",
		"**/build/**",
		"**/target/**",
		"**/out/**",
		"**/__pycache__/**",
		"**/*.pyc",
		"**/*.pyo",
		"**/*.class",
		"**/*.o",
		"**/*.obj",
		"**/*.exe",
		"**/*.dll",
		"**/*.so",
		"**/*.dylib",
		"**/coverage/**",
		"**/.coverage",
	}

	for _, pattern := range buildPatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			reason:  "build artifacts preset",
		})
	}
}

func (fm *FileMasker) addNodeModulesPreset() {
	// Hide most of node_modules but allow package metadata
	fm.rules = append(fm.rules, maskRule{
		pattern: "**/node_modules/**",
		mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
		reason:  "node_modules preset",
	})

	// But keep package.json files readable
	fm.config.ExposePatterns = append(fm.config.ExposePatterns,
		"**/node_modules/*/package.json",
	)
}

func (fm *FileMasker) addSupplyChainPreset() {
	// This is the most restrictive preset for AI agents
	fm.addSecretsPreset()
	fm.addBuildArtifactsPreset()
	fm.addIDEPreset()

	// Additional supply chain specific rules
	supplyChainPatterns := []string{
		"**/.git/**",   // Hide all git data
		"**/vendor/**", // Go vendor
		"**/node_modules/**",
		"**/.cache/**",
		"**/tmp/**",
		"**/temp/**",
	}

	for _, pattern := range supplyChainPatterns {
		fm.rules = append(fm.rules, maskRule{
			pattern: pattern,
			mode:    sandboxv1.FileMaskMode_FILE_MASK_MODE_HIDDEN,
			reason:  "supply chain preset",
		})
	}

	// Explicitly expose dependency lockfiles
	lockfiles := []string{
		"**/package-lock.json",
		"**/yarn.lock",
		"**/pnpm-lock.yaml",
		"**/go.sum",
		"**/go.mod",
		"**/Cargo.lock",
		"**/Cargo.toml",
		"**/Gemfile.lock",
		"**/Gemfile",
		"**/poetry.lock",
		"**/pyproject.toml",
		"**/requirements.txt",
		"**/Pipfile.lock",
		"**/composer.lock",
		"**/composer.json",
		"**/pom.xml",
		"**/build.gradle",
		"**/build.gradle.kts",
		"**/mix.lock",
		"**/pubspec.lock",
		"**/packages.config",
		"**/*.csproj",
		"**/*.fsproj",
	}

	fm.config.ExposePatterns = append(fm.config.ExposePatterns, lockfiles...)
}

// matchPattern checks if a path matches a glob pattern.
// Supports ** for recursive matching and common glob patterns.
func matchPattern(path, pattern string) bool {
	// Normalize path separators
	path = filepath.ToSlash(path)
	pattern = filepath.ToSlash(pattern)

	// Handle ** patterns (recursive match)
	if strings.Contains(pattern, "**") {
		return matchDoubleStarPattern(path, pattern)
	}

	// Try matching full path
	if matched, _ := filepath.Match(pattern, path); matched {
		return true
	}

	// Try matching just the filename
	if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
		return true
	}

	// Try matching each path component for directory patterns
	parts := strings.Split(path, "/")
	for i := range parts {
		subPath := strings.Join(parts[i:], "/")
		if matched, _ := filepath.Match(pattern, subPath); matched {
			return true
		}
	}

	return false
}

// matchDoubleStarPattern handles patterns containing **.
// ** matches any sequence of directories (including zero).
func matchDoubleStarPattern(path, pattern string) bool {
	// Split pattern by **
	parts := strings.Split(pattern, "**")

	if len(parts) == 1 {
		// No ** found, shouldn't happen but handle gracefully
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	// Handle common cases: prefix/**/suffix, **/name, name/**
	if len(parts) == 2 {
		prefix := strings.Trim(parts[0], "/")
		suffix := strings.Trim(parts[1], "/")

		// Pattern like "**/.git/**" or "**/node_modules/**"
		// Should match anything containing the middle part

		// Check if we're looking for a specific directory anywhere in path
		if prefix == "" && suffix != "" {
			// Pattern like "**/.git/**" - match paths containing .git/
			// or pattern like "**/package.json" - match any path ending with that
			// Use CutSuffix (Go 1.20+) instead of HasSuffix + TrimSuffix
			if dirName, found := strings.CutSuffix(suffix, "/**"); found {
				// Pattern like "**/.git/**" - look for directory
				return containsPathComponent(path, dirName)
			}
			// Pattern like "**/package.json" - match filename anywhere
			if !strings.Contains(suffix, "/") {
				return matchSimplePattern(filepath.Base(path), suffix)
			}
			// Pattern like "**/dir/file" - check if path ends with this
			return strings.HasSuffix("/"+path, "/"+suffix) ||
				strings.Contains("/"+path+"/", "/"+suffix+"/")
		}

		if prefix != "" && suffix == "" {
			// Pattern like "dir/**" - match paths under dir
			return strings.HasPrefix(path, prefix+"/") || path == prefix
		}

		if prefix != "" && suffix != "" {
			// Pattern like "prefix/**/suffix"
			if !strings.HasPrefix(path, prefix+"/") && path != prefix {
				return false
			}
			// Check if path ends with suffix pattern
			pathAfterPrefix := strings.TrimPrefix(path, prefix+"/")
			return matchPattern(pathAfterPrefix, "**"+suffix)
		}

		// prefix == "" && suffix == "" means pattern is just "**"
		return true
	}

	// Multiple ** in pattern (rare) - handle recursively
	return matchMultipleDoubleStars(path, parts)
}

// containsPathComponent checks if path contains a specific directory component.
// Uses slices.Contains (Go 1.21+) for cleaner code.
func containsPathComponent(path, component string) bool {
	return slices.Contains(strings.Split(path, "/"), component)
}

// matchMultipleDoubleStars handles patterns with multiple ** segments.
func matchMultipleDoubleStars(path string, patternParts []string) bool {
	// Reconstruct and match incrementally
	if len(patternParts) == 0 {
		return true
	}

	first := strings.Trim(patternParts[0], "/")
	if first != "" && !strings.HasPrefix(path, first) {
		return false
	}

	rest := strings.Join(patternParts[1:], "**")
	pathRest := strings.TrimPrefix(path, first)
	pathRest = strings.TrimPrefix(pathRest, "/")

	// Try matching rest of pattern at each position
	// Use range-over-int (Go 1.22+) for cleaner iteration
	parts := strings.Split(pathRest, "/")
	for i := range len(parts) + 1 {
		subPath := strings.Join(parts[i:], "/")
		if matchPattern(subPath, rest) {
			return true
		}
	}

	return false
}

// matchSimplePattern matches simple glob patterns without **.
func matchSimplePattern(path, pattern string) bool {
	matched, _ := filepath.Match(pattern, path)
	return matched
}

// createEmptyFile creates an empty file with the given permissions.
func createEmptyFile(path string, mode os.FileMode) error {
	f, err := os.OpenFile(path, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, mode)
	if err != nil {
		return err
	}
	return f.Close()
}

// DefaultSupplyChainMask returns the default file mask for supply chain security.
func DefaultSupplyChainMask() *sandboxv1.FileMaskConfig {
	return &sandboxv1.FileMaskConfig{
		Presets: []sandboxv1.FileMaskPreset{
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SUPPLY_CHAIN,
		},
	}
}

// DefaultAgentMask returns the default file mask for AI agent execution.
func DefaultAgentMask() *sandboxv1.FileMaskConfig {
	return &sandboxv1.FileMaskConfig{
		DefaultMode: sandboxv1.FileMaskMode_FILE_MASK_MODE_READ_ONLY,
		Presets: []sandboxv1.FileMaskPreset{
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_SECRETS,
			sandboxv1.FileMaskPreset_FILE_MASK_PRESET_IDE,
		},
		ExposePatterns: []string{
			// Common dependency files that agents need to modify
			"**/package.json",
			"**/package-lock.json",
			"**/go.mod",
			"**/go.sum",
			"**/Cargo.toml",
			"**/Cargo.lock",
			"**/pyproject.toml",
			"**/requirements.txt",
			// Source code (allow modifications)
			"**/*.go",
			"**/*.js",
			"**/*.ts",
			"**/*.py",
			"**/*.rs",
			"**/*.java",
			"**/*.rb",
		},
	}
}
