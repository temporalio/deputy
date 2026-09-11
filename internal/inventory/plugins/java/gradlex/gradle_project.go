package gradlex

import (
	"context"
	"fmt"
	"io/fs"
	"maps"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// GradleProjectName is the extractor name for comprehensive Gradle project extraction.
	GradleProjectName = "java/gradleproject"
)

// GradleProjectExtractor provides comprehensive dependency extraction for Gradle projects.
//
// This extractor combines multiple sources of dependency information:
//   - settings.gradle: Identifies multi-module projects
//   - gradle.properties: Version variables
//   - libs.versions.toml: Version catalog (Gradle 7+)
//   - build.gradle: Dependency declarations with variable substitution
//   - gradle.lockfile: Resolved dependencies (if present)
//   - verification-metadata.xml: Verified dependencies (if present)
//
// The extractor prioritizes lockfiles and verification metadata when available,
// falling back to static analysis of build scripts when they're not present.
type GradleProjectExtractor struct{}

// NewGradleProjectExtractor returns a new comprehensive Gradle project extractor.
func NewGradleProjectExtractor() filesystem.Extractor {
	return &GradleProjectExtractor{}
}

// Name returns the extractor name.
func (e *GradleProjectExtractor) Name() string {
	return GradleProjectName
}

// Version returns the extractor version.
func (e *GradleProjectExtractor) Version() int {
	return 0
}

// Requirements returns the extractor's required capabilities.
func (e *GradleProjectExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true for settings.gradle files (project root markers).
// This extractor triggers on the project root and then scans the entire project.
func (e *GradleProjectExtractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "settings.gradle" || base == "settings.gradle.kts"
}

// Extract performs comprehensive dependency extraction for a Gradle project.
func (e *GradleProjectExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.FS == nil {
		return inventory.Inventory{}, nil
	}

	projectDir := filepath.Dir(input.Path)

	// Build comprehensive property map from all sources
	props := make(map[string]string)

	// 1. Load gradle.properties
	if data, err := readFSFile(input.FS, filepath.Join(projectDir, "gradle.properties")); err == nil {
		maps.Copy(props, ParseGradleProperties(data))
	}

	// 2. Load version catalog (check standard location and project root)
	var catalog *VersionCatalog
	for _, catalogPath := range []string{
		filepath.Join(projectDir, "gradle", "libs.versions.toml"),
		filepath.Join(projectDir, "libs.versions.toml"),
	} {
		if data, err := readFSFile(input.FS, catalogPath); err == nil {
			if c, err := ParseVersionCatalog(data); err == nil {
				catalog = c
				// Add catalog versions to props
				for k, v := range c.ToProperties() {
					if _, exists := props[k]; !exists {
						props[k] = v
					}
				}
			}
			break
		}
	}

	// 3. Load ext block from root build.gradle
	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		if data, err := readFSFile(input.FS, filepath.Join(projectDir, buildFile)); err == nil {
			for k, v := range ParseExtBlock(data) {
				if _, exists := props[k]; !exists {
					props[k] = v
				}
			}
			break
		}
	}

	// 4. Check for lockfiles or verification metadata first (most reliable)
	var packages []*extractor.Package

	// Try verification-metadata.xml
	if data, err := readFSFile(input.FS, filepath.Join(projectDir, "gradle", "verification-metadata.xml")); err == nil {
		deps, err := ParseVerificationMetadata(data)
		if err == nil && len(deps) > 0 {
			packages = depsToPackages(deps, filepath.Join(projectDir, "gradle", "verification-metadata.xml"))
			return inventory.Inventory{Packages: packages}, nil
		}
	}

	// Try gradle.lockfile at root
	// (OSV-SCALIBR handles this, but we include for completeness if running standalone)

	// 5. Parse build.gradle files to extract dependencies and BOMs
	deps, boms, err := e.extractFromBuildScripts(ctx, input.FS, projectDir, props)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("extracting from build scripts: %w", err)
	}

	// 6. Add libraries from version catalog if available
	if catalog != nil {
		catalogDeps := catalog.GetLibraries()
		deps = append(deps, catalogDeps...)
	}

	// 7. Resolve BOM-managed versions using deps.dev (if resolver is registered)
	if len(boms) > 0 && defaultBOMVersionResolver != nil {
		deps = defaultBOMVersionResolver.ResolveBOMVersions(ctx, deps, boms)
	}

	// Deduplicate and convert to packages
	packages = depsToPackages(deduplicateDeps(deps), input.Path)

	return inventory.Inventory{Packages: packages}, nil
}

// extractFromBuildScripts walks the project and extracts dependencies and BOMs from all build.gradle files.
func (e *GradleProjectExtractor) extractFromBuildScripts(ctx context.Context, fsys scalibrfs.FS, rootDir string, props map[string]string) ([]MavenDependency, []GradleBOM, error) {
	var allDeps []MavenDependency
	var allBOMs []GradleBOM
	seenBOMs := make(map[string]bool)

	// Find all build.gradle files
	buildFiles, err := findBuildGradleFiles(fsys, rootDir)
	if err != nil {
		return nil, nil, err
	}

	for _, buildFile := range buildFiles {
		data, err := readFSFile(fsys, buildFile)
		if err != nil {
			continue
		}

		// Create a copy of props with any file-specific ext block values
		fileProps := make(map[string]string, len(props))
		maps.Copy(fileProps, props)
		for k, v := range ParseExtBlock(data) {
			if _, exists := fileProps[k]; !exists {
				fileProps[k] = v
			}
		}

		// Extract dependencies
		deps, err := ParseBuildGradle(data, fileProps)
		if err != nil {
			continue
		}
		allDeps = append(allDeps, deps...)

		// Extract BOMs (deduplicated across files)
		boms := ParseBOMs(data, fileProps)
		for _, bom := range boms {
			key := bom.GroupID + ":" + bom.ArtifactID + ":" + bom.Version
			if !seenBOMs[key] {
				seenBOMs[key] = true
				allBOMs = append(allBOMs, bom)
			}
		}
	}

	return allDeps, allBOMs, nil
}

// findBuildGradleFiles locates all build.gradle files in a project.
func findBuildGradleFiles(fsys scalibrfs.FS, rootDir string) ([]string, error) {
	var files []string

	// Check if the FS implements WalkDir
	walker, ok := fsys.(fs.FS)
	if !ok {
		// Fallback: just check root
		for _, name := range []string{"build.gradle", "build.gradle.kts"} {
			path := filepath.Join(rootDir, name)
			if f, err := fsys.Open(path); err == nil {
				f.Close()
				files = append(files, path)
			}
		}
		return files, nil
	}

	err := fs.WalkDir(walker, rootDir, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip errors
		}

		// Skip common non-source directories
		if d.IsDir() {
			name := d.Name()
			if name == ".git" || name == ".gradle" || name == "build" || name == "node_modules" {
				return fs.SkipDir
			}
			return nil
		}

		base := filepath.Base(path)
		if base == "build.gradle" || base == "build.gradle.kts" {
			files = append(files, path)
		}
		return nil
	})

	return files, err
}

// depsToPackages converts MavenDependencies to extractor.Packages.
func depsToPackages(deps []MavenDependency, location string) []*extractor.Package {
	packages := make([]*extractor.Package, 0, len(deps))
	for _, dep := range deps {
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}
		// Skip unresolved versions (still contain variables)
		if strings.Contains(dep.Version, "${") || strings.Contains(dep.Version, "$") {
			continue
		}

		pkg := &extractor.Package{
			Name:     dep.Name(),
			Version:  dep.Version,
			PURLType: purl.TypeMaven,
			Location: extractor.LocationFromPath(location),
			Metadata: &MavenMetadata{
				GroupID:    dep.GroupID,
				ArtifactID: dep.ArtifactID,
				Scope:      dep.Scope,
			},
		}
		packages = append(packages, pkg)
	}
	return packages
}

// deduplicateDeps removes duplicate dependencies, keeping the first occurrence.
func deduplicateDeps(deps []MavenDependency) []MavenDependency {
	seen := make(map[string]bool)
	result := make([]MavenDependency, 0, len(deps))

	for _, dep := range deps {
		key := dep.Coordinate()
		if seen[key] {
			continue
		}
		seen[key] = true
		result = append(result, dep)
	}

	return result
}

// ParseSettingsGradle parses a settings.gradle file to extract project structure.
func ParseSettingsGradle(content []byte) (*GradleSettings, error) {
	settings := &GradleSettings{
		Includes: make([]string, 0),
	}

	// Parse rootProject.name
	rootNamePattern := `rootProject\.name\s*=\s*["']([^"']+)["']`
	if matches := regexp.MustCompile(rootNamePattern).FindSubmatch(content); len(matches) >= 2 {
		settings.RootProjectName = string(matches[1])
	}

	// Parse include statements: include("module1", "module2") or include ':module1', ':module2'
	includePattern := `include\s*\(?["']?:?([^"'\s,\)]+)["']?`
	matches := regexp.MustCompile(includePattern).FindAllSubmatch(content, -1)
	for _, m := range matches {
		if len(m) >= 2 {
			module := strings.TrimPrefix(string(m[1]), ":")
			settings.Includes = append(settings.Includes, module)
		}
	}

	return settings, nil
}

// GradleSettings represents parsed settings.gradle content.
type GradleSettings struct {
	RootProjectName string
	Includes        []string
}

// IsMultiModule returns true if this is a multi-module project.
func (s *GradleSettings) IsMultiModule() bool {
	return len(s.Includes) > 0
}

// Ensure GradleProjectExtractor implements filesystem.Extractor.
var _ filesystem.Extractor = (*GradleProjectExtractor)(nil)

// GradleProject represents a parsed Gradle project with all its configuration.
type GradleProject struct {
	RootDir    string
	Settings   *GradleSettings
	Properties map[string]string
	Catalog    *VersionCatalog
	Modules    map[string]*GradleModule
}

// GradleModule represents a single module in a Gradle project.
type GradleModule struct {
	Name         string
	Path         string
	Dependencies []MavenDependency
}

// LoadGradleProject loads a complete Gradle project from a filesystem.
func LoadGradleProject(ctx context.Context, fsys scalibrfs.FS, rootDir string) (*GradleProject, error) {
	project := &GradleProject{
		RootDir:    rootDir,
		Properties: make(map[string]string),
		Modules:    make(map[string]*GradleModule),
	}

	// Load settings.gradle
	for _, settingsFile := range []string{"settings.gradle", "settings.gradle.kts"} {
		path := filepath.Join(rootDir, settingsFile)
		if data, err := readFSFile(fsys, path); err == nil {
			settings, err := ParseSettingsGradle(data)
			if err == nil {
				project.Settings = settings
			}
			break
		}
	}

	// Load gradle.properties
	if data, err := readFSFile(fsys, filepath.Join(rootDir, "gradle.properties")); err == nil {
		project.Properties = ParseGradleProperties(data)
	}

	// Load version catalog
	for _, catalogPath := range []string{
		filepath.Join(rootDir, "gradle", "libs.versions.toml"),
	} {
		if data, err := readFSFile(fsys, catalogPath); err == nil {
			if catalog, err := ParseVersionCatalog(data); err == nil {
				project.Catalog = catalog
				for k, v := range catalog.ToProperties() {
					if _, exists := project.Properties[k]; !exists {
						project.Properties[k] = v
					}
				}
			}
			break
		}
	}

	// Load root build.gradle ext block
	for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
		if data, err := readFSFile(fsys, filepath.Join(rootDir, buildFile)); err == nil {
			for k, v := range ParseExtBlock(data) {
				if _, exists := project.Properties[k]; !exists {
					project.Properties[k] = v
				}
			}
			break
		}
	}

	// Load each module
	modulePaths := []string{rootDir}
	if project.Settings != nil {
		for _, include := range project.Settings.Includes {
			modulePath := filepath.Join(rootDir, strings.ReplaceAll(include, ":", string(filepath.Separator)))
			modulePaths = append(modulePaths, modulePath)
		}
	}

	for _, modulePath := range modulePaths {
		module := &GradleModule{
			Name: filepath.Base(modulePath),
			Path: modulePath,
		}

		for _, buildFile := range []string{"build.gradle", "build.gradle.kts"} {
			buildPath := filepath.Join(modulePath, buildFile)
			if data, err := readFSFile(fsys, buildPath); err == nil {
				deps, _ := ParseBuildGradle(data, project.Properties)
				module.Dependencies = deps
				break
			}
		}

		project.Modules[module.Name] = module
	}

	return project, nil
}

// AllDependencies returns all dependencies from all modules, deduplicated.
func (p *GradleProject) AllDependencies() []MavenDependency {
	var all []MavenDependency
	for _, module := range p.Modules {
		all = append(all, module.Dependencies...)
	}
	return deduplicateDeps(all)
}

// ResolvedDependencies returns dependencies with all versions resolved.
// Dependencies with unresolved variables are filtered out.
func (p *GradleProject) ResolvedDependencies() []MavenDependency {
	all := p.AllDependencies()
	resolved := make([]MavenDependency, 0, len(all))

	for _, dep := range all {
		if dep.IsResolved() {
			resolved = append(resolved, dep)
		}
	}

	return resolved
}
