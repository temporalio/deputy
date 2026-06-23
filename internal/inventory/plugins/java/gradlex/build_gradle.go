package gradlex

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
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

	"github.com/temporalio/deputy/internal/logs"
)

// BOMVersionResolver resolves dependency versions from BOMs.
// This interface allows the graph package to register a resolver
// without creating an import cycle.
type BOMVersionResolver interface {
	// ResolveBOMVersions resolves versions for dependencies that are missing versions
	// by looking them up in the provided BOMs.
	ResolveBOMVersions(ctx context.Context, deps []MavenDependency, boms []GradleBOM) []MavenDependency
}

// defaultBOMVersionResolver is the registered BOM version resolver.
// It's set by the graph package during initialization.
var defaultBOMVersionResolver BOMVersionResolver

// RegisterBOMVersionResolver registers a BOM version resolver.
// This should be called by the graph package to enable BOM resolution.
func RegisterBOMVersionResolver(resolver BOMVersionResolver) {
	defaultBOMVersionResolver = resolver
}

const (
	// BuildGradleName is the extractor name for build.gradle files.
	BuildGradleName = "java/buildgradle"
)

// BuildGradleExtractor extracts Maven dependencies from Gradle build scripts.
//
// This extractor performs static analysis of build.gradle and build.gradle.kts files
// to identify dependency declarations. It handles common patterns including:
//
//   - Standard dependency configurations: implementation, api, compileOnly, etc.
//   - String notation: implementation "group:artifact:version"
//   - Map notation: implementation group: 'g', name: 'a', version: 'v'
//   - Platform/BOM imports: implementation platform("group:artifact:version")
//   - Project dependencies: implementation project(":module")
//   - Version variables: implementation "group:artifact:$version"
//
// Version variables are resolved using companion files (gradle.properties, ext blocks).
// Unresolved variables are reported with the variable name for later resolution.
type BuildGradleExtractor struct{}

// NewBuildGradleExtractor returns a new build.gradle extractor.
func NewBuildGradleExtractor() *BuildGradleExtractor {
	return &BuildGradleExtractor{}
}

// Name returns the extractor name.
func (e *BuildGradleExtractor) Name() string {
	return BuildGradleName
}

// Version returns the extractor version.
func (e *BuildGradleExtractor) Version() int {
	return 0
}

// Requirements returns the extractor's required capabilities.
func (e *BuildGradleExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired returns true if the file is a Gradle build script.
func (e *BuildGradleExtractor) FileRequired(api filesystem.FileAPI) bool {
	base := filepath.Base(api.Path())
	return base == "build.gradle" || base == "build.gradle.kts"
}

// Extract parses a build.gradle file and returns discovered dependencies.
func (e *BuildGradleExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}

	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("reading build.gradle: %w", err)
	}

	// Load properties from the project for variable resolution
	props := e.loadProjectProperties(input.FS, input.Path)

	// Parse dependencies from the build script
	deps, err := ParseBuildGradle(data, props)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("parsing build.gradle: %w", err)
	}

	// Parse BOMs from the build script and resolve versions using deps.dev
	boms := ParseBOMs(data, props)
	if len(boms) > 0 && defaultBOMVersionResolver != nil {
		deps = defaultBOMVersionResolver.ResolveBOMVersions(ctx, deps, boms)
	}

	packages := make([]*extractor.Package, 0, len(deps))
	seen := make(map[string]bool)

	// Track unresolved dependencies for logging
	var unresolvedVars, bomManaged int

	for _, dep := range deps {
		// Skip project dependencies (internal modules)
		if dep.GroupID == "" && strings.HasPrefix(dep.ArtifactID, ":") {
			continue
		}

		// Skip dependencies without resolved coordinates
		if dep.GroupID == "" || dep.ArtifactID == "" {
			continue
		}

		// Deduplicate
		key := dep.Coordinate()
		if seen[key] {
			continue
		}
		seen[key] = true

		// Track resolution status for debug logging
		if !dep.IsResolved() {
			if strings.Contains(dep.Version, "$") {
				unresolvedVars++
				logs.Debug(ctx, "gradle: unresolved version variable",
					"dependency", dep.Name(),
					"version", dep.Version,
					"file", input.Path,
				)
			} else if dep.Version == "" {
				bomManaged++
				logs.Debug(ctx, "gradle: BOM-managed dependency (version from platform)",
					"dependency", dep.Name(),
					"file", input.Path,
				)
			}
		}

		pkg := &extractor.Package{
			Name:      dep.Name(),
			Version:   dep.Version,
			PURLType:  purl.TypeMaven,
			Locations: []string{input.Path},
			Metadata: &MavenMetadata{
				GroupID:    dep.GroupID,
				ArtifactID: dep.ArtifactID,
				Scope:      dep.Scope,
			},
		}
		packages = append(packages, pkg)
	}

	// Log summary at debug level for audit purposes
	if unresolvedVars > 0 || bomManaged > 0 {
		logs.Debug(ctx, "gradle: extraction summary",
			"file", input.Path,
			"total", len(packages),
			"unresolved_variables", unresolvedVars,
			"bom_managed", bomManaged,
		)
	}

	return inventory.Inventory{Packages: packages}, nil
}

// loadProjectProperties loads version properties from gradle.properties and root build.gradle.
func (e *BuildGradleExtractor) loadProjectProperties(fs scalibrfs.FS, buildPath string) map[string]string {
	props := make(map[string]string)
	if fs == nil {
		return props
	}

	// Try to find and load gradle.properties
	dir := filepath.Dir(buildPath)
	propsFile := filepath.Join(dir, "gradle.properties")
	if data, err := readFSFile(fs, propsFile); err == nil {
		maps.Copy(props, ParseGradleProperties(data))
	}

	// Also check root gradle.properties
	if data, err := readFSFile(fs, "gradle.properties"); err == nil {
		maps.Copy(props, ParseGradleProperties(data))
	}

	// Try to extract ext {} block from root build.gradle
	if data, err := readFSFile(fs, "build.gradle"); err == nil {
		maps.Copy(props, ParseExtBlock(data))
	}

	return props
}

// readFSFile reads a file from the scalibr filesystem.
func readFSFile(fs scalibrfs.FS, path string) ([]byte, error) {
	f, err := fs.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// Ensure BuildGradleExtractor implements filesystem.Extractor.
var _ filesystem.Extractor = (*BuildGradleExtractor)(nil)

// Common Gradle dependency configurations.
var gradleConfigurations = []string{
	"implementation",
	"api",
	"compileOnly",
	"compileOnlyApi",
	"runtimeOnly",
	"testImplementation",
	"testCompileOnly",
	"testRuntimeOnly",
	"annotationProcessor",
	"kapt",
	"ksp",
	"classpath",
}

// Regex patterns for dependency extraction.
var (
	// String notation: implementation "group:artifact:version" or implementation("group:artifact:version")
	// Matches: "group:artifact:version" or "group:artifact" (no version)
	stringDepPattern = regexp.MustCompile(`["']([^"':]+):([^"':]+)(?::([^"']+))?["']`)

	// Map notation: implementation group: 'g', name: 'n', version: 'v'
	mapGroupPattern      = regexp.MustCompile(`group\s*[:=]\s*["']([^"']+)["']`)
	mapNamePattern       = regexp.MustCompile(`name\s*[:=]\s*["']([^"']+)["']`)
	mapVersionPattern    = regexp.MustCompile(`version\s*[:=]\s*["']([^"']+)["']`)
	mapVersionVarPattern = regexp.MustCompile(`version\s*[:=]\s*(\$?\w+(?:\.\w+)*)`)

	// Project dependency: implementation project(":module")
	projectDepPattern = regexp.MustCompile(`project\s*\(\s*["']:?([^"']+)["']\s*\)`)

	// Version variable: $version, ${version}, $rootProject.ext.version
	versionVarPattern = regexp.MustCompile(`\$\{?(\w+(?:\.\w+)*)\}?`)

	// ext block: ext { version = "1.0" } or ext.version = "1.0"
	extBlockPattern   = regexp.MustCompile(`ext\s*\{([^}]+)\}`)
	extPropPattern    = regexp.MustCompile(`(\w+)\s*=\s*["']([^"']+)["']`)
	extPropVarPattern = regexp.MustCompile(`ext\.(\w+)\s*=\s*["']([^"']+)["']`)

	// BOM/Platform patterns:
	// Groovy: implementation platform("group:artifact:version")
	// Groovy: implementation enforcedPlatform("group:artifact:version")
	// Kotlin: implementation(platform("group:artifact:version"))
	// Kotlin: implementation(enforcedPlatform("group:artifact:version"))
	platformPattern = regexp.MustCompile(`(?:enforced)?[Pp]latform\s*\(\s*["']([^"':]+):([^"':]+):([^"']+)["']\s*\)`)

	// Spring Boot plugin: id 'org.springframework.boot' version '3.2.0'
	// Kotlin notation: id("org.springframework.boot") version "3.2.0"
	pluginPattern = regexp.MustCompile(`id\s*\(?["']([^"']+)["']\)?\s*(?:version\s*["']([^"']+)["'])?`)
)

// ParseBuildGradle parses a build.gradle file and extracts dependencies.
// The props map is used for variable substitution.
func ParseBuildGradle(content []byte, props map[string]string) ([]MavenDependency, error) {
	if props == nil {
		props = make(map[string]string)
	}

	// First, extract any ext {} block properties from this file
	for k, v := range ParseExtBlock(content) {
		if _, exists := props[k]; !exists {
			props[k] = v
		}
	}

	var deps []MavenDependency
	scanner := bufio.NewScanner(bytes.NewReader(content))

	// Track if we're inside a dependencies block
	inDependencies := false
	braceDepth := 0
	currentConfig := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments
		if strings.HasPrefix(line, "//") || strings.HasPrefix(line, "/*") || strings.HasPrefix(line, "*") {
			continue
		}

		// Track dependencies block
		if strings.Contains(line, "dependencies") && strings.Contains(line, "{") {
			inDependencies = true
			braceDepth = 1
			continue
		}

		if inDependencies {
			braceDepth += strings.Count(line, "{") - strings.Count(line, "}")
			if braceDepth <= 0 {
				inDependencies = false
				continue
			}

			// Check for dependency configurations
			for _, config := range gradleConfigurations {
				if strings.HasPrefix(line, config) || strings.Contains(line, config+"(") || strings.Contains(line, config+" ") {
					currentConfig = config
					break
				}
			}

			// Extract dependencies from this line
			lineDeps := extractDependenciesFromLine(line, currentConfig, props)
			deps = append(deps, lineDeps...)
		}
	}

	return deps, scanner.Err()
}

// extractDependenciesFromLine extracts dependencies from a single line of build.gradle.
func extractDependenciesFromLine(line, config string, props map[string]string) []MavenDependency {
	var deps []MavenDependency

	// Check for project dependencies first (to skip them)
	if projectDepPattern.MatchString(line) {
		return deps
	}

	// Check for map notation first: group: 'g', name: 'n', version: 'v'
	// This takes priority because string notation regex can accidentally match
	// individual values in map notation
	groupMatch := mapGroupPattern.FindStringSubmatch(line)
	nameMatch := mapNamePattern.FindStringSubmatch(line)
	if len(groupMatch) >= 2 && len(nameMatch) >= 2 {
		dep := MavenDependency{
			GroupID:    groupMatch[1],
			ArtifactID: nameMatch[1],
			Scope:      mapConfigToScope(config),
		}
		// Try quoted version first
		versionMatch := mapVersionPattern.FindStringSubmatch(line)
		if len(versionMatch) >= 2 {
			dep.Version = resolveVersion(versionMatch[1], props)
		} else {
			// Try variable version
			versionVarMatch := mapVersionVarPattern.FindStringSubmatch(line)
			if len(versionVarMatch) >= 2 {
				dep.Version = resolveVersion(versionVarMatch[1], props)
			}
		}
		return []MavenDependency{dep}
	}

	// Try string notation: "group:artifact:version"
	matches := stringDepPattern.FindAllStringSubmatch(line, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			group := strings.TrimSpace(m[1])
			artifact := strings.TrimSpace(m[2])

			// Skip invalid Maven coordinates
			if !isValidMavenCoordinate(group, artifact) {
				continue
			}

			dep := MavenDependency{
				GroupID:    group,
				ArtifactID: artifact,
				Scope:      mapConfigToScope(config),
			}
			if len(m) >= 4 && m[3] != "" {
				dep.Version = resolveVersion(m[3], props)
			}
			deps = append(deps, dep)
		}
	}

	return deps
}

// isValidMavenCoordinate validates that group and artifact look like valid Maven coordinates.
func isValidMavenCoordinate(group, artifact string) bool {
	// Must have both group and artifact
	if group == "" || artifact == "" {
		return false
	}

	// Group should contain a dot (like com.example) or be a known short groupId (like junit)
	// Filter out things that look like exclusion syntax fragments
	if strings.Contains(group, ",") || strings.Contains(group, " ") {
		return false
	}
	if strings.Contains(artifact, ",") || strings.Contains(artifact, " ") {
		return false
	}

	// Group should have a dot or be at least 3 characters
	if !strings.Contains(group, ".") && len(group) < 3 {
		return false
	}

	// Artifact should be a reasonable identifier
	if len(artifact) < 2 {
		return false
	}

	return true
}

// resolveVersion resolves version variables using the properties map.
func resolveVersion(version string, props map[string]string) string {
	if version == "" {
		return ""
	}

	// Handle ${variable} or $variable syntax
	resolved := versionVarPattern.ReplaceAllStringFunc(version, func(match string) string {
		// Extract variable name
		varMatch := versionVarPattern.FindStringSubmatch(match)
		if len(varMatch) < 2 {
			return match
		}
		varName := varMatch[1]

		// Try direct lookup
		if val, ok := props[varName]; ok {
			return val
		}

		// Try without prefix (e.g., "rootProject.ext.version" -> "version")
		parts := strings.Split(varName, ".")
		shortName := parts[len(parts)-1]
		if val, ok := props[shortName]; ok {
			return val
		}

		// Return original if not found
		return match
	})

	return resolved
}

// mapConfigToScope maps Gradle configuration names to Maven scopes.
func mapConfigToScope(config string) string {
	switch config {
	case "implementation", "api":
		return "compile"
	case "compileOnly", "compileOnlyApi":
		return "provided"
	case "runtimeOnly":
		return "runtime"
	case "testImplementation", "testCompileOnly", "testRuntimeOnly":
		return "test"
	default:
		return "compile"
	}
}

// ParseExtBlock extracts property definitions from Gradle ext {} blocks.
func ParseExtBlock(content []byte) map[string]string {
	props := make(map[string]string)

	// Find ext { ... } blocks
	extMatches := extBlockPattern.FindAllSubmatch(content, -1)
	for _, extMatch := range extMatches {
		if len(extMatch) >= 2 {
			blockContent := extMatch[1]
			propMatches := extPropPattern.FindAllSubmatch(blockContent, -1)
			for _, propMatch := range propMatches {
				if len(propMatch) >= 3 {
					props[string(propMatch[1])] = string(propMatch[2])
				}
			}
		}
	}

	// Find ext.property = "value" style
	extPropMatches := extPropVarPattern.FindAllSubmatch(content, -1)
	for _, m := range extPropMatches {
		if len(m) >= 3 {
			props[string(m[1])] = string(m[2])
		}
	}

	return props
}

// ParseGradleProperties parses a gradle.properties file.
func ParseGradleProperties(content []byte) map[string]string {
	props := make(map[string]string)
	scanner := bufio.NewScanner(bytes.NewReader(content))

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") || strings.HasPrefix(line, "!") {
			continue
		}

		// Handle continuation lines (ending with \)
		for strings.HasSuffix(line, "\\") && scanner.Scan() {
			line = strings.TrimSuffix(line, "\\") + strings.TrimSpace(scanner.Text())
		}

		// Parse key=value or key:value
		var key, value string
		if before, after, ok := strings.Cut(line, "="); ok {
			key = strings.TrimSpace(before)
			value = strings.TrimSpace(after)
		} else if before, after, ok := strings.Cut(line, ":"); ok {
			key = strings.TrimSpace(before)
			value = strings.TrimSpace(after)
		} else {
			continue
		}

		// Skip system properties (systemProp.*)
		if strings.HasPrefix(key, "systemProp.") {
			continue
		}

		props[key] = value
	}

	return props
}

// GradleBOM represents a detected BOM (Bill of Materials) in a Gradle project.
type GradleBOM struct {
	GroupID    string
	ArtifactID string
	Version    string
	Source     string // "platform", "plugin", or "catalog"
}

// ParseBOMs extracts all BOMs from a build.gradle file.
// It detects BOMs from:
//   - platform("group:artifact:version") declarations
//   - enforcedPlatform("group:artifact:version") declarations
//   - Known Gradle plugins (e.g., org.springframework.boot)
func ParseBOMs(content []byte, props map[string]string) []GradleBOM {
	if props == nil {
		props = make(map[string]string)
	}

	var boms []GradleBOM
	seen := make(map[string]bool)

	// Extract platform() declarations
	matches := platformPattern.FindAllSubmatch(content, -1)
	for _, m := range matches {
		if len(m) >= 3 {
			groupID := string(m[1])
			artifactID := string(m[2])
			version := ""
			if len(m) >= 4 {
				version = resolveVersion(string(m[3]), props)
			}

			key := groupID + ":" + artifactID
			if !seen[key] && version != "" && !strings.Contains(version, "$") {
				seen[key] = true
				boms = append(boms, GradleBOM{
					GroupID:    groupID,
					ArtifactID: artifactID,
					Version:    version,
					Source:     "platform",
				})
			}
		}
	}

	// Extract plugins that imply BOMs
	pluginMatches := pluginPattern.FindAllSubmatch(content, -1)
	for _, m := range pluginMatches {
		if len(m) >= 2 {
			pluginID := string(m[1])
			version := ""
			if len(m) >= 3 {
				version = resolveVersion(string(m[2]), props)
			}

			// Check for known plugins that map to BOMs
			bom := pluginToBOM(pluginID, version)
			if bom != nil && bom.Version != "" && !strings.Contains(bom.Version, "$") {
				key := bom.GroupID + ":" + bom.ArtifactID
				if !seen[key] {
					seen[key] = true
					boms = append(boms, *bom)
				}
			}
		}
	}

	return boms
}

// pluginToBOM maps a Gradle plugin ID to its corresponding BOM.
func pluginToBOM(pluginID, version string) *GradleBOM {
	switch pluginID {
	case "org.springframework.boot":
		return &GradleBOM{
			GroupID:    "org.springframework.boot",
			ArtifactID: "spring-boot-dependencies",
			Version:    version,
			Source:     "plugin",
		}
	case "io.spring.dependency-management":
		// This plugin alone doesn't imply a BOM; it's used with Spring Boot
		return nil
	case "io.quarkus":
		return &GradleBOM{
			GroupID:    "io.quarkus.platform",
			ArtifactID: "quarkus-bom",
			Version:    version,
			Source:     "plugin",
		}
	case "io.micronaut.application", "io.micronaut.library":
		return &GradleBOM{
			GroupID:    "io.micronaut.platform",
			ArtifactID: "micronaut-platform",
			Version:    version,
			Source:     "plugin",
		}
	default:
		return nil
	}
}
