package gradlex

import (
	"bufio"
	"bytes"
	"fmt"
	"regexp"
	"strings"
)

// VersionCatalog represents a parsed Gradle version catalog (libs.versions.toml).
//
// Version catalogs are Gradle's modern way of centralizing dependency versions.
// They contain four sections:
//   - [versions]: Version constants that can be referenced elsewhere
//   - [libraries]: Dependency declarations with group, name, and version
//   - [bundles]: Groups of libraries that can be added together
//   - [plugins]: Gradle plugin declarations
type VersionCatalog struct {
	Versions  map[string]string         // version aliases -> version strings
	Libraries map[string]CatalogLibrary // library aliases -> library definitions
	Bundles   map[string][]string       // bundle names -> list of library aliases
	Plugins   map[string]CatalogPlugin  // plugin aliases -> plugin definitions
}

// CatalogLibrary represents a library in the version catalog.
type CatalogLibrary struct {
	Group   string
	Name    string
	Version string // resolved version or version.ref
}

// CatalogPlugin represents a plugin in the version catalog.
type CatalogPlugin struct {
	ID      string
	Version string
}

// ParseVersionCatalog parses a libs.versions.toml file.
//
// Example format:
//
//	[versions]
//	kotlin = "1.9.0"
//	grpc = "1.58.1"
//
//	[libraries]
//	grpc-api = { group = "io.grpc", name = "grpc-api", version.ref = "grpc" }
//	kotlin-stdlib = "org.jetbrains.kotlin:kotlin-stdlib:1.9.0"
//
//	[bundles]
//	grpc = ["grpc-api", "grpc-stub"]
//
//	[plugins]
//	kotlin-jvm = { id = "org.jetbrains.kotlin.jvm", version.ref = "kotlin" }
func ParseVersionCatalog(content []byte) (*VersionCatalog, error) {
	catalog := &VersionCatalog{
		Versions:  make(map[string]string),
		Libraries: make(map[string]CatalogLibrary),
		Bundles:   make(map[string][]string),
		Plugins:   make(map[string]CatalogPlugin),
	}

	scanner := bufio.NewScanner(bytes.NewReader(content))
	currentSection := ""

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip empty lines and comments
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Detect section headers
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			currentSection = strings.Trim(line, "[]")
			continue
		}

		// Parse based on current section
		switch currentSection {
		case "versions":
			parseVersionLine(line, catalog)
		case "libraries":
			parseLibraryLine(line, catalog)
		case "bundles":
			parseBundleLine(line, catalog)
		case "plugins":
			parsePluginLine(line, catalog)
		}
	}

	// Resolve version references in libraries
	for alias, lib := range catalog.Libraries {
		if strings.HasPrefix(lib.Version, "ref:") {
			ref := strings.TrimPrefix(lib.Version, "ref:")
			if resolved, ok := catalog.Versions[ref]; ok {
				lib.Version = resolved
				catalog.Libraries[alias] = lib
			}
		}
	}

	// Resolve version references in plugins
	for alias, plugin := range catalog.Plugins {
		if strings.HasPrefix(plugin.Version, "ref:") {
			ref := strings.TrimPrefix(plugin.Version, "ref:")
			if resolved, ok := catalog.Versions[ref]; ok {
				plugin.Version = resolved
				catalog.Plugins[alias] = plugin
			}
		}
	}

	return catalog, scanner.Err()
}

// Regex patterns for TOML parsing
var (
	// key = "value" or key = 'value'
	tomlStringPattern = regexp.MustCompile(`^(\S+)\s*=\s*["']([^"']+)["']`)

	// key = { ... } inline table
	tomlInlineTablePattern = regexp.MustCompile(`^(\S+)\s*=\s*\{([^}]+)\}`)

	// key = [...] array
	tomlArrayPattern = regexp.MustCompile(`^(\S+)\s*=\s*\[([^\]]+)\]`)

	// group = "value" inside inline table
	tomlGroupPattern = regexp.MustCompile(`group\s*=\s*["']([^"']+)["']`)
	tomlNamePattern  = regexp.MustCompile(`name\s*=\s*["']([^"']+)["']`)

	// version = "value" or version.ref = "value"
	tomlVersionPattern    = regexp.MustCompile(`(?:^|,\s*)version\s*=\s*["']([^"']+)["']`)
	tomlVersionRefPattern = regexp.MustCompile(`version\.ref\s*=\s*["']([^"']+)["']`)

	// id = "value" for plugins
	tomlIDPattern = regexp.MustCompile(`id\s*=\s*["']([^"']+)["']`)

	// module = "group:name" shorthand
	tomlModulePattern = regexp.MustCompile(`module\s*=\s*["']([^"':]+):([^"']+)["']`)
)

// parseVersionLine parses a line from the [versions] section.
func parseVersionLine(line string, catalog *VersionCatalog) {
	match := tomlStringPattern.FindStringSubmatch(line)
	if len(match) >= 3 {
		catalog.Versions[match[1]] = match[2]
	}
}

// parseLibraryLine parses a line from the [libraries] section.
func parseLibraryLine(line string, catalog *VersionCatalog) {
	// Try inline table format: lib = { group = "...", name = "...", version = "..." }
	tableMatch := tomlInlineTablePattern.FindStringSubmatch(line)
	if len(tableMatch) >= 3 {
		alias := tableMatch[1]
		tableContent := tableMatch[2]

		lib := CatalogLibrary{}

		// Check for module shorthand first
		moduleMatch := tomlModulePattern.FindStringSubmatch(tableContent)
		if len(moduleMatch) >= 3 {
			lib.Group = moduleMatch[1]
			lib.Name = moduleMatch[2]
		} else {
			// Parse group and name separately
			groupMatch := tomlGroupPattern.FindStringSubmatch(tableContent)
			if len(groupMatch) >= 2 {
				lib.Group = groupMatch[1]
			}
			nameMatch := tomlNamePattern.FindStringSubmatch(tableContent)
			if len(nameMatch) >= 2 {
				lib.Name = nameMatch[1]
			}
		}

		// Parse version (direct or ref)
		versionRefMatch := tomlVersionRefPattern.FindStringSubmatch(tableContent)
		if len(versionRefMatch) >= 2 {
			lib.Version = "ref:" + versionRefMatch[1]
		} else {
			versionMatch := tomlVersionPattern.FindStringSubmatch(tableContent)
			if len(versionMatch) >= 2 {
				lib.Version = versionMatch[1]
			}
		}

		if lib.Group != "" && lib.Name != "" {
			catalog.Libraries[alias] = lib
		}
		return
	}

	// Try string shorthand format: lib = "group:name:version"
	stringMatch := tomlStringPattern.FindStringSubmatch(line)
	if len(stringMatch) >= 3 {
		alias := stringMatch[1]
		coordinate := stringMatch[2]

		parts := strings.Split(coordinate, ":")
		if len(parts) >= 2 {
			lib := CatalogLibrary{
				Group: parts[0],
				Name:  parts[1],
			}
			if len(parts) >= 3 {
				lib.Version = parts[2]
			}
			catalog.Libraries[alias] = lib
		}
	}
}

// parseBundleLine parses a line from the [bundles] section.
func parseBundleLine(line string, catalog *VersionCatalog) {
	arrayMatch := tomlArrayPattern.FindStringSubmatch(line)
	if len(arrayMatch) >= 3 {
		bundleName := arrayMatch[1]
		arrayContent := arrayMatch[2]

		// Parse array elements
		var elements []string
		// Match quoted strings in the array
		elementPattern := regexp.MustCompile(`["']([^"']+)["']`)
		matches := elementPattern.FindAllStringSubmatch(arrayContent, -1)
		for _, m := range matches {
			if len(m) >= 2 {
				elements = append(elements, m[1])
			}
		}

		if len(elements) > 0 {
			catalog.Bundles[bundleName] = elements
		}
	}
}

// parsePluginLine parses a line from the [plugins] section.
func parsePluginLine(line string, catalog *VersionCatalog) {
	// Try inline table format: plugin = { id = "...", version = "..." }
	tableMatch := tomlInlineTablePattern.FindStringSubmatch(line)
	if len(tableMatch) >= 3 {
		alias := tableMatch[1]
		tableContent := tableMatch[2]

		plugin := CatalogPlugin{}

		idMatch := tomlIDPattern.FindStringSubmatch(tableContent)
		if len(idMatch) >= 2 {
			plugin.ID = idMatch[1]
		}

		versionRefMatch := tomlVersionRefPattern.FindStringSubmatch(tableContent)
		if len(versionRefMatch) >= 2 {
			plugin.Version = "ref:" + versionRefMatch[1]
		} else {
			versionMatch := tomlVersionPattern.FindStringSubmatch(tableContent)
			if len(versionMatch) >= 2 {
				plugin.Version = versionMatch[1]
			}
		}

		if plugin.ID != "" {
			catalog.Plugins[alias] = plugin
		}
	}
}

// GetLibraries returns all libraries with resolved versions as MavenDependencies.
func (c *VersionCatalog) GetLibraries() []MavenDependency {
	deps := make([]MavenDependency, 0, len(c.Libraries))
	for _, lib := range c.Libraries {
		if lib.Group == "" || lib.Name == "" {
			continue
		}
		deps = append(deps, MavenDependency{
			GroupID:    lib.Group,
			ArtifactID: lib.Name,
			Version:    lib.Version,
		})
	}
	return deps
}

// GetBundleLibraries returns all libraries in a bundle.
func (c *VersionCatalog) GetBundleLibraries(bundleName string) []MavenDependency {
	aliases, ok := c.Bundles[bundleName]
	if !ok {
		return nil
	}

	deps := make([]MavenDependency, 0, len(aliases))
	for _, alias := range aliases {
		lib, ok := c.Libraries[alias]
		if !ok {
			continue
		}
		deps = append(deps, MavenDependency{
			GroupID:    lib.Group,
			ArtifactID: lib.Name,
			Version:    lib.Version,
		})
	}
	return deps
}

// ToProperties returns version catalog versions as a properties map.
// This can be used to resolve version references in build.gradle files.
func (c *VersionCatalog) ToProperties() map[string]string {
	props := make(map[string]string, len(c.Versions))
	for k, v := range c.Versions {
		props[k] = v
		// Also add with "Version" suffix for common patterns
		props[k+"Version"] = v
	}
	return props
}

// String returns a human-readable representation of the catalog.
func (c *VersionCatalog) String() string {
	var b strings.Builder
	fmt.Fprintf(&b, "VersionCatalog:\n")
	fmt.Fprintf(&b, "  Versions: %d\n", len(c.Versions))
	fmt.Fprintf(&b, "  Libraries: %d\n", len(c.Libraries))
	fmt.Fprintf(&b, "  Bundles: %d\n", len(c.Bundles))
	fmt.Fprintf(&b, "  Plugins: %d\n", len(c.Plugins))
	return b.String()
}
