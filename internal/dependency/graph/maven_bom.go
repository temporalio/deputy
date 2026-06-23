package graph

import (
	"context"
	"fmt"
	"maps"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	"github.com/temporalio/deputy/internal/cache/memory"
)

// MavenBOMResolver resolves Maven BOM (Bill of Materials) dependency management
// using the deps.dev API. It provides fast, accurate version resolution for
// dependencies managed by published BOMs like Spring Boot, gRPC, and others.
//
// The resolver handles:
//   - Recursive BOM imports (e.g., Spring Boot imports Jackson BOM)
//   - Property interpolation (e.g., ${jackson.version} -> 2.15.3)
//   - Caching to minimize API calls
//
// Limitations:
//   - Only works for published artifacts (not SNAPSHOT or local)
//   - Cannot resolve custom property overrides in build files
//   - Requires network access to deps.dev
type MavenBOMResolver struct {
	client *DepsDevClient

	// requirementsCache caches GetRequirements responses
	requirementsCache *memory.TTLCache[string, *pb.Requirements]

	// resolvedBOMCache caches fully resolved BOM data (with property interpolation done)
	resolvedBOMCache *memory.TTLCache[string, *ResolvedBOM]

	// mu protects concurrent BOM resolution to avoid duplicate work
	mu sync.Mutex
}

// ResolvedBOM contains the fully resolved dependency management from a BOM.
type ResolvedBOM struct {
	// ManagedVersions maps "groupId:artifactId" to resolved version
	ManagedVersions map[string]string

	// Properties maps property names to resolved values
	Properties map[string]string
}

// NewMavenBOMResolver creates a new BOM resolver using the provided deps.dev client.
func NewMavenBOMResolver(client *DepsDevClient) *MavenBOMResolver {
	return &MavenBOMResolver{
		client:            client,
		requirementsCache: memory.NewTTLCache[string, *pb.Requirements](1024, defaultDepsDevCacheTTL),
		resolvedBOMCache:  memory.NewTTLCache[string, *ResolvedBOM](256, defaultDepsDevCacheTTL),
	}
}

// ResolveBOM fetches and resolves a BOM, returning all managed versions.
// The coordinate should be in the format "groupId:artifactId:version".
func (r *MavenBOMResolver) ResolveBOM(ctx context.Context, groupID, artifactID, version string) (*ResolvedBOM, error) {
	cacheKey := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)

	// Check cache first
	if resolved, ok := r.resolvedBOMCache.Get(cacheKey); ok {
		return resolved, nil
	}

	// Use mutex to prevent duplicate resolution of the same BOM
	r.mu.Lock()
	defer r.mu.Unlock()

	// Double-check after acquiring lock
	if resolved, ok := r.resolvedBOMCache.Get(cacheKey); ok {
		return resolved, nil
	}

	// Resolve the BOM recursively
	resolved, err := r.resolveBOMRecursive(ctx, groupID, artifactID, version, make(map[string]bool))
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.resolvedBOMCache.Set(cacheKey, resolved)

	return resolved, nil
}

// resolveBOMRecursive resolves a BOM and any imported BOMs.
// The visited map prevents infinite loops from circular imports.
func (r *MavenBOMResolver) resolveBOMRecursive(ctx context.Context, groupID, artifactID, version string, visited map[string]bool) (*ResolvedBOM, error) {
	key := fmt.Sprintf("%s:%s:%s", groupID, artifactID, version)
	if visited[key] {
		return &ResolvedBOM{
			ManagedVersions: make(map[string]string),
			Properties:      make(map[string]string),
		}, nil
	}
	visited[key] = true

	// Fetch requirements from deps.dev
	req, err := r.getRequirements(ctx, groupID, artifactID, version)
	if err != nil {
		return nil, fmt.Errorf("fetching requirements for %s: %w", key, err)
	}

	maven := req.GetMaven()
	if maven == nil {
		return nil, fmt.Errorf("no Maven data for %s", key)
	}

	// Build initial property map
	props := make(map[string]string)
	for _, p := range maven.GetProperties() {
		props[p.GetName()] = p.GetValue()
	}

	// Resolve property references within properties themselves
	// (e.g., jackson.version.databind = ${jackson.version})
	props = r.resolvePropertyReferences(props)

	// Initialize result
	result := &ResolvedBOM{
		ManagedVersions: make(map[string]string),
		Properties:      props,
	}

	// Process dependency management entries
	for _, dep := range maven.GetDependencyManagement() {
		name := dep.GetName() // format: "groupId:artifactId"
		version := dep.GetVersion()
		scope := dep.GetScope()
		depType := dep.GetType()

		// Check if this is a BOM import
		if scope == "import" && (depType == "pom" || depType == "") {
			// Resolve the version (may contain property reference)
			resolvedVersion := r.interpolateProperties(version, props)
			if resolvedVersion == "" || strings.Contains(resolvedVersion, "${") {
				continue // Can't resolve this BOM
			}

			// Parse the name to get groupId and artifactId
			parts := strings.SplitN(name, ":", 2)
			if len(parts) != 2 {
				continue
			}
			importGroupID, importArtifactID := parts[0], parts[1]

			// Recursively resolve the imported BOM
			importedBOM, err := r.resolveBOMRecursive(ctx, importGroupID, importArtifactID, resolvedVersion, visited)
			if err != nil {
				// Log but continue - partial resolution is better than none
				continue
			}

			// Merge imported BOM (imported entries have lower priority)
			for k, v := range importedBOM.ManagedVersions {
				if _, exists := result.ManagedVersions[k]; !exists {
					result.ManagedVersions[k] = v
				}
			}
			// Merge properties (imported properties have lower priority)
			for k, v := range importedBOM.Properties {
				if _, exists := result.Properties[k]; !exists {
					result.Properties[k] = v
				}
			}
		} else {
			// Regular managed dependency
			resolvedVersion := r.interpolateProperties(version, props)
			if resolvedVersion != "" && !strings.Contains(resolvedVersion, "${") {
				result.ManagedVersions[name] = resolvedVersion
			}
		}
	}

	return result, nil
}

// getRequirements fetches requirements from deps.dev with caching.
func (r *MavenBOMResolver) getRequirements(ctx context.Context, groupID, artifactID, version string) (*pb.Requirements, error) {
	// Maven name format for deps.dev: "groupId:artifactId"
	name := groupID + ":" + artifactID
	cacheKey := fmt.Sprintf("maven/%s@%s", name, version)

	// Check cache
	if req, ok := r.requirementsCache.Get(cacheKey); ok {
		return req, nil
	}

	// Fetch from API
	req, err := r.client.client.GetRequirements(ctx, &pb.GetRequirementsRequest{
		VersionKey: &pb.VersionKey{
			System:  pb.System_MAVEN,
			Name:    name,
			Version: version,
		},
	})
	if err != nil {
		return nil, err
	}

	// Cache the result
	r.requirementsCache.Set(cacheKey, req)

	return req, nil
}

// interpolateProperties replaces ${property} references with their values.
func (r *MavenBOMResolver) interpolateProperties(value string, props map[string]string) string {
	if !strings.Contains(value, "${") {
		return value
	}

	result := value
	// Iterate multiple times to handle nested references
	for range 10 { // Max 10 iterations to prevent infinite loops
		changed := false
		for name, propValue := range props {
			placeholder := "${" + name + "}"
			if strings.Contains(result, placeholder) {
				result = strings.ReplaceAll(result, placeholder, propValue)
				changed = true
			}
		}
		if !changed || !strings.Contains(result, "${") {
			break
		}
	}

	return result
}

// resolvePropertyReferences resolves property references within properties.
func (r *MavenBOMResolver) resolvePropertyReferences(props map[string]string) map[string]string {
	result := make(map[string]string, len(props))
	maps.Copy(result, props)

	// Iterate to resolve nested references
	for range 10 {
		changed := false
		for name, value := range result {
			if strings.Contains(value, "${") {
				resolved := r.interpolateProperties(value, result)
				if resolved != value {
					result[name] = resolved
					changed = true
				}
			}
		}
		if !changed {
			break
		}
	}

	return result
}

// ResolveVersion looks up the managed version for a dependency.
// Returns the version and true if found, or empty string and false if not managed.
func (r *MavenBOMResolver) ResolveVersion(bom *ResolvedBOM, groupID, artifactID string) (string, bool) {
	if bom == nil {
		return "", false
	}
	key := groupID + ":" + artifactID
	version, ok := bom.ManagedVersions[key]
	return version, ok
}

// KnownBOMs maps common Gradle plugins to their corresponding BOMs.
// This allows automatic BOM detection from build.gradle plugin declarations.
var KnownBOMs = map[string]BOMInfo{
	// Spring Boot
	"org.springframework.boot": {
		GroupID:    "org.springframework.boot",
		ArtifactID: "spring-boot-dependencies",
	},
	// gRPC
	"com.google.protobuf": {
		GroupID:    "com.google.protobuf",
		ArtifactID: "protobuf-bom",
	},
	// Jackson
	"com.fasterxml.jackson": {
		GroupID:    "com.fasterxml.jackson",
		ArtifactID: "jackson-bom",
	},
	// JUnit
	"org.junit": {
		GroupID:    "org.junit",
		ArtifactID: "junit-bom",
	},
	// Micronaut
	"io.micronaut.application": {
		GroupID:    "io.micronaut.platform",
		ArtifactID: "micronaut-platform",
	},
	// Quarkus
	"io.quarkus": {
		GroupID:    "io.quarkus.platform",
		ArtifactID: "quarkus-bom",
	},
}

// BOMInfo identifies a Maven BOM artifact.
type BOMInfo struct {
	GroupID    string
	ArtifactID string
}

// GlobalBOMResolver provides a shared BOM resolver instance.
// It's initialized lazily on first use.
var (
	globalBOMResolver     *MavenBOMResolver
	globalBOMResolverOnce sync.Once
	globalBOMResolverErr  error
)

// GetGlobalBOMResolver returns the shared BOM resolver instance.
// Returns nil and an error if deps.dev is unavailable.
func GetGlobalBOMResolver() (*MavenBOMResolver, error) {
	globalBOMResolverOnce.Do(func() {
		client, err := NewDepsDevClient()
		if err != nil {
			globalBOMResolverErr = err
			return
		}
		globalBOMResolver = NewMavenBOMResolver(client)
	})
	return globalBOMResolver, globalBOMResolverErr
}

// ResolveManagedVersions resolves versions for dependencies using BOMs.
// This is a convenience function that:
//  1. Gets the global BOM resolver
//  2. Resolves all provided BOMs
//  3. Returns a map of "groupId:artifactId" -> version
//
// Parameters:
//   - ctx: Context for cancellation
//   - boms: List of BOMs to resolve (groupID, artifactID, version tuples)
//
// Returns a map of managed versions, or an empty map if resolution fails.
func ResolveManagedVersions(ctx context.Context, boms []BOMCoordinate) map[string]string {
	resolver, err := GetGlobalBOMResolver()
	if err != nil || resolver == nil {
		return make(map[string]string)
	}

	managedVersions := make(map[string]string)

	for _, bom := range boms {
		resolved, err := resolver.ResolveBOM(ctx, bom.GroupID, bom.ArtifactID, bom.Version)
		if err != nil {
			continue
		}

		// Merge managed versions (later BOMs override earlier ones)
		maps.Copy(managedVersions, resolved.ManagedVersions)
	}

	return managedVersions
}

// BOMCoordinate represents a BOM's Maven coordinates.
type BOMCoordinate struct {
	GroupID    string
	ArtifactID string
	Version    string
}

// GradleBOMResolver implements gradlex.BOMVersionResolver using deps.dev.
// This adapter allows the graph package to provide BOM resolution to the
// gradlex extractors without creating an import cycle.
type GradleBOMResolver struct {
	resolver *MavenBOMResolver
}

// NewGradleBOMResolver creates a new Gradle BOM resolver.
func NewGradleBOMResolver(resolver *MavenBOMResolver) *GradleBOMResolver {
	return &GradleBOMResolver{resolver: resolver}
}

// initGradleBOMResolverFunc is set by resolve_gradle.go to register the resolver.
// This avoids importing gradlex in this file which would cause an import cycle.
var initGradleBOMResolverFunc func(*MavenBOMResolver)

// InitGradleBOMResolver initializes and registers the global BOM resolver
// with the gradlex package. This should be called during application startup
// or when the first Gradle extraction occurs.
func InitGradleBOMResolver() {
	resolver, err := GetGlobalBOMResolver()
	if err != nil {
		return // Silently fail - BOM resolution is optional
	}

	if initGradleBOMResolverFunc != nil {
		initGradleBOMResolverFunc(resolver)
	}
}
