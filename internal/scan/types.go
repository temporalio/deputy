package scan

import (
	"fmt"
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/dockerfile"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/targets"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Target describes what was scanned and how it was resolved.
type Target struct {
	Kind         targets.Kind
	DisplayPath  string
	LocalPath    string
	Ref          string
	EffectiveRef string
	CommitHash   string
	OriginURL    string
	Cloned       bool
	Provenance   map[string]string
}

// Inventory captures the packages and direct dependency hints discovered during scanning.
type Inventory struct {
	Packages []*extractor.Package
	Direct   map[string]bool
}

// Options configures scan behavior.
type Options struct {
	Ecosystems      []string
	PublishedBefore time.Time
	PublishedAfter  time.Time

	// Graph controls dependency graph resolution.
	// When enabled, the scan result includes a fully-resolved dependency graph
	// with edges showing which packages depend on which.
	Graph GraphOptions
}

// GraphOptions configures dependency graph resolution during scans.
type GraphOptions struct {
	// Enabled controls whether to build the dependency graph.
	// When true, the scan will resolve dependency edges and include
	// the graph in results, enabling path-based vulnerability analysis.
	Enabled bool

	// UseProxy enables fetching module metadata from package registries
	// (e.g., proxy.golang.org for Go). This provides more accurate transitive
	// dependency resolution but requires network access.
	UseProxy bool

	// UseGit enables cloning repositories for private module resolution.
	// This is useful for private Go modules that aren't available via proxy.
	UseGit bool

	// PrivatePatterns specifies glob patterns for private modules
	// (similar to GOPRIVATE). These modules will use git instead of proxy.
	PrivatePatterns []string
}

// Validate checks that the options are valid.
func (o Options) Validate() error {
	if !o.PublishedBefore.IsZero() && !o.PublishedAfter.IsZero() {
		if o.PublishedAfter.After(o.PublishedBefore) {
			return fmt.Errorf("PublishedAfter must be before PublishedBefore")
		}
	}
	return nil
}

// Result is the output of a scan operation.
type Result struct {
	Target          Target
	GeneratedAt     time.Time
	PackagesScanned int
	Inventory       Inventory

	Findings   []vulnerability.Finding
	Advisories map[string]vulnerability.Advisory
	Stats      vulnerability.Stats

	// Graph contains the resolved dependency graph with edges showing
	// relationships between packages. When populated, it enables path-based
	// analysis like "why is this vulnerable package in my dependencies?"
	// This is nil when graph resolution is disabled or not applicable.
	Graph *graph.Graph

	PolicyActions []policy.Action

	Warnings []string

	// ImageInfo contains extracted configuration and metadata for container image scans.
	// This is nil for non-container-image targets.
	ImageInfo *image.Info

	// DockerfileInfo contains parsed Dockerfile data for dockerfile targets.
	// This is nil for non-dockerfile targets.
	DockerfileInfo *dockerfile.Info

	// DockerfileAnalysis contains static analysis results for dockerfile targets.
	// This is nil for non-dockerfile targets.
	DockerfileAnalysis *dockerfile.Analysis
}

// Execution wraps a scan result and any cleanup callbacks.
type Execution struct {
	Result  Result
	cleanup func()
}

// Close releases any temporary resources created during the scan.
func (e *Execution) Close() error {
	if e == nil || e.cleanup == nil {
		return nil
	}
	e.cleanup()
	return nil
}
