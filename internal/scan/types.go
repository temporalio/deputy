package scan

import (
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/container/image"
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
