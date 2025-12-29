package scan

import (
	"time"

	"github.com/google/osv-scalibr/extractor"
	"github.com/picatz/deputy/internal/policy"
	"github.com/picatz/deputy/internal/vulnerability"
)

// Target describes what was scanned and how it was resolved.
type Target struct {
	DisplayPath  string
	LocalPath    string
	Ref          string
	EffectiveRef string
	CommitHash   string
	OriginURL    string
	Cloned       bool
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

	PolicyDecisions []policy.Decision

	Warnings []string
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
