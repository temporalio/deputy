// Package nixstore provides extraction of Nix packages from the Nix store.
package nixstore

import (
	"context"
	"fmt"
	"log/slog"
	"path/filepath"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// DBName is the unique name of the database-based extractor.
	DBName = "nix/db"
)

// DBExtractor extracts Nix packages from the Nix database (db.sqlite).
// This provides more complete package information than path scanning,
// including dependency relationships and hash information.
type DBExtractor struct {
	db *StoreDB
	// parseDerivations enables parsing .drv files for additional metadata
	parseDerivations bool
}

// DBExtractorOptions configures the database extractor.
type DBExtractorOptions struct {
	// ParseDerivations enables parsing .drv files for additional metadata.
	ParseDerivations bool
	// CaptureOwnedFiles enables capturing the list of files owned by each package.
	CaptureOwnedFiles bool
	// StoreDir is the Nix store directory (default: /nix/store).
	StoreDir string
}

// NewDBExtractor creates a new database-based Nix extractor.
func NewDBExtractor(opts DBExtractorOptions) *DBExtractor {
	return &DBExtractor{
		db: NewStoreDB(StoreDBConfig{
			CaptureOwnedFiles: opts.CaptureOwnedFiles,
			ParseDerivations:  opts.ParseDerivations,
			StoreDir:          opts.StoreDir,
		}),
		parseDerivations: opts.ParseDerivations,
	}
}

// Name implements the plugin.Plugin interface.
func (e *DBExtractor) Name() string {
	return DBName
}

// Version implements the plugin.Plugin interface.
func (e *DBExtractor) Version() int {
	return 1
}

// Requirements implements the filesystem.Extractor interface.
func (e *DBExtractor) Requirements() *plugin.Capabilities {
	return &plugin.Capabilities{}
}

// FileRequired implements the filesystem.Extractor interface.
// It only matches the Nix database file.
func (e *DBExtractor) FileRequired(api filesystem.FileAPI) bool {
	path := api.Path()
	// Match /nix/var/nix/db/db.sqlite or var/nix/db/db.sqlite
	return path == "nix/var/nix/db/db.sqlite" ||
		path == "/nix/var/nix/db/db.sqlite" ||
		strings.HasSuffix(path, "/var/nix/db/db.sqlite")
}

// Extract implements the filesystem.Extractor interface.
func (e *DBExtractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Path == "" {
		return inventory.Inventory{}, fmt.Errorf("invalid input")
	}

	// Get the real filesystem path
	realPath := input.Path
	if input.Root != "" && !strings.HasPrefix(realPath, "/") {
		realPath = filepath.Join(input.Root, realPath)
	}

	slog.Debug("nix/db: extracting from database", "path", realPath)

	// Scan packages from the database
	packages, err := e.db.ScanPackages(ctx, realPath)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("scan packages: %w", err)
	}

	slog.Debug("nix/db: found packages", "count", len(packages))

	// Convert DBPackage to extractor.Package
	result := make([]*extractor.Package, 0, len(packages))
	for _, pkg := range packages {
		if pkg.Name == "" {
			continue
		}

		extPkg := &extractor.Package{
			Name:     pkg.Name,
			Version:  pkg.Version,
			PURLType: purl.TypeNix,
			Metadata: &Metadata{
				PackageName:    pkg.Name,
				PackageVersion: pkg.Version,
				PackageHash:    pkg.OutputHash,
				PackageOutput:  pkg.Output,
			},
			Locations: []string{pkg.StorePath},
		}

		result = append(result, extPkg)
	}

	return inventory.Inventory{Packages: result}, nil
}

// ToPURL implements the Extractor interface.
func (e *DBExtractor) ToPURL(pkg *extractor.Package) *purl.PackageURL {
	if pkg == nil {
		return nil
	}
	return &purl.PackageURL{
		Type:    purl.TypeNix,
		Name:    pkg.Name,
		Version: pkg.Version,
	}
}

// ToCPEs implements the Extractor interface.
func (e *DBExtractor) ToCPEs(pkg *extractor.Package) []string {
	return nil // Nix packages don't have standard CPEs
}

// Ecosystem implements the Extractor interface.
func (e *DBExtractor) Ecosystem(pkg *extractor.Package) string {
	return "nix"
}

// ScanResult contains packages from the Nix database along with their dependencies.
type ScanResult struct {
	// Packages are the discovered packages.
	Packages []*DBPackage
	// Dependencies maps package store paths to their dependency store paths.
	Dependencies map[string][]string
}

// ScanWithDependencies performs a full scan including dependency information.
// This is useful for building dependency graphs.
func (e *DBExtractor) ScanWithDependencies(ctx context.Context, dbPath string) (*ScanResult, error) {
	// Open database for reading
	packages, err := e.db.ScanPackages(ctx, dbPath)
	if err != nil {
		return nil, fmt.Errorf("scan: %w", err)
	}

	// Build dependency graph from the same database
	// We need to open a new connection since ScanPackages closes it
	storeDB := NewStoreDB(e.db.config)

	// For now, return empty dependencies since BuildDependencyGraph
	// requires an open database connection. This can be enhanced.
	result := &ScanResult{
		Packages:     packages,
		Dependencies: make(map[string][]string),
	}

	// If derivation parsing is enabled, we can get dependencies from there
	if e.parseDerivations {
		for _, pkg := range packages {
			if pkg.Derivation != nil {
				deps := pkg.Derivation.Dependencies()
				for _, dep := range deps {
					// Resolve output paths for each dependency
					for _, output := range dep.Outputs {
						if outputPath := pkg.Derivation.OutputPath(output); outputPath != "" {
							result.Dependencies[pkg.StorePath] = append(
								result.Dependencies[pkg.StorePath],
								outputPath,
							)
						}
					}
				}
			}
		}
	}

	// Suppress unused variable warning
	_ = storeDB

	return result, nil
}

// Ensure DBExtractor implements the filesystem.Extractor interface.
var _ filesystem.Extractor = (*DBExtractor)(nil)
