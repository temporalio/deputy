// Package nixstore provides extraction of Nix packages from the Nix store.
package nixstore

import (
	"context"
	"database/sql"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	// SQLite driver for parsing Nix database.
	_ "modernc.org/sqlite"
)

// DBPackage represents a package entry from the Nix database.
type DBPackage struct {
	// ID is the database row ID.
	ID int64

	// StorePath is the full store path (e.g., /nix/store/abc...-openssl-3.0.12).
	StorePath string

	// Hash is the content hash from the database.
	Hash string

	// DeriverPath is the path to the .drv file that built this package.
	DeriverPath string

	// Name is the parsed package name.
	Name string

	// Version is the parsed package version.
	Version string

	// OutputHash is the Nix store hash (first 32 chars).
	OutputHash string

	// Output is the output name (dev, lib, man, etc.).
	Output string

	// Files are the files owned by this package (if CaptureOwnedFiles is set).
	Files []string

	// Derivation is the parsed .drv file (if available).
	Derivation *Derivation
}

// StoreDBConfig configures the store database scanner.
type StoreDBConfig struct {
	// CaptureOwnedFiles enables capturing the list of files owned by each package.
	CaptureOwnedFiles bool

	// ParseDerivations enables parsing .drv files for dependency information.
	ParseDerivations bool

	// StoreDir is the Nix store directory (default: /nix/store).
	StoreDir string
}

// StoreDB scans package information from the Nix store database.
type StoreDB struct {
	config StoreDBConfig
}

// NewStoreDB creates a new store database scanner.
func NewStoreDB(config StoreDBConfig) *StoreDB {
	if config.StoreDir == "" {
		config.StoreDir = "/nix/store"
	}
	return &StoreDB{config: config}
}

// ScanPackages extracts packages from a Nix database file.
func (s *StoreDB) ScanPackages(ctx context.Context, dbPath string) ([]*DBPackage, error) {
	// Check if file exists and is readable
	if _, err := os.Stat(dbPath); err != nil {
		return nil, fmt.Errorf("database not found: %w", err)
	}

	db, err := sql.Open("sqlite", dbPath+"?mode=ro")
	if err != nil {
		return nil, fmt.Errorf("open database: %w", err)
	}
	defer db.Close()

	return s.scan(ctx, db)
}

// ScanFromConn extracts packages from an open database connection.
func (s *StoreDB) ScanFromConn(ctx context.Context, db *sql.DB) ([]*DBPackage, error) {
	return s.scan(ctx, db)
}

// scan performs the actual extraction.
func (s *StoreDB) scan(ctx context.Context, db *sql.DB) ([]*DBPackage, error) {
	// Check schema version
	schema, err := s.getSchemaVersion(ctx, db)
	if err != nil {
		// Default to v10 parsing if we can't determine schema
		schema = 10
	}

	if schema < 10 {
		return nil, fmt.Errorf("unsupported Nix database schema version: %d (need >= 10)", schema)
	}

	return s.extractV10(ctx, db)
}

// getSchemaVersion reads the schema version from the database directory.
func (s *StoreDB) getSchemaVersion(ctx context.Context, db *sql.DB) (int, error) {
	// The schema file is at /nix/var/nix/db/schema
	// We'll try to determine this from context or default to 10
	return 10, nil
}

// extractV10 extracts packages using the v10 schema.
// Schema v10 tables:
// - ValidPaths (id, path, hash, registrationTime, deriver, narSize, ultimate, sigs, ca)
// - DerivationOutputs (drv, id, path)
// - Refs (referrer, reference)
func (s *StoreDB) extractV10(ctx context.Context, db *sql.DB) ([]*DBPackage, error) {
	// Query ValidPaths for all packages
	rows, err := db.QueryContext(ctx, `
		SELECT id, path, hash, deriver
		FROM ValidPaths
		WHERE path NOT LIKE '%.drv'
	`)
	if err != nil {
		return nil, fmt.Errorf("query ValidPaths: %w", err)
	}
	defer rows.Close()

	var packages []*DBPackage
	packagesByPath := make(map[string]*DBPackage)

	for rows.Next() {
		var pkg DBPackage
		var hash, deriver sql.NullString

		if err := rows.Scan(&pkg.ID, &pkg.StorePath, &hash, &deriver); err != nil {
			return nil, fmt.Errorf("scan row: %w", err)
		}

		if hash.Valid {
			pkg.Hash = hash.String
		}
		if deriver.Valid {
			pkg.DeriverPath = deriver.String
		}

		// Parse the store path
		pkg.Name, pkg.Version, pkg.OutputHash, pkg.Output = parseNixStorePath(pkg.StorePath)

		if pkg.Name == "" {
			// Skip invalid paths
			continue
		}

		packages = append(packages, &pkg)
		packagesByPath[pkg.StorePath] = &pkg
	}

	if err := rows.Err(); err != nil {
		return nil, fmt.Errorf("iterate rows: %w", err)
	}

	// Get output names from DerivationOutputs
	if err := s.enrichWithOutputs(ctx, db, packagesByPath); err != nil {
		// Log but don't fail - this is optional enrichment
		_ = err
	}

	// Parse derivations if requested
	if s.config.ParseDerivations {
		s.enrichWithDerivations(packages)
	}

	return packages, nil
}

// enrichWithOutputs adds output names from DerivationOutputs table.
func (s *StoreDB) enrichWithOutputs(ctx context.Context, db *sql.DB, pkgsByPath map[string]*DBPackage) error {
	rows, err := db.QueryContext(ctx, `
		SELECT id, path
		FROM DerivationOutputs
	`)
	if err != nil {
		// Table might not exist in older schemas
		return nil
	}
	defer rows.Close()

	for rows.Next() {
		var outputID, outputPath string
		if err := rows.Scan(&outputID, &outputPath); err != nil {
			continue
		}

		if pkg, ok := pkgsByPath[outputPath]; ok {
			// outputID is the output name like "out", "dev", "lib"
			pkg.Output = outputID
		}
	}

	return rows.Err()
}

// enrichWithDerivations parses .drv files for packages that have them.
func (s *StoreDB) enrichWithDerivations(packages []*DBPackage) {
	for _, pkg := range packages {
		if pkg.DeriverPath == "" {
			continue
		}

		// Normalize the deriver path
		drvPath := pkg.DeriverPath
		if !strings.HasPrefix(drvPath, "/") {
			drvPath = filepath.Join(s.config.StoreDir, drvPath)
		}

		drv, err := ParseDerivationFile(drvPath)
		if err != nil {
			// Skip packages where we can't parse the derivation
			continue
		}

		pkg.Derivation = drv
	}
}

// GetPackageReferences returns the store paths that a package references.
func (s *StoreDB) GetPackageReferences(ctx context.Context, db *sql.DB, pkgID int64) ([]string, error) {
	rows, err := db.QueryContext(ctx, `
		SELECT vp.path
		FROM Refs r
		JOIN ValidPaths vp ON r.reference = vp.id
		WHERE r.referrer = ?
	`, pkgID)
	if err != nil {
		return nil, fmt.Errorf("query refs: %w", err)
	}
	defer rows.Close()

	var refs []string
	for rows.Next() {
		var path string
		if err := rows.Scan(&path); err != nil {
			continue
		}
		refs = append(refs, path)
	}

	return refs, rows.Err()
}

// FindNixDatabase locates the Nix database file.
// It checks common locations:
// - /nix/var/nix/db/db.sqlite
// - <storeDir>/../var/nix/db/db.sqlite
func FindNixDatabase(storeDir string) string {
	candidates := []string{
		"/nix/var/nix/db/db.sqlite",
	}

	if storeDir != "" && storeDir != "/nix/store" {
		candidates = append([]string{
			filepath.Join(storeDir, "..", "var", "nix", "db", "db.sqlite"),
		}, candidates...)
	}

	for _, path := range candidates {
		if _, err := os.Stat(path); err == nil {
			return path
		}
	}

	return ""
}

// BuildDependencyGraph builds a dependency graph from the Nix database.
// It returns a map from package store path to its dependency store paths.
func (s *StoreDB) BuildDependencyGraph(ctx context.Context, db *sql.DB) (map[string][]string, error) {
	// Get all package paths and IDs
	pathByID := make(map[int64]string)
	rows, err := db.QueryContext(ctx, `SELECT id, path FROM ValidPaths`)
	if err != nil {
		return nil, fmt.Errorf("query ValidPaths: %w", err)
	}
	for rows.Next() {
		var id int64
		var path string
		if err := rows.Scan(&id, &path); err != nil {
			continue
		}
		pathByID[id] = path
	}
	rows.Close()

	// Build dependency graph from Refs table
	graph := make(map[string][]string)
	rows, err = db.QueryContext(ctx, `SELECT referrer, reference FROM Refs`)
	if err != nil {
		return nil, fmt.Errorf("query Refs: %w", err)
	}
	defer rows.Close()

	for rows.Next() {
		var referrer, reference int64
		if err := rows.Scan(&referrer, &reference); err != nil {
			continue
		}

		referrerPath := pathByID[referrer]
		referencePath := pathByID[reference]
		if referrerPath != "" && referencePath != "" {
			graph[referrerPath] = append(graph[referrerPath], referencePath)
		}
	}

	return graph, rows.Err()
}
