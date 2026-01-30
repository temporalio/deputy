package nixstore

import (
	"context"
	"database/sql"
	"os"
	"path/filepath"
	"testing"

	_ "modernc.org/sqlite"
)

// Valid 32-char Nix store hashes (base32 without vowels except 'a')
const (
	testHash1 = "0123456789abcdfghjklmnpqrsvwxyz1"
	testHash2 = "0123456789abcdfghjklmnpqrsvwxyz2"
	testHash3 = "0123456789abcdfghjklmnpqrsvwxyz3"
	testHash4 = "0123456789abcdfghjklmnpqrsvwxyz4"
)

// createTestDB creates a temporary Nix database with the V10 schema for testing
func createTestDB(t *testing.T) string {
	t.Helper()

	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "db.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create test database: %v", err)
	}
	defer db.Close()

	// Create V10 schema
	schema := `
		CREATE TABLE IF NOT EXISTS ValidPaths (
			id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
			path TEXT UNIQUE NOT NULL,
			hash TEXT NOT NULL,
			registrationTime INTEGER NOT NULL,
			deriver TEXT,
			narSize INTEGER,
			ultimate INTEGER,
			sigs TEXT,
			ca TEXT
		);

		CREATE TABLE IF NOT EXISTS DerivationOutputs (
			drv INTEGER NOT NULL,
			id TEXT NOT NULL,
			path TEXT NOT NULL,
			PRIMARY KEY (drv, id),
			FOREIGN KEY (drv) REFERENCES ValidPaths(id) ON DELETE CASCADE
		);

		CREATE TABLE IF NOT EXISTS Refs (
			referrer INTEGER NOT NULL,
			reference INTEGER NOT NULL,
			PRIMARY KEY (referrer, reference),
			FOREIGN KEY (referrer) REFERENCES ValidPaths(id) ON DELETE CASCADE,
			FOREIGN KEY (reference) REFERENCES ValidPaths(id) ON DELETE CASCADE
		);
	`

	_, err = db.Exec(schema)
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	// Use valid store paths with 32-char hashes
	helloPath := "/nix/store/" + testHash1 + "-hello-2.10"
	glibcPath := "/nix/store/" + testHash2 + "-glibc-2.38"
	curlPath := "/nix/store/" + testHash3 + "-curl-8.4.0"
	helloDrvPath := "/nix/store/" + testHash4 + "-hello-2.10.drv"

	// Insert test data
	insertPaths := `
		INSERT INTO ValidPaths (id, path, hash, registrationTime, deriver) VALUES
		(1, ?, 'sha256:abc123', 1700000000, ?),
		(2, ?, 'sha256:def456', 1700000001, NULL),
		(3, ?, 'sha256:ghi789', 1700000002, NULL),
		(4, ?, 'sha256:xyz789drv', 1700000000, NULL);
	`

	_, err = db.Exec(insertPaths, helloPath, helloDrvPath, glibcPath, curlPath, helloDrvPath)
	if err != nil {
		t.Fatalf("Failed to insert test paths: %v", err)
	}

	// Insert derivation outputs
	insertOutputs := `
		INSERT INTO DerivationOutputs (drv, id, path) VALUES
		(4, 'out', ?);
	`

	_, err = db.Exec(insertOutputs, helloPath)
	if err != nil {
		t.Fatalf("Failed to insert derivation outputs: %v", err)
	}

	// Insert refs: hello depends on glibc
	insertRefs := `
		INSERT INTO Refs (referrer, reference) VALUES
		(1, 2),
		(3, 2);
	`

	_, err = db.Exec(insertRefs)
	if err != nil {
		t.Fatalf("Failed to insert refs: %v", err)
	}

	return dbPath
}

func TestStoreDBScanPackages(t *testing.T) {
	dbPath := createTestDB(t)

	storeDB := NewStoreDB(StoreDBConfig{
		CaptureOwnedFiles: false,
		ParseDerivations:  false,
		StoreDir:          "/nix/store",
	})

	ctx := context.Background()
	packages, err := storeDB.ScanPackages(ctx, dbPath)
	if err != nil {
		t.Fatalf("ScanPackages failed: %v", err)
	}

	if len(packages) != 3 { // excluding the .drv file
		t.Errorf("len(packages) = %d, want 3", len(packages))
	}

	// Check that we found hello
	var hello *DBPackage
	for _, pkg := range packages {
		if pkg.Name == "hello" {
			hello = pkg
			break
		}
	}

	if hello == nil {
		t.Fatal("Did not find hello package")
	}

	if hello.Version != "2.10" {
		t.Errorf("hello.Version = %q, want %q", hello.Version, "2.10")
	}

	expectedPath := "/nix/store/" + testHash1 + "-hello-2.10"
	if hello.StorePath != expectedPath {
		t.Errorf("hello.StorePath = %q, want %q", hello.StorePath, expectedPath)
	}

	expectedDrv := "/nix/store/" + testHash4 + "-hello-2.10.drv"
	if hello.DeriverPath != expectedDrv {
		t.Errorf("hello.DeriverPath = %q, want %q", hello.DeriverPath, expectedDrv)
	}

	if hello.Hash != "sha256:abc123" {
		t.Errorf("hello.Hash = %q", hello.Hash)
	}
}

func TestStoreDBWithOutputHash(t *testing.T) {
	dbPath := createTestDB(t)

	storeDB := NewStoreDB(StoreDBConfig{
		StoreDir: "/nix/store",
	})

	ctx := context.Background()
	packages, err := storeDB.ScanPackages(ctx, dbPath)
	if err != nil {
		t.Fatalf("ScanPackages failed: %v", err)
	}

	// Find hello which should have an output hash from DerivationOutputs
	var hello *DBPackage
	for _, pkg := range packages {
		if pkg.Name == "hello" {
			hello = pkg
			break
		}
	}

	if hello == nil {
		t.Fatal("Did not find hello package")
	}

	// hello should have output info from DerivationOutputs table
	if hello.Output != "out" {
		t.Errorf("hello.Output = %q, want %q", hello.Output, "out")
	}
}

func TestStoreDBBuildDependencyGraph(t *testing.T) {
	dbPath := createTestDB(t)

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to open database: %v", err)
	}
	defer db.Close()

	storeDB := NewStoreDB(StoreDBConfig{
		StoreDir: "/nix/store",
	})

	ctx := context.Background()
	graph, err := storeDB.BuildDependencyGraph(ctx, db)
	if err != nil {
		t.Fatalf("BuildDependencyGraph failed: %v", err)
	}

	helloPath := "/nix/store/" + testHash1 + "-hello-2.10"
	glibcPath := "/nix/store/" + testHash2 + "-glibc-2.38"
	curlPath := "/nix/store/" + testHash3 + "-curl-8.4.0"

	// hello depends on glibc
	helloDeps := graph[helloPath]
	if len(helloDeps) != 1 || helloDeps[0] != glibcPath {
		t.Errorf("hello deps = %v, want [%s]", helloDeps, glibcPath)
	}

	// curl depends on glibc
	curlDeps := graph[curlPath]
	if len(curlDeps) != 1 || curlDeps[0] != glibcPath {
		t.Errorf("curl deps = %v, want [%s]", curlDeps, glibcPath)
	}

	// glibc has no deps
	glibcDeps := graph[glibcPath]
	if len(glibcDeps) != 0 {
		t.Errorf("glibc deps = %v, want []", glibcDeps)
	}
}

func TestFindNixDatabase(t *testing.T) {
	tmpDir := t.TempDir()

	// Create the expected directory structure
	dbDir := filepath.Join(tmpDir, "nix", "var", "nix", "db")
	err := os.MkdirAll(dbDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create db dir: %v", err)
	}

	dbPath := filepath.Join(dbDir, "db.sqlite")
	err = os.WriteFile(dbPath, []byte(""), 0644)
	if err != nil {
		t.Fatalf("Failed to create db file: %v", err)
	}

	// Test finding with store dir
	storeDir := filepath.Join(tmpDir, "nix", "store")
	err = os.MkdirAll(storeDir, 0755)
	if err != nil {
		t.Fatalf("Failed to create store dir: %v", err)
	}

	found := FindNixDatabase(storeDir)
	if found != dbPath {
		t.Errorf("FindNixDatabase = %q, want %q", found, dbPath)
	}
}

func TestFindNixDatabaseNotFound(t *testing.T) {
	tmpDir := t.TempDir()

	found := FindNixDatabase(tmpDir)
	if found != "" {
		t.Errorf("FindNixDatabase should return empty string when db doesn't exist, got %q", found)
	}
}

func TestParseNixStorePathFromDB(t *testing.T) {
	// Test the parsing through catalog results rather than directly calling
	// parseNixStorePath (which is in extractor.go)
	tests := []struct {
		storePath   string
		wantName    string
		wantVersion string
	}{
		{"/nix/store/" + testHash1 + "-hello-2.10", "hello", "2.10"},
		{"/nix/store/" + testHash2 + "-glibc-2.38", "glibc", "2.38"},
		{"/nix/store/" + testHash3 + "-curl-8.4.0", "curl", "8.4.0"},
	}

	for _, tc := range tests {
		name, version, _, _ := parseNixStorePath(tc.storePath)
		if name != tc.wantName {
			t.Errorf("parseNixStorePath(%q) name = %q, want %q", tc.storePath, name, tc.wantName)
		}
		if version != tc.wantVersion {
			t.Errorf("parseNixStorePath(%q) version = %q, want %q", tc.storePath, version, tc.wantVersion)
		}
	}
}

func TestStoreDBEmptyDatabase(t *testing.T) {
	tmpDir := t.TempDir()
	dbPath := filepath.Join(tmpDir, "empty.sqlite")

	db, err := sql.Open("sqlite", dbPath)
	if err != nil {
		t.Fatalf("Failed to create database: %v", err)
	}

	// Create empty tables
	schema := `
		CREATE TABLE IF NOT EXISTS ValidPaths (
			id INTEGER PRIMARY KEY AUTOINCREMENT NOT NULL,
			path TEXT UNIQUE NOT NULL,
			hash TEXT NOT NULL,
			registrationTime INTEGER NOT NULL,
			deriver TEXT,
			narSize INTEGER,
			ultimate INTEGER,
			sigs TEXT,
			ca TEXT
		);
	`
	_, err = db.Exec(schema)
	db.Close()
	if err != nil {
		t.Fatalf("Failed to create schema: %v", err)
	}

	storeDB := NewStoreDB(StoreDBConfig{
		StoreDir: "/nix/store",
	})

	ctx := context.Background()
	packages, err := storeDB.ScanPackages(ctx, dbPath)
	if err != nil {
		t.Fatalf("ScanPackages failed: %v", err)
	}

	if len(packages) != 0 {
		t.Errorf("len(packages) = %d, want 0", len(packages))
	}
}

func TestStoreDBMissingDatabase(t *testing.T) {
	storeDB := NewStoreDB(StoreDBConfig{
		StoreDir: "/nix/store",
	})

	ctx := context.Background()
	_, err := storeDB.ScanPackages(ctx, "/nonexistent/db.sqlite")
	if err == nil {
		t.Error("ScanPackages should fail for missing database")
	}
}
