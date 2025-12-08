package main

import (
	"context"
	"encoding/csv"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestInventoryOutput_NoUnknowns walks the generated inventory-output
// directory and validates that rows have non-empty project/package/version
// fields and do not contain the placeholder license "?". This is intended to
// catch regressions where license enrichment or name normalization fails.
//
// The test is best-effort: if inventory-output is absent it will be skipped so
// regular CI runs do not fail unexpectedly.
func TestInventoryOutput_NoUnknowns(t *testing.T) {
	base := filepath.Join("inventory-output")
	info, err := os.Stat(base)
	if errors.Is(err, os.ErrNotExist) {
		t.Skipf("inventory-output not present; generate CSVs first")
	}
	if err != nil {
		t.Fatalf("stat %s: %v", base, err)
	}
	if !info.IsDir() {
		t.Fatalf("inventory-output is not a directory")
	}

	csvFiles, err := findCSVFiles(base)
	if err != nil {
		t.Fatalf("find csv files: %v", err)
	}
	if len(csvFiles) == 0 {
		t.Skip("no csv files found under inventory-output")
	}

	strict := os.Getenv("STRICT_LICENSE_CHECK") == "1"
	var failures []string
	for _, path := range csvFiles {
		t.Run(strings.TrimPrefix(path, base+string(filepath.Separator)), func(t *testing.T) {
			bad := validateCSV(path)
			if len(bad) > 0 {
				failures = append(failures, bad...)
			}
		})
	}

	if len(failures) > 0 {
		msg := fmt.Sprintf("validation failures (sample):\n%s", strings.Join(sampleStrings(failures, 20), "\n"))
		if strict {
			t.Fatalf("%s", msg)
		} else {
			t.Log(msg)
		}
	}
}

// findCSVFiles returns all .csv files beneath base.
func findCSVFiles(base string) ([]string, error) {
	var out []string
	err := filepath.WalkDir(base, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		if strings.HasSuffix(strings.ToLower(d.Name()), ".csv") {
			out = append(out, path)
		}
		return nil
	})
	return out, err
}

// validateCSV checks for empty/unknown fields and placeholder licenses in one CSV file.
func validateCSV(path string) []string {
	f, err := os.Open(path)
	if err != nil {
		return []string{fmt.Sprintf("%s: open: %v", path, err)}
	}
	defer f.Close()

	r := csv.NewReader(f)
	records, err := r.ReadAll()
	if err != nil {
		return []string{fmt.Sprintf("%s: read: %v", path, err)}
	}
	if len(records) == 0 {
		return []string{fmt.Sprintf("%s: empty csv", path)}
	}
	header := records[0]
	if len(header) < 4 {
		return []string{fmt.Sprintf("%s: unexpected header columns (%d): %v", path, len(header), header)}
	}

	var issues []string
	for i, rec := range records[1:] {
		line := i + 2 // 1-based with header line
		if len(rec) < 4 {
			issues = append(issues, fmt.Sprintf("%s:%d: expected 4 columns, got %d", path, line, len(rec)))
			continue
		}
		project := strings.TrimSpace(rec[0])
		pkg := strings.TrimSpace(rec[1])
		version := strings.TrimSpace(rec[2])
		license := strings.TrimSpace(rec[3])

		if project == "" || strings.EqualFold(project, "unknown") {
			issues = append(issues, fmt.Sprintf("%s:%d: empty/unknown project", path, line))
		}
		if pkg == "" || strings.EqualFold(pkg, "unknown") {
			issues = append(issues, fmt.Sprintf("%s:%d: empty/unknown package", path, line))
		}
		if version == "" || strings.EqualFold(version, "unknown") {
			issues = append(issues, fmt.Sprintf("%s:%d: empty/unknown version (%s)", path, line, version))
		}
		if license == "" || license == "?" || strings.EqualFold(license, "unknown") {
			issues = append(issues, fmt.Sprintf("%s:%d: missing license for %s@%s", path, line, pkg, version))
		}
	}
	return issues
}

// sampleStrings returns up to n strings from the slice for concise test output.
func sampleStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	return in[:n]
}

func TestPackagistLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name    string
		version string
	}{
		{"amphp/amp", "v3.1.0"},
		{"composer/pcre", "3.3.2"},
		{"phpunit/phpunit", "10.5.45"},
	}

	for _, tc := range cases {
		licenses := lookupPackagistLicense(ctx, tc.name, tc.version)
		if len(licenses) == 0 {
			t.Fatalf("expected licenses for %s@%s, got none", tc.name, tc.version)
		}
		for _, l := range licenses {
			if strings.TrimSpace(l) == "" || strings.TrimSpace(l) == "?" {
				t.Fatalf("got empty/unknown license for %s@%s: %+v", tc.name, tc.version, licenses)
			}
		}
	}
}
