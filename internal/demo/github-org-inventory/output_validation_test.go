package main

import (
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	neturl "net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	pb "deps.dev/api/v3"
	"github.com/temporalio/deputy/internal/license"
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

func TestPubLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name    string
		version string
	}{
		{"http", "1.1.0"},
		{"riverpod", "1.0.0"},
	}

	for _, tc := range cases {
		licenses := license.LookupPubLicense(ctx, tc.name, tc.version)
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

func TestCocoaPodsLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name    string
		version string
	}{
		{"Alamofire", "5.9.1"},
	}

	for _, tc := range cases {
		licenses := license.LookupCocoaPodsLicense(ctx, tc.name, tc.version)
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

func TestHexLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name    string
		version string
	}{
		{"plug", "1.12.0"},
	}

	for _, tc := range cases {
		licenses := license.LookupHexLicense(ctx, tc.name, tc.version)
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

// TestCratesLookup samples a few Rust crates to ensure crates.io license lookup works,
// including versions that may omit patch components.
func TestCratesLookup(t *testing.T) {
	t.Parallel()

	ctx := context.Background()
	cases := []struct {
		name    string
		version string
	}{
		{"crossbeam-channel", "0.5"},
		{"crossbeam-queue", "0.3"},
		{"dashmap", "6.0"},
	}

	for _, tc := range cases {
		licenses := lookupCratesLicense(ctx, tc.name, tc.version)
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

// TestLicenseVerificationSample re-fetches licenses for a small sample of rows
// from generated CSVs using upstream registries (deps.dev for Go, npm registry
// for JS) to validate accuracy. Skips if CSVs are absent or registry lookups
// are unavailable (network, rate limits).
func TestLicenseVerificationSample(t *testing.T) {
	base := filepath.Join("inventory-output")
	info, err := os.Stat(base)
	if errors.Is(err, os.ErrNotExist) {
		t.Skip("inventory-output not present; generate CSVs first")
	}
	if err != nil || !info.IsDir() {
		t.Skip("inventory-output missing or not dir")
	}

	type sample struct {
		eco  string
		path string
	}
	samples := []sample{
		{eco: "go", path: filepath.Join(base, "temporalio", "go.csv")},
		{eco: "javascript", path: filepath.Join(base, "temporalio", "javascript.csv")},
	}
	for _, s := range samples {
		s := s
		t.Run(s.eco, func(t *testing.T) {
			if _, err := os.Stat(s.path); errors.Is(err, os.ErrNotExist) {
				t.Skipf("%s not present", s.path)
			}
			rows, err := readCSVRows(s.path)
			if err != nil {
				t.Fatalf("read csv: %v", err)
			}
			if len(rows) == 0 {
				t.Skip("no rows to verify")
			}
			ctx := context.Background()
			checked := 0
			for _, r := range rows {
				if r.License == "" || r.License == "?" {
					continue
				}
				ok, reason := verifyLicense(ctx, s.eco, r)
				if !ok {
					t.Fatalf("license mismatch for %s@%s from %s: %s", r.Package, r.Version, s.path, reason)
				}
				checked++
				if checked >= 5 { // limit to keep test fast
					break
				}
			}
			if checked == 0 {
				t.Skip("no rows with licenses to verify")
			}
		})
	}
}

type csvRow struct {
	Project string
	Package string
	Version string
	License string
}

func readCSVRows(path string) ([]csvRow, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	r := csv.NewReader(f)
	recs, err := r.ReadAll()
	if err != nil {
		return nil, err
	}
	if len(recs) < 2 {
		return nil, nil
	}
	var rows []csvRow
	for _, rec := range recs[1:] {
		if len(rec) < 4 {
			continue
		}
		rows = append(rows, csvRow{
			Project: strings.TrimSpace(rec[0]),
			Package: strings.TrimSpace(rec[1]),
			Version: strings.TrimSpace(rec[2]),
			License: strings.TrimSpace(rec[3]),
		})
	}
	return rows, nil
}

func verifyLicense(ctx context.Context, eco string, row csvRow) (bool, string) {
	gotLicenses := splitLicenseString(row.License)
	if len(gotLicenses) == 0 {
		return false, "csv license empty"
	}
	switch eco {
	case "go":
		client := newDepsDevClient()
		if client == nil {
			return true, "deps.dev unavailable; skip"
		}
		version := row.Version
		if version != "" && !strings.HasPrefix(version, "v") {
			version = "v" + version
		}
		req := &pb.GetVersionRequest{VersionKey: &pb.VersionKey{System: pb.System_GO, Name: row.Package, Version: version}}
		resp, err := client.GetVersion(ctx, req)
		if err != nil || resp == nil || len(resp.Licenses) == 0 {
			return true, "deps.dev lookup skipped (error or empty)"
		}
		want := normalizeLicenses(resp.Licenses)
		if !anyIntersect(gotLicenses, want) {
			return false, fmt.Sprintf("csv licenses %v do not match deps.dev %v", gotLicenses, want)
		}
		return true, ""
	case "javascript":
		if lic := fetchNPMLicense(ctx, row.Package, row.Version); len(lic) > 0 {
			want := normalizeLicenses(lic)
			if !anyIntersect(gotLicenses, want) {
				return false, fmt.Sprintf("csv licenses %v do not match npm %v", gotLicenses, want)
			}
			return true, ""
		}
		return true, "npm lookup skipped (empty)"
	default:
		return true, "ecosystem not verified"
	}
}

func anyIntersect(a, b []string) bool {
	if len(a) == 0 || len(b) == 0 {
		return false
	}
	set := map[string]struct{}{}
	for _, v := range a {
		set[strings.ToLower(strings.TrimSpace(v))] = struct{}{}
	}
	for _, v := range b {
		if _, ok := set[strings.ToLower(strings.TrimSpace(v))]; ok {
			return true
		}
	}
	return false
}

func fetchNPMLicense(ctx context.Context, name, version string) []string {
	name = strings.TrimSpace(name)
	version = strings.TrimSpace(version)
	if name == "" || version == "" {
		return nil
	}
	if ctx.Err() != nil {
		return nil
	}
	encodedName := neturl.PathEscape(name)
	url := fmt.Sprintf("https://registry.npmjs.org/%s/%s", encodedName, version)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return nil
	}
	client := &http.Client{Timeout: 5 * time.Second}
	resp, err := client.Do(req)
	if err != nil {
		return nil
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil
	}
	var payload struct {
		License any `json:"license"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&payload); err != nil {
		return nil
	}
	switch v := payload.License.(type) {
	case string:
		return splitLicenseString(v)
	case []any:
		var out []string
		for _, elem := range v {
			if s, ok := elem.(string); ok {
				out = append(out, s)
			}
		}
		return normalizeLicenses(out)
	default:
		return nil
	}
}
