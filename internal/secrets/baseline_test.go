package secrets

import (
	"context"
	"os"
	"path/filepath"
	"testing"
)

func TestBaseline_AddAndContains(t *testing.T) {
	baseline := NewBaseline()

	finding := Finding{
		Type:       TypeGitHubToken,
		File:       "config.go",
		Line:       42,
		Column:     10,
		Value:      "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Confidence: 0.99,
	}

	// Should not contain before adding
	if baseline.Contains(finding) {
		t.Error("baseline should not contain finding before adding")
	}

	// Add finding
	baseline.AddFinding(finding, "test secret")

	// Should contain after adding
	if !baseline.Contains(finding) {
		t.Error("baseline should contain finding after adding")
	}

	// Should contain with slightly different line (fuzzy match)
	movedFinding := finding
	movedFinding.Line = 44 // Within 5 lines
	if !baseline.Contains(movedFinding) {
		t.Error("baseline should fuzzy match finding within 5 lines")
	}

	// Should not contain with different file
	differentFile := finding
	differentFile.File = "other.go"
	if baseline.Contains(differentFile) {
		t.Error("baseline should not contain finding from different file")
	}
}

func TestBaseline_Filter(t *testing.T) {
	baseline := NewBaseline()

	knownSecret := Finding{
		Type:       TypeAWSAccessKey,
		File:       "test.go",
		Line:       10,
		Value:      "AKIAIOSFODNN7EXAMPLE",
		Confidence: 0.95,
	}
	baseline.AddFinding(knownSecret, "test fixture")

	newSecret := Finding{
		Type:       TypeGitHubToken,
		File:       "main.go",
		Line:       25,
		Value:      "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
		Confidence: 0.99,
	}

	findings := []Finding{knownSecret, newSecret}
	filtered := baseline.Filter(findings)

	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered))
	}
	if filtered[0].Type != TypeGitHubToken {
		t.Errorf("expected GitHub token to remain, got %s", filtered[0].Type)
	}
}

func TestBaseline_SaveAndLoad(t *testing.T) {
	tmpDir := t.TempDir()
	baselinePath := filepath.Join(tmpDir, ".baseline.json")

	// Create and save baseline
	baseline := NewBaseline()
	baseline.AddFinding(Finding{
		Type:       TypeSlackToken,
		File:       "webhook.go",
		Line:       15,
		Value:      "xoxb-1234567890-1234567890-abcdefghij",
		Confidence: 0.95,
	}, "test token")

	if err := baseline.Save(baselinePath); err != nil {
		t.Fatalf("Save failed: %v", err)
	}

	// Load and verify
	loaded, err := LoadBaseline(baselinePath)
	if err != nil {
		t.Fatalf("Load failed: %v", err)
	}

	if loaded.Version != BaselineVersion {
		t.Errorf("expected version %s, got %s", BaselineVersion, loaded.Version)
	}
	if loaded.TotalEntries() != 1 {
		t.Errorf("expected 1 entry, got %d", loaded.TotalEntries())
	}
	if len(loaded.Results["webhook.go"]) != 1 {
		t.Error("expected entry for webhook.go")
	}
}

func TestBaseline_LoadNotFound(t *testing.T) {
	_, err := LoadBaseline("/nonexistent/path/baseline.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestAllowlist_Filter(t *testing.T) {
	allowlist := NewAllowlist()

	// Add test data to ignore
	allowlist.AddType("high_entropy_string", "too noisy")
	allowlist.AddHash("test_secret_value", "test fixture")
	allowlist.AddPath("*_test.go", "test files")

	findings := []Finding{
		{Type: TypeHighEntropy, File: "main.go", Value: "random_string"},
		{Type: TypeGitHubToken, File: "main.go", Value: "ghp_real_token"},
		{Type: TypeAWSAccessKey, File: "main_test.go", Value: "test_secret_value"},
	}

	filtered := allowlist.Filter(findings)

	// High entropy should be filtered (type allowlist)
	// test_secret_value should be filtered (hash allowlist)
	// GitHub token should remain
	if len(filtered) != 1 {
		t.Fatalf("expected 1 finding after filter, got %d", len(filtered))
	}
	if filtered[0].Type != TypeGitHubToken {
		t.Errorf("expected GitHub token to remain, got %s", filtered[0].Type)
	}
}

func TestAllowlist_ShouldIgnoreFile(t *testing.T) {
	allowlist := NewAllowlist()
	allowlist.AddPath("*_test.go", "test files")
	allowlist.AddPath("vendor/*", "vendor files")
	allowlist.AddPath(".env.example", "example env")

	tests := []struct {
		path   string
		ignore bool
	}{
		{"main_test.go", true},
		{"main.go", false},
		{"vendor/lib/file.go", true}, // "vendor/*" matches the whole vendor subtree
		{".env.example", true},
		{".env", false},
	}

	for _, tc := range tests {
		if got := allowlist.ShouldIgnoreFile(tc.path); got != tc.ignore {
			t.Errorf("ShouldIgnoreFile(%q) = %v, want %v", tc.path, got, tc.ignore)
		}
	}
}

// TestAllowlist_ShouldIgnoreFile_RecursiveGlob proves the globmatch migration
// fixes the segment-bounded filepath.Match bug: a "vendor/**" pattern now
// excludes deeply nested files, which filepath.Match silently failed to match.
func TestAllowlist_ShouldIgnoreFile_RecursiveGlob(t *testing.T) {
	allowlist := NewAllowlist()
	allowlist.AddPath("vendor/**", "vendor tree")
	allowlist.AddPath("node_modules/**", "node deps")

	tests := []struct {
		path   string
		ignore bool
	}{
		{"vendor/sub/secret.env", true}, // nested: the bug
		{"vendor/x.go", true},           // direct child
		{"a/node_modules/b/c.js", true}, // bare-name any depth
		{"src/main.go", false},          // unrelated
	}
	for _, tc := range tests {
		if got := allowlist.ShouldIgnoreFile(tc.path); got != tc.ignore {
			t.Errorf("ShouldIgnoreFile(%q) = %v, want %v", tc.path, got, tc.ignore)
		}
	}
}

// TestMatchesPathFilter_RecursiveGlob proves matchesPathFilter matches nested
// files under a "dir/**" pattern after the globmatch migration.
func TestMatchesPathFilter_RecursiveGlob(t *testing.T) {
	patterns := []string{"vendor/**"}
	if !matchesPathFilter("vendor/sub/secret.env", patterns) {
		t.Errorf("matchesPathFilter should match nested vendor file")
	}
	if matchesPathFilter("src/main.go", patterns) {
		t.Errorf("matchesPathFilter should not match unrelated file")
	}
}

func TestBaselineScanner(t *testing.T) {
	ctx := context.Background()

	// Create a mock scanner that returns fixed findings
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	// Create baseline with one known finding
	baseline := NewBaseline()
	baseline.AddFinding(Finding{
		Type:  TypeGitHubToken,
		File:  "test.txt",
		Line:  1,
		Value: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}, "known test token")

	// Wrap scanner
	baselineScanner := NewBaselineScanner(engine, baseline)

	// Scan content with known token
	content := []byte("token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n")
	findings, err := baselineScanner.ScanFile(ctx, "test.txt", content)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// Known token should be filtered out
	if len(findings) != 0 {
		t.Errorf("expected 0 findings (known filtered), got %d", len(findings))
	}

	// Scan with different token
	content2 := []byte("token = ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy\n")
	findings2, err := baselineScanner.ScanFile(ctx, "other.txt", content2)
	if err != nil {
		t.Fatalf("ScanFile failed: %v", err)
	}

	// New token should be reported
	if len(findings2) != 1 {
		t.Errorf("expected 1 finding (new token), got %d", len(findings2))
	}
}

func TestParseInlineAllowlist(t *testing.T) {
	tests := []struct {
		name    string
		lines   []string
		lineNum int
		allowed bool
		reason  string
	}{
		{
			name:    "trailing comment",
			lines:   []string{"token = ghp_xxx // deputy:allowlist:test token"},
			lineNum: 1,
			allowed: true,
			reason:  "test token",
		},
		{
			name:    "previous line comment",
			lines:   []string{"// deputy:allowlist:test fixture", "SECRET_KEY = xxx"},
			lineNum: 2,
			allowed: true,
			reason:  "test fixture",
		},
		{
			name:    "no allowlist",
			lines:   []string{"token = ghp_xxx"},
			lineNum: 1,
			allowed: false,
			reason:  "",
		},
		{
			name:    "hash comment",
			lines:   []string{"API_KEY = xxx # deputy:allowlist testing"},
			lineNum: 1,
			allowed: true,
			reason:  "testing",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			allowed, reason := ParseInlineAllowlist(tc.lines, tc.lineNum)
			if allowed != tc.allowed {
				t.Errorf("allowed = %v, want %v", allowed, tc.allowed)
			}
			if reason != tc.reason {
				t.Errorf("reason = %q, want %q", reason, tc.reason)
			}
		})
	}
}

func TestInlineAllowlistScanner(t *testing.T) {
	ctx := context.Background()

	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	scanner := NewInlineAllowlistScanner(engine)

	// Content with inline allowlist
	content := []byte(`// deputy:allowlist:test fixture
token = ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx
other = ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy
`)

	findings, err := scanner.Scan(ctx, content)
	if err != nil {
		t.Fatalf("Scan failed: %v", err)
	}

	// First token should be filtered (has allowlist comment)
	// Second token should be reported
	if len(findings) != 1 {
		t.Errorf("expected 1 finding, got %d", len(findings))
	}
}

func TestHashFinding(t *testing.T) {
	f1 := Finding{
		Type:  TypeGitHubToken,
		Value: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	f2 := Finding{
		Type:  TypeGitHubToken,
		Value: "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx",
	}
	f3 := Finding{
		Type:  TypeGitHubToken,
		Value: "ghp_yyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyyy",
	}

	h1 := HashFinding(f1)
	h2 := HashFinding(f2)
	h3 := HashFinding(f3)

	// Same content should produce same hash
	if h1 != h2 {
		t.Errorf("same findings should have same hash: %s != %s", h1, h2)
	}

	// Different content should produce different hash
	if h1 == h3 {
		t.Error("different findings should have different hashes")
	}
}

func TestBaseline_TotalEntries(t *testing.T) {
	baseline := NewBaseline()

	if baseline.TotalEntries() != 0 {
		t.Errorf("new baseline should have 0 entries, got %d", baseline.TotalEntries())
	}

	baseline.AddFinding(Finding{Type: TypeGitHubToken, File: "a.go", Line: 1, Value: "ghp_x"}, "")
	baseline.AddFinding(Finding{Type: TypeAWSAccessKey, File: "b.go", Line: 1, Value: "AKIAX"}, "")
	baseline.AddFinding(Finding{Type: TypeSlackToken, File: "a.go", Line: 2, Value: "xoxb-x"}, "")

	if baseline.TotalEntries() != 3 {
		t.Errorf("expected 3 entries, got %d", baseline.TotalEntries())
	}
}

func TestBaseline_Files(t *testing.T) {
	baseline := NewBaseline()
	baseline.AddFinding(Finding{Type: TypeGitHubToken, File: "zebra.go", Line: 1, Value: "ghp_x"}, "")
	baseline.AddFinding(Finding{Type: TypeAWSAccessKey, File: "alpha.go", Line: 1, Value: "AKIAX"}, "")
	baseline.AddFinding(Finding{Type: TypeSlackToken, File: "beta.go", Line: 1, Value: "xoxb-x"}, "")

	files := baseline.Files()

	// Should be sorted
	expected := []string{"alpha.go", "beta.go", "zebra.go"}
	if len(files) != len(expected) {
		t.Fatalf("expected %d files, got %d", len(expected), len(files))
	}
	for i, f := range files {
		if f != expected[i] {
			t.Errorf("file[%d] = %q, want %q", i, f, expected[i])
		}
	}
}

func TestBaseline_Merge(t *testing.T) {
	baseline1 := NewBaseline()
	baseline1.AddFinding(Finding{Type: TypeGitHubToken, File: "a.go", Line: 1, Value: "ghp_x"}, "")

	baseline2 := NewBaseline()
	baseline2.AddFinding(Finding{Type: TypeAWSAccessKey, File: "b.go", Line: 1, Value: "AKIAX"}, "")
	baseline2.AddFinding(Finding{Type: TypeSlackToken, File: "a.go", Line: 2, Value: "xoxb-x"}, "") // Same file as baseline1

	baseline1.Merge(baseline2)

	if baseline1.TotalEntries() != 3 {
		t.Errorf("expected 3 entries after merge, got %d", baseline1.TotalEntries())
	}
	if len(baseline1.Results["a.go"]) != 2 {
		t.Errorf("expected 2 entries for a.go, got %d", len(baseline1.Results["a.go"]))
	}
}

func TestGenerateBaseline(t *testing.T) {
	ctx := context.Background()

	// Create temp directory with test files
	tmpDir := t.TempDir()

	// Create file with secret
	testFile := filepath.Join(tmpDir, "config.go")
	content := `package config

const Token = "ghp_xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx"
`
	if err := os.WriteFile(testFile, []byte(content), 0644); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Generate baseline
	engine, err := NewEngine()
	if err != nil {
		t.Fatalf("NewEngine failed: %v", err)
	}

	baseline, err := GenerateBaseline(ctx, engine, tmpDir, "initial baseline")
	if err != nil {
		t.Fatalf("GenerateBaseline failed: %v", err)
	}

	if baseline.TotalEntries() == 0 {
		t.Error("expected at least one entry in generated baseline")
	}

	// Check that the finding is in the baseline
	entries := baseline.Results["config.go"]
	if len(entries) == 0 {
		t.Error("expected entry for config.go")
	}
}
