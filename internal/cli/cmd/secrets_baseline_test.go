package cmd

import (
	"bytes"
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/secrets"
)

// fakeScanner is a Scanner whose behaviour per file is decided by the test. The walks
// under test are about what happens when reading or scanning fails, so driving the
// failure directly is more honest than arranging for the real engine to break.
type fakeScanner struct {
	// findFor returns findings for a file; a nil entry means "clean".
	findFor map[string][]secrets.Finding
	// failFor names files the scanner refuses, and the error it returns for them.
	failFor map[string]error
}

func (f *fakeScanner) Scan(ctx context.Context, content []byte) ([]secrets.Finding, error) {
	return nil, nil
}

func (f *fakeScanner) ScanFile(ctx context.Context, filename string, content []byte) ([]secrets.Finding, error) {
	if err, ok := f.failFor[filename]; ok {
		return nil, err
	}
	return f.findFor[filename], nil
}

var _ secrets.Scanner = (*fakeScanner)(nil)

// writeUnreadable creates a file the current user cannot read, and skips the test when
// that is not achievable — running as root, or on a filesystem that ignores the mode.
// The check is done by attempting the read rather than by inspecting the uid, because
// the thing the test needs is the read failing, not a proxy for it.
func writeUnreadable(t *testing.T, dir, name string) string {
	t.Helper()

	path := filepath.Join(dir, name)
	if err := os.WriteFile(path, []byte("token = \"unreadable\"\n"), 0o600); err != nil {
		t.Fatalf("writing %s: %v", name, err)
	}
	if err := os.Chmod(path, 0o000); err != nil {
		t.Fatalf("chmod %s: %v", name, err)
	}
	t.Cleanup(func() { _ = os.Chmod(path, 0o600) })

	if _, err := os.ReadFile(path); err == nil {
		t.Skip("cannot make a file unreadable here (running as root?); skipping")
	}
	return path
}

// TestGenerateBaselineCountsUnreadableFiles is the bug in #309, asserted against the
// kernel rather than against a mock: a file that genuinely cannot be read is dropped from
// the baseline, and before this change it was dropped silently. The baseline is a claim
// about what the repository contains, so the omission has to be reported.
func TestGenerateBaselineCountsUnreadableFiles(t *testing.T) {
	dir := t.TempDir()
	writeUnreadable(t, dir, "secret.env")
	if err := os.WriteFile(filepath.Join(dir, "ok.env"), []byte("token = \"visible\"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	sc := &fakeScanner{findFor: map[string][]secrets.Finding{
		"ok.env": {{File: "ok.env", Line: 1, Type: "test_token"}},
	}}

	baseline, skips, err := generateBaselineWithExcludes(context.Background(), sc, dir, "test", nil)
	if err != nil {
		t.Fatalf("generateBaselineWithExcludes: %v", err)
	}

	if got := len(skips.Unreadable); got != 1 {
		t.Fatalf("unreadable files recorded = %d, want 1 (skips=%+v)", got, skips)
	}
	if got := skips.Unreadable[0].Path; got != "secret.env" {
		t.Errorf("unreadable path = %q, want %q", got, "secret.env")
	}
	if skips.Unreadable[0].Err == nil {
		t.Error("unreadable entry carries no error; the reason is the useful half")
	}
	if got := len(skips.Unscannable); got != 0 {
		t.Errorf("unscannable = %d, want 0: a read failure is not a scanner defect", got)
	}
	if got := skips.Total(); got != 1 {
		t.Errorf("Total() = %d, want 1", got)
	}

	// The readable file still makes it in — reporting the gap must not shrink the result.
	if got := baseline.TotalEntries(); got != 1 {
		t.Errorf("baseline entries = %d, want 1", got)
	}
}

// TestGenerateBaselineCountsScanErrors pins the other half of the issue's Direction: a
// scan failure is a defect in the scanner, so it is kept apart from a routine read
// failure rather than collapsed into one count.
func TestGenerateBaselineCountsScanErrors(t *testing.T) {
	dir := t.TempDir()
	for _, n := range []string{"a.env", "b.env"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	boom := errors.New("detector panic recovered")
	sc := &fakeScanner{failFor: map[string]error{"b.env": boom}}

	_, skips, err := generateBaselineWithExcludes(context.Background(), sc, dir, "test", nil)
	if err != nil {
		t.Fatalf("generateBaselineWithExcludes: %v", err)
	}

	if got := len(skips.Unscannable); got != 1 {
		t.Fatalf("unscannable = %d, want 1", got)
	}
	if got := skips.Unscannable[0].Path; got != "b.env" {
		t.Errorf("unscannable path = %q, want %q", got, "b.env")
	}
	if !errors.Is(skips.Unscannable[0].Err, boom) {
		t.Errorf("scanner error not preserved: %v", skips.Unscannable[0].Err)
	}
	if got := len(skips.Unreadable); got != 0 {
		t.Errorf("unreadable = %d, want 0", got)
	}
}

// TestGenerateBaselineCleanWalkReportsNothing is the case that must stay quiet. A
// diagnostic that fires on every clean run is one nobody reads by the second week.
func TestGenerateBaselineCleanWalkReportsNothing(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "a.env"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	_, skips, err := generateBaselineWithExcludes(context.Background(), &fakeScanner{}, dir, "test", nil)
	if err != nil {
		t.Fatalf("generateBaselineWithExcludes: %v", err)
	}
	if got := skips.Total(); got != 0 {
		t.Fatalf("Total() = %d, want 0", got)
	}

	var buf bytes.Buffer
	skips.report(&buf)
	if buf.Len() != 0 {
		t.Errorf("clean walk wrote a diagnostic: %q", buf.String())
	}
}

// TestScanDirectoryForBaselineCountsSkips covers the second walk in the same file. It is
// a separate test because the two functions were fixed together and a regression that
// touched only one of them is exactly how this bug survived the first time.
func TestScanDirectoryForBaselineCountsSkips(t *testing.T) {
	dir := t.TempDir()
	writeUnreadable(t, dir, "locked.env")
	for _, n := range []string{"a.env", "bad.env"} {
		if err := os.WriteFile(filepath.Join(dir, n), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	sc := &fakeScanner{
		findFor: map[string][]secrets.Finding{"a.env": {{File: "a.env", Line: 1, Type: "test_token"}}},
		failFor: map[string]error{"bad.env": errors.New("scan failed")},
	}

	findings, skips, err := scanDirectoryForBaseline(context.Background(), sc, dir)
	if err != nil {
		t.Fatalf("scanDirectoryForBaseline: %v", err)
	}

	if got := len(findings); got != 1 {
		t.Errorf("findings = %d, want 1", got)
	}
	if got, want := len(skips.Unreadable), 1; got != want {
		t.Errorf("unreadable = %d, want %d", got, want)
	}
	if got, want := len(skips.Unscannable), 1; got != want {
		t.Errorf("unscannable = %d, want %d", got, want)
	}
	if got := skips.Total(); got != 2 {
		t.Errorf("Total() = %d, want 2", got)
	}
}

// TestBaselineSkipsReport pins what the operator actually sees, because the whole issue
// is that the operator saw nothing.
func TestBaselineSkipsReport(t *testing.T) {
	s := &baselineSkips{
		Unreadable:  []skippedFile{{Path: "z.env", Err: os.ErrPermission}, {Path: "a.env", Err: os.ErrPermission}},
		Unscannable: []skippedFile{{Path: "broken.env", Err: errors.New("detector blew up")}},
	}

	var buf bytes.Buffer
	s.report(&buf)
	out := buf.String()

	for _, want := range []string{
		"could not be scanned",
		"broken.env",
		"detector blew up",
		"could not be read",
		"a.env",
		"z.env",
		// The sentence that stops the result reading as complete.
		"covers only the files that could be scanned",
		"3 files skipped",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("report missing %q; got:\n%s", want, out)
		}
	}

	// Deterministic order, so the same tree produces the same bytes twice.
	if strings.Index(out, "a.env") > strings.Index(out, "z.env") {
		t.Errorf("unreadable files not sorted by path; got:\n%s", out)
	}
}

// TestBaselineSkipsReportElidesLongUnreadableList: a walk over a tree the user mostly
// cannot read can skip thousands of files, and a list that scrolls the scan errors off
// the screen is a worse diagnostic than a count. The count stays exact either way.
func TestBaselineSkipsReportElidesLongUnreadableList(t *testing.T) {
	s := &baselineSkips{}
	for _, n := range []string{"01", "02", "03", "04", "05", "06", "07", "08", "09", "10", "11", "12"} {
		s.addUnreadable(n+".env", os.ErrPermission)
	}

	var buf bytes.Buffer
	s.report(&buf)
	out := buf.String()

	if !strings.Contains(out, "12 files could not be read") {
		t.Errorf("count is not exact; got:\n%s", out)
	}
	if !strings.Contains(out, "and 2 more") {
		t.Errorf("elision not reported; got:\n%s", out)
	}
	if strings.Contains(out, "12.env") {
		t.Errorf("list was not capped; got:\n%s", out)
	}
}

// TestBaselineSkipsTotalNil: Total is read on the create path before anything guarantees
// a non-nil value, so a nil receiver must answer 0 rather than panic.
func TestBaselineSkipsTotalNil(t *testing.T) {
	var s *baselineSkips
	if got := s.Total(); got != 0 {
		t.Errorf("nil Total() = %d, want 0", got)
	}
}

// TestPluralFiles keeps the diagnostic from saying "1 files".
func TestPluralFiles(t *testing.T) {
	for _, tt := range []struct {
		n    int
		want string
	}{{0, "0 files"}, {1, "1 file"}, {2, "2 files"}} {
		if got := pluralFiles(tt.n); got != tt.want {
			t.Errorf("pluralFiles(%d) = %q, want %q", tt.n, got, tt.want)
		}
	}
}
