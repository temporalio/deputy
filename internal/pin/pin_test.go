package pin

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"regexp"
	"strings"
	"testing"

	scalibrfs "github.com/google/osv-scalibr/fs"
)

// testRoot creates an os.Root for testing using a temp directory.
func testRoot(t *testing.T) *os.Root {
	t.Helper()
	root, err := os.OpenRoot(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// mockStrategy implements Strategy for testing.
type mockStrategy struct {
	refs          []Ref
	resolveErr    error
	verifyErr     error
	rewriteErr    error
	resolved      map[string]struct{ sha, tag string }
	verified      map[string]*Verification
	rewrites      []rewriteCall
	updateResults map[string]struct{ sha, newTag, curTag string }
	updateErr     error
}

type rewriteCall struct {
	path    string
	updates []Update
}

func (m *mockStrategy) Ecosystem() string { return "mock" }

func (m *mockStrategy) IsPinned(ref Ref) bool {
	return ref.IsSHAPinned()
}

func (m *mockStrategy) ShouldSkip(ref Ref) (bool, string) {
	if strings.Contains(ref.Version, "${{") {
		return true, "expression ref"
	}
	return false, ""
}

func (m *mockStrategy) Discover(_ context.Context, _ scalibrfs.FS) ([]Ref, error) {
	return m.refs, nil
}

func (m *mockStrategy) Resolve(_ context.Context, ref Ref) (string, string, error) {
	if m.resolveErr != nil {
		return "", "", m.resolveErr
	}
	if r, ok := m.resolved[ref.Name+"@"+ref.Version]; ok {
		return r.sha, r.tag, nil
	}
	return "abc123def456abc123def456abc123def456abc1", ref.Version, nil
}

func (m *mockStrategy) Verify(_ context.Context, ref Ref) (*Verification, error) {
	if m.verifyErr != nil {
		return nil, m.verifyErr
	}
	if v, ok := m.verified[ref.Version]; ok {
		return v, nil
	}
	return &Verification{
		SignatureValid: true,
		OnBranch:       true,
		BranchName:     "main",
	}, nil
}

func (m *mockStrategy) Rewrite(_ *os.Root, path string, updates []Update) error {
	if m.rewriteErr != nil {
		return m.rewriteErr
	}
	m.rewrites = append(m.rewrites, rewriteCall{path: path, updates: updates})
	return nil
}

func (m *mockStrategy) ResolveUpdate(_ context.Context, ref Ref) (string, string, string, error) {
	if m.updateErr != nil {
		return "", "", "", m.updateErr
	}
	if r, ok := m.updateResults[ref.Version]; ok {
		return r.sha, r.newTag, r.curTag, nil
	}
	// Default: no update available.
	return ref.Version, "v1.0.0", "v1.0.0", nil
}

// containerMockStrategy mocks a container pinning strategy for orchestrator
// tests. It does regex-based container rewriting (name:tag → name:tag@digest).
type containerMockStrategy struct {
	refs   []Ref
	digest string
}

func (m *containerMockStrategy) Ecosystem() string { return "container" }
func (m *containerMockStrategy) IsPinned(ref Ref) bool {
	return strings.Contains(ref.Version, "sha256:")
}
func (m *containerMockStrategy) ShouldSkip(_ Ref) (bool, string) { return false, "" }
func (m *containerMockStrategy) Discover(_ context.Context, _ scalibrfs.FS) ([]Ref, error) {
	return m.refs, nil
}
func (m *containerMockStrategy) Resolve(_ context.Context, ref Ref) (string, string, error) {
	return m.digest, ref.Version, nil
}
func (m *containerMockStrategy) Verify(_ context.Context, _ Ref) (*Verification, error) {
	return nil, nil
}
func (m *containerMockStrategy) ResolveUpdate(_ context.Context, ref Ref) (string, string, string, error) {
	return ref.Version, "", "", nil
}
func (m *containerMockStrategy) Rewrite(root *os.Root, relPath string, updates []Update) error {
	if len(updates) == 0 {
		return nil
	}
	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return err
	}
	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return err
	}
	contentStr := string(content)
	modified := false
	for _, u := range updates {
		pattern := fmt.Sprintf(`%s:%s(@sha256:[a-fA-F0-9]+)?`, regexp.QuoteMeta(u.Name), regexp.QuoteMeta(u.VersionTag))
		re := regexp.MustCompile(pattern)
		replacement := fmt.Sprintf("%s:%s@%s", u.Name, u.VersionTag, u.PinnedValue)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}
	if !modified {
		return nil
	}
	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(contentStr))
	return err
}

func TestPin_BasicPinning(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "v5", FilePath: "/tmp/ci.yml"},
		},
		resolved: map[string]struct{ sha, tag string }{
			"actions/checkout@v4": {"aaa1111111111111111111111111111111111111", "v4.2.2"},
			"actions/setup-go@v5": {"bbb2222222222222222222222222222222222222", "v5.4.0"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Pinned != 2 {
		t.Errorf("expected 2 pinned, got %d", report.Stats.Pinned)
	}
	if report.Stats.Total != 2 {
		t.Errorf("expected 2 total, got %d", report.Stats.Total)
	}
	if len(strategy.rewrites) != 1 {
		t.Errorf("expected 1 rewrite call, got %d", len(strategy.rewrites))
	}
}

func TestPin_VerificationModes(t *testing.T) {
	const sha = "aaa1111111111111111111111111111111111111"
	newStrategy := func(v *Verification) *mockStrategy {
		return &mockStrategy{
			refs: []Ref{{Ecosystem: "mock", Name: "aws-actions/amazon-ecr-login", Version: "v1", FilePath: "/tmp/ci.yml"}},
			resolved: map[string]struct{ sha, tag string }{
				"aws-actions/amazon-ecr-login@v1": {sha, "v1.0.0"},
			},
			verified: map[string]*Verification{sha: v},
		}
	}
	// flagged mirrors a legitimate old-major/off-default-branch release: unsigned
	// and not reachable from the default branch, which the verifier flags.
	flagged := &Verification{IsForkCommit: true, Warnings: []string{"possible imposter commit from fork"}}
	unverifiable := &Verification{Unverifiable: true, Warnings: []string{"could not verify branch reachability: rate limited"}}

	t.Run("warn pins flagged ref and reports it", func(t *testing.T) {
		s := newStrategy(flagged)
		report, err := Pin(context.Background(), testRoot(t), Options{Verification: VerificationWarn}, s)
		if err != nil {
			t.Fatal(err)
		}
		if report.Stats.Pinned != 1 || report.Stats.Suspicious != 0 || report.Stats.Flagged != 1 {
			t.Errorf("warn: pinned=%d suspicious=%d flagged=%d, want 1/0/1",
				report.Stats.Pinned, report.Stats.Suspicious, report.Stats.Flagged)
		}
		if len(s.rewrites) != 1 {
			t.Errorf("warn: flagged ref should still be written, rewrites=%d", len(s.rewrites))
		}
	})

	t.Run("default mode is warn", func(t *testing.T) {
		s := newStrategy(flagged)
		report, err := Pin(context.Background(), testRoot(t), Options{}, s)
		if err != nil {
			t.Fatal(err)
		}
		if report.Stats.Pinned != 1 || report.Stats.Suspicious != 0 {
			t.Errorf("default: pinned=%d suspicious=%d, want 1/0 (warn)", report.Stats.Pinned, report.Stats.Suspicious)
		}
	})

	t.Run("error leaves flagged ref unpinned", func(t *testing.T) {
		s := newStrategy(flagged)
		report, err := Pin(context.Background(), testRoot(t), Options{Verification: VerificationError}, s)
		if err != nil {
			t.Fatal(err)
		}
		if report.Stats.Suspicious != 1 || report.Stats.Pinned != 0 {
			t.Errorf("error: suspicious=%d pinned=%d, want 1/0", report.Stats.Suspicious, report.Stats.Pinned)
		}
		if len(s.rewrites) != 0 {
			t.Errorf("error: flagged ref must not be written, rewrites=%d", len(s.rewrites))
		}
	})

	t.Run("unverifiable is never an imposter", func(t *testing.T) {
		for _, mode := range []VerificationMode{VerificationWarn, VerificationError} {
			s := newStrategy(unverifiable)
			report, err := Pin(context.Background(), testRoot(t), Options{Verification: mode}, s)
			if err != nil {
				t.Fatal(err)
			}
			if report.Stats.Suspicious != 0 {
				t.Errorf("mode %s: unverifiable must not be suspicious, got %d", mode, report.Stats.Suspicious)
			}
			if report.Stats.Pinned != 1 || report.Stats.Unverifiable != 1 {
				t.Errorf("mode %s: pinned=%d unverifiable=%d, want 1/1", mode, report.Stats.Pinned, report.Stats.Unverifiable)
			}
		}
	})

	t.Run("off skips verification entirely", func(t *testing.T) {
		s := newStrategy(flagged)
		report, err := Pin(context.Background(), testRoot(t), Options{Verification: VerificationOff}, s)
		if err != nil {
			t.Fatal(err)
		}
		if report.Stats.Pinned != 1 || report.Stats.Flagged != 0 {
			t.Errorf("off: pinned=%d flagged=%d, want 1/0", report.Stats.Pinned, report.Stats.Flagged)
		}
	})
}

func TestPin_DryRun(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{DryRun: true, SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Pinned != 1 {
		t.Errorf("expected 1 pinned, got %d", report.Stats.Pinned)
	}
	if len(strategy.rewrites) != 0 {
		t.Error("expected no rewrites in dry-run mode")
	}
}

func TestVerify_Basic(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "v5", FilePath: "/tmp/ci.yml"},
		},
		verified: map[string]*Verification{
			sha: {SignatureValid: true, OnBranch: true, BranchName: "main"},
		},
	}

	report, err := Verify(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	// SHA-pinned action should be verified
	if report.Stats.Verified != 1 {
		t.Errorf("expected 1 verified, got %d", report.Stats.Verified)
	}
	// Tag-pinned action should be skipped (not pinned to immutable ref)
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Stats.Skipped)
	}
	if len(strategy.rewrites) != 0 {
		t.Error("expected no rewrites in verify mode")
	}
}

func TestVerify_Suspicious(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
		verified: map[string]*Verification{
			sha: {IsForkCommit: true, Warnings: []string{"possible imposter commit"}},
		},
	}

	report, err := Verify(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Suspicious != 1 {
		t.Errorf("expected 1 suspicious, got %d", report.Stats.Suspicious)
	}
}

func TestVerify_NoVerifierAvailable(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	// A strategy where Verify returns (nil, nil) — no verifier configured.
	strategy := &nilVerifyStrategy{
		mockStrategy: mockStrategy{
			refs: []Ref{
				{Ecosystem: "mock", Name: "alpine", Version: sha, FilePath: "/tmp/Dockerfile"},
			},
		},
	}

	report, err := Verify(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	// Should NOT be counted as verified — should be already-pinned.
	if report.Stats.Verified != 0 {
		t.Errorf("expected 0 verified (no verifier), got %d", report.Stats.Verified)
	}
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned, got %d", report.Stats.AlreadyPinned)
	}
	r := report.Results[0]
	if !strings.Contains(r.Reason, "no pin-time provenance check") {
		t.Errorf("expected reason about no pin-time provenance check, got %q", r.Reason)
	}
}

// nilVerifyStrategy returns (nil, nil) from Verify, simulating an ecosystem
// without provenance checking (e.g., container images).
type nilVerifyStrategy struct {
	mockStrategy
}

func (s *nilVerifyStrategy) Verify(_ context.Context, _ Ref) (*Verification, error) {
	return nil, nil
}

func TestVerify_Error(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
		verifyErr: fmt.Errorf("API rate limit exceeded"),
	}

	report, err := Verify(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Errors != 1 {
		t.Errorf("expected 1 error, got %d", report.Stats.Errors)
	}
}

func TestPin_AlreadyPinned(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned, got %d", report.Stats.AlreadyPinned)
	}
}

func TestPin_SkippedExpressionRef(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "${{ matrix.version }}", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Stats.Skipped)
	}
	if report.Results[0].Reason != "expression ref" {
		t.Errorf("expected reason 'expression ref', got %q", report.Results[0].Reason)
	}
}

func TestPin_ResolutionError(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
		resolveErr: fmt.Errorf("rate limit exceeded"),
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Errors != 1 {
		t.Errorf("expected 1 error, got %d", report.Stats.Errors)
	}
}

func TestPin_Suspicious(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
		verified: map[string]*Verification{
			"abc123def456abc123def456abc123def456abc1": {
				IsForkCommit: true,
				Warnings:     []string{"possible imposter commit"},
			},
		},
	}

	// In error mode a flagged ref is left unpinned and counted suspicious.
	report, err := Pin(context.Background(), testRoot(t), Options{Verification: VerificationError}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Suspicious != 1 {
		t.Errorf("expected 1 suspicious, got %d", report.Stats.Suspicious)
	}
}

func TestPin_MixedResults(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: sha, FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "foo/bar", Version: "${{ inputs.ref }}", FilePath: "/tmp/ci.yml"},
		},
		resolved: map[string]struct{ sha, tag string }{
			"actions/checkout@v4": {"abc123def456abc123def456abc123def456abc1", "v4.2.2"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	if report.Stats.Total != 3 {
		t.Errorf("expected 3 total, got %d", report.Stats.Total)
	}
	if report.Stats.Pinned != 1 {
		t.Errorf("expected 1 pinned, got %d", report.Stats.Pinned)
	}
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned, got %d", report.Stats.AlreadyPinned)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Stats.Skipped)
	}
}

func TestRef_IsSHAPinned(t *testing.T) {
	tests := []struct {
		version string
		want    bool
	}{
		{"11bd71901bbe5b1630ceea73d27597364c9af683", true},
		{"AABBCCDD11223344556677889900aabbccddeeff", true},
		{"v4", false},
		{"v4.2.2", false},
		{"main", false},
		{"abc123", false},     // too short
		{"", false},           // empty
		{"${{ foo }}", false}, // expression
	}

	for _, tc := range tests {
		t.Run(tc.version, func(t *testing.T) {
			r := Ref{Version: tc.version}
			if got := r.IsSHAPinned(); got != tc.want {
				t.Errorf("IsSHAPinned(%q) = %v, want %v", tc.version, got, tc.want)
			}
		})
	}
}

func TestPin_ContextCancellation(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel() // cancel immediately

	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Pin(ctx, testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	// The single ref should have an error from context cancellation
	if report.Stats.Errors != 1 {
		t.Errorf("expected 1 error from cancellation, got %d errors", report.Stats.Errors)
	}
}

func TestPin_VerificationErrorReported(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
		verifyErr: fmt.Errorf("API rate limit exceeded"),
	}

	report, err := Pin(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}

	// Should still be already-pinned, with a reason noting verification was
	// unavailable (a failed verify call is "unknown", not a confirmed imposter).
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned, got stats: %+v", report.Stats)
	}
	r := report.Results[0]
	if !strings.Contains(r.Reason, "verification unavailable") {
		t.Errorf("expected reason to mention verification unavailable, got %q", r.Reason)
	}
}

func TestOptions_Concurrency(t *testing.T) {
	tests := []struct {
		input int
		want  int
	}{
		{0, 4},  // zero defaults to 4
		{-1, 4}, // negative defaults to 4
		{1, 1},  // explicit 1
		{8, 8},  // explicit 8
		{100, 100},
	}
	for _, tc := range tests {
		o := Options{Concurrency: tc.input}
		if got := o.concurrency(); got != tc.want {
			t.Errorf("Options{Concurrency: %d}.concurrency() = %d, want %d", tc.input, got, tc.want)
		}
	}
}

func TestPin_EmptyRefs(t *testing.T) {
	strategy := &mockStrategy{refs: nil}
	report, err := Pin(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Total != 0 {
		t.Errorf("expected 0 total, got %d", report.Stats.Total)
	}
}

func TestPin_MultipleStrategies(t *testing.T) {
	s1 := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock1", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
	}
	s2 := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock2", Name: "docker/image", Version: "v1", FilePath: "/tmp/Dockerfile"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, s1, s2)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Total != 2 {
		t.Errorf("expected 2 total from two strategies, got %d", report.Stats.Total)
	}
	if report.Stats.Pinned != 2 {
		t.Errorf("expected 2 pinned, got %d", report.Stats.Pinned)
	}
}

func TestPin_WriteStrategyError(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
		rewriteErr: fmt.Errorf("permission denied"),
	}

	_, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err == nil {
		t.Fatal("expected error from rewrite failure")
	}
	if !strings.Contains(err.Error(), "permission denied") {
		t.Errorf("error should mention root cause, got: %v", err)
	}
}

func TestRef_DisplayName(t *testing.T) {
	tests := []struct {
		name    string
		subpath string
		want    string
	}{
		{"actions/checkout", "", "actions/checkout"},
		{"github/codeql-action", "init", "github/codeql-action/init"},
	}

	for _, tc := range tests {
		ref := Ref{Name: tc.name, Subpath: tc.subpath}
		if got := ref.DisplayName(); got != tc.want {
			t.Errorf("DisplayName() = %q, want %q", got, tc.want)
		}
	}
}

// TestPin_StrategyIsPinnedUsed verifies that the core orchestrator dispatches
// to strategy.IsPinned() rather than using a hardcoded check. A custom strategy
// that considers "PINNED" as already-pinned should work.
func TestPin_StrategyIsPinnedUsed(t *testing.T) {
	strategy := &customPinStrategy{
		mockStrategy: mockStrategy{
			refs: []Ref{
				{Ecosystem: "custom", Name: "dep/a", Version: "PINNED", FilePath: "/tmp/f.yml"},
				{Ecosystem: "custom", Name: "dep/b", Version: "v1", FilePath: "/tmp/f.yml"},
			},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned (custom IsPinned), got %d", report.Stats.AlreadyPinned)
	}
	if report.Stats.Pinned != 1 {
		t.Errorf("expected 1 pinned, got %d", report.Stats.Pinned)
	}
}

// TestPin_StrategyShouldSkipUsed verifies that the core orchestrator dispatches
// to strategy.ShouldSkip() rather than using a hardcoded expression check.
func TestPin_StrategyShouldSkipUsed(t *testing.T) {
	strategy := &customPinStrategy{
		mockStrategy: mockStrategy{
			refs: []Ref{
				{Ecosystem: "custom", Name: "dep/a", Version: "${VAR}", FilePath: "/tmp/f.yml"},
				{Ecosystem: "custom", Name: "dep/b", Version: "v1", FilePath: "/tmp/f.yml"},
			},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped (custom ShouldSkip for ${VAR}), got %d", report.Stats.Skipped)
	}
	if report.Results[0].Reason != "variable substitution" {
		t.Errorf("expected reason 'variable substitution', got %q", report.Results[0].Reason)
	}
}

// customPinStrategy wraps mockStrategy but overrides IsPinned and ShouldSkip
// to prove the core doesn't hardcode GitHub Actions behavior.
type customPinStrategy struct {
	mockStrategy
}

func (c *customPinStrategy) Ecosystem() string { return "custom" }

func (c *customPinStrategy) IsPinned(ref Ref) bool {
	return ref.Version == "PINNED"
}

func (c *customPinStrategy) ShouldSkip(ref Ref) (bool, string) {
	if strings.Contains(ref.Version, "${") {
		return true, "variable substitution"
	}
	return false, ""
}

// --- Check tests ---

func TestCheck_AllPinned(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "aabbccdd11223344556677889900aabbccddeeff", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Check(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.AlreadyPinned != 2 {
		t.Errorf("expected 2 already-pinned, got %d", report.Stats.AlreadyPinned)
	}
	if report.Stats.Unpinned != 0 {
		t.Errorf("expected 0 unpinned, got %d", report.Stats.Unpinned)
	}
}

func TestCheck_HasUnpinned(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "v5", FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/cache", Version: "main", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Check(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned, got %d", report.Stats.AlreadyPinned)
	}
	if report.Stats.Unpinned != 2 {
		t.Errorf("expected 2 unpinned, got %d", report.Stats.Unpinned)
	}
}

func TestCheck_WithExclude(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "v5", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Check(context.Background(), testRoot(t), Options{
		Exclude: []string{"actions/checkout"},
	}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped (excluded), got %d", report.Stats.Skipped)
	}
	if report.Stats.Unpinned != 1 {
		t.Errorf("expected 1 unpinned, got %d", report.Stats.Unpinned)
	}
}

func TestCheck_SkipsExpressions(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "${{ matrix.v }}", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Check(context.Background(), testRoot(t), Options{}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Stats.Skipped)
	}
}

// --- Update tests ---

func TestUpdate_BasicUpdate(t *testing.T) {
	oldSHA := "11bd71901bbe5b1630ceea73d27597364c9af683"
	newSHA := "aabbccdd11223344556677889900aabbccddeeff"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: oldSHA, FilePath: "/tmp/ci.yml"},
		},
		updateResults: map[string]struct{ sha, newTag, curTag string }{
			oldSHA: {newSHA, "v4.3.0", "v4.2.2"},
		},
	}

	report, err := PinUpdate(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", report.Stats.Updated)
	}
	if len(strategy.rewrites) != 1 {
		t.Errorf("expected 1 rewrite call, got %d", len(strategy.rewrites))
	}
	if report.Results[0].PinnedValue != newSHA {
		t.Errorf("expected pinned value %s, got %s", newSHA, report.Results[0].PinnedValue)
	}
}

func TestUpdate_NoChange(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
		updateResults: map[string]struct{ sha, newTag, curTag string }{
			sha: {sha, "v4.2.2", "v4.2.2"}, // same SHA = no update
		},
	}

	report, err := PinUpdate(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.AlreadyPinned != 1 {
		t.Errorf("expected 1 already-pinned (no update), got %d", report.Stats.AlreadyPinned)
	}
	if report.Stats.Updated != 0 {
		t.Errorf("expected 0 updated, got %d", report.Stats.Updated)
	}
	if len(strategy.rewrites) != 0 {
		t.Error("expected no rewrites for no-op update")
	}
}

func TestUpdate_SkipsUnpinned(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := PinUpdate(context.Background(), testRoot(t), Options{SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped (unpinned), got %d", report.Stats.Skipped)
	}
	if report.Results[0].Reason != "not pinned (use 'deputy pin' first)" {
		t.Errorf("expected skip reason, got %q", report.Results[0].Reason)
	}
}

func TestUpdate_DryRun(t *testing.T) {
	oldSHA := "11bd71901bbe5b1630ceea73d27597364c9af683"
	newSHA := "aabbccdd11223344556677889900aabbccddeeff"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: oldSHA, FilePath: "/tmp/ci.yml"},
		},
		updateResults: map[string]struct{ sha, newTag, curTag string }{
			oldSHA: {newSHA, "v4.3.0", "v4.2.2"},
		},
	}

	report, err := PinUpdate(context.Background(), testRoot(t), Options{DryRun: true, SkipVerification: true}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Updated != 1 {
		t.Errorf("expected 1 updated, got %d", report.Stats.Updated)
	}
	if len(strategy.rewrites) != 0 {
		t.Error("expected no rewrites in dry-run")
	}
}

func TestUpdate_WithExclude(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: sha, FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := PinUpdate(context.Background(), testRoot(t), Options{
		SkipVerification: true,
		Exclude:          []string{"actions/checkout"},
	}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped (excluded), got %d", report.Stats.Skipped)
	}
}

func TestUpdate_Suspicious(t *testing.T) {
	oldSHA := "11bd71901bbe5b1630ceea73d27597364c9af683"
	newSHA := "aabbccdd11223344556677889900aabbccddeeff"
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: oldSHA, FilePath: "/tmp/ci.yml"},
		},
		updateResults: map[string]struct{ sha, newTag, curTag string }{
			oldSHA: {newSHA, "v4.3.0", "v4.2.2"},
		},
		verified: map[string]*Verification{
			newSHA: {IsForkCommit: true, Warnings: []string{"imposter commit"}},
		},
	}

	// In error mode a flagged update is left unpinned and counted suspicious.
	report, err := PinUpdate(context.Background(), testRoot(t), Options{Verification: VerificationError}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Suspicious != 1 {
		t.Errorf("expected 1 suspicious, got %d", report.Stats.Suspicious)
	}
}

// --- Exclude tests ---

func TestShouldExclude(t *testing.T) {
	tests := []struct {
		name    string
		ref     Ref
		exclude []string
		want    bool
	}{
		{"exact match", Ref{Name: "actions/checkout"}, []string{"actions/checkout"}, true},
		{"no match", Ref{Name: "actions/checkout"}, []string{"actions/setup-go"}, false},
		{"glob star", Ref{Name: "actions/checkout"}, []string{"actions/*"}, true},
		{"glob no match", Ref{Name: "myorg/tool"}, []string{"actions/*"}, false},
		{"empty excludes", Ref{Name: "actions/checkout"}, nil, false},
		{"subpath match", Ref{Name: "github/codeql-action", Subpath: "init"}, []string{"github/codeql-action/init"}, true},
		{"subpath no match", Ref{Name: "github/codeql-action", Subpath: "init"}, []string{"github/codeql-action/analyze"}, false},
		{"multiple patterns", Ref{Name: "actions/cache"}, []string{"actions/checkout", "actions/cache"}, true},

		// Monorepo / subpath actions: org- and repo-level patterns must exclude
		// nested actions, not just top-level ones (the wildcard depth bug).
		{"org star excludes top-level action", Ref{Name: "temporalio/simple-action"}, []string{"temporalio/*"}, true},
		{"org star excludes subpath action", Ref{Name: "temporalio/private-actions", Subpath: "golang/setup"}, []string{"temporalio/*"}, true},
		{"org doublestar excludes subpath action", Ref{Name: "temporalio/private-actions", Subpath: "golang/setup"}, []string{"temporalio/**"}, true},
		{"repo identity excludes all subpaths", Ref{Name: "temporalio/private-actions", Subpath: "golang/setup"}, []string{"temporalio/private-actions"}, true},
		{"repo doublestar excludes subpaths", Ref{Name: "temporalio/private-actions", Subpath: "golang/setup"}, []string{"temporalio/private-actions/**"}, true},
		{"single star is not recursive across repos", Ref{Name: "otherorg/action"}, []string{"temporalio/*"}, false},
		{"other org not excluded by doublestar", Ref{Name: "otherorg/private-actions", Subpath: "golang/setup"}, []string{"temporalio/**"}, false},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			if got := shouldExclude(tc.ref, tc.exclude); got != tc.want {
				t.Errorf("shouldExclude(%q, %v) = %v, want %v", tc.ref.DisplayName(), tc.exclude, got, tc.want)
			}
		})
	}
}

func TestPin_WithExclude(t *testing.T) {
	strategy := &mockStrategy{
		refs: []Ref{
			{Ecosystem: "mock", Name: "actions/checkout", Version: "v4", FilePath: "/tmp/ci.yml"},
			{Ecosystem: "mock", Name: "actions/setup-go", Version: "v5", FilePath: "/tmp/ci.yml"},
		},
	}

	report, err := Pin(context.Background(), testRoot(t), Options{
		SkipVerification: true,
		Exclude:          []string{"actions/checkout"},
	}, strategy)
	if err != nil {
		t.Fatal(err)
	}
	if report.Stats.Skipped != 1 {
		t.Errorf("expected 1 skipped, got %d", report.Stats.Skipped)
	}
	if report.Stats.Pinned != 1 {
		t.Errorf("expected 1 pinned, got %d", report.Stats.Pinned)
	}
}

// writingMockStrategy wraps mockStrategy but actually writes files via
// regex-based rewriting, so multi-strategy tests see each other's changes
// on disk. This mirrors the real RewriteWorkflow logic without importing
// the githubactions subpackage (which would create an import cycle).
type writingMockStrategy struct {
	mockStrategy
}

func (m *writingMockStrategy) Rewrite(root *os.Root, path string, updates []Update) error {
	return testRewriteWorkflow(root, path, updates)
}

// testRewriteWorkflow is a minimal reimplementation of the GHA rewrite logic
// for use in orchestrator tests that need real file writes.
func testRewriteWorkflow(root *os.Root, relPath string, updates []Update) error {
	if len(updates) == 0 {
		return nil
	}
	rootFS := root.FS()
	info, err := fs.Stat(rootFS, relPath)
	if err != nil {
		return err
	}
	content, err := fs.ReadFile(rootFS, relPath)
	if err != nil {
		return err
	}
	contentStr := string(content)
	modified := false
	for _, u := range updates {
		pattern := fmt.Sprintf(`(uses:\s*["']?)(%s)@([^\s"'#]+)(["']?)(\s*#[^\n]*)?`, regexp.QuoteMeta(u.Name))
		re := regexp.MustCompile(pattern)
		replacement := fmt.Sprintf("${1}${2}@%s${4} # %s", u.PinnedValue, u.VersionTag)
		newContent := re.ReplaceAllString(contentStr, replacement)
		if newContent != contentStr {
			contentStr = newContent
			modified = true
		}
	}
	if !modified {
		return nil
	}
	f, err := root.OpenFile(relPath, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, info.Mode().Perm())
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.Write([]byte(contentStr))
	return err
}

// TestPin_MultiStrategySharedFile proves that GHA and Container strategies
// can both pin refs in the same workflow file without overwriting each other.
func TestPin_MultiStrategySharedFile(t *testing.T) {
	const (
		actionSHA = "abc123def456abc123def456abc123def456abc1"
		digest    = "sha256:a8560b36e8b8210634f77d9f7f9efd7ffa463e380b75e2e74aff4511df3ef88c"
	)

	input := `name: CI
on: push
jobs:
  test:
    container: postgres:16
    steps:
      - uses: actions/checkout@v4
      - uses: docker://alpine:3.19
`
	// Create a real temp directory with a real file, because both strategies
	// read and rewrite the same file sequentially.
	root := writerTestRoot(t, ".github/workflows/ci.yml", input)

	gha := &writingMockStrategy{
		mockStrategy: mockStrategy{
			refs: []Ref{
				{Ecosystem: "mock-gha", Name: "actions/checkout", Version: "v4",
					FilePath: ".github/workflows/ci.yml"},
			},
			resolved: map[string]struct{ sha, tag string }{
				"actions/checkout@v4": {actionSHA, "v4.2.2"},
			},
		},
	}

	ctr := &containerMockStrategy{
		refs: []Ref{
			{Ecosystem: "container", Name: "postgres", Version: "16",
				FilePath: ".github/workflows/ci.yml"},
			{Ecosystem: "container", Name: "alpine", Version: "3.19",
				FilePath: ".github/workflows/ci.yml"},
		},
		digest: digest,
	}

	report, err := Pin(context.Background(), root, Options{SkipVerification: true}, gha, ctr)
	if err != nil {
		t.Fatal(err)
	}

	// Both strategies should have pinned refs.
	if report.Stats.Pinned < 2 {
		t.Errorf("expected at least 2 pinned (GHA + container), got stats: %+v", report.Stats)
	}

	// Read the final file — both GHA and container pins must be present.
	got, err := fs.ReadFile(root.FS(), ".github/workflows/ci.yml")
	if err != nil {
		t.Fatal(err)
	}
	content := string(got)

	if !strings.Contains(content, "actions/checkout@"+actionSHA) {
		t.Error("GHA pin lost after container strategy wrote")
	}
	if !strings.Contains(content, "postgres:16@"+digest) {
		t.Error("container pin for postgres missing")
	}
	if !strings.Contains(content, "alpine:3.19@"+digest) {
		t.Error("container pin for alpine (docker://) missing")
	}
}
