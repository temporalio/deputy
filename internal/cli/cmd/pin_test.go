package cmd

import (
	"bytes"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	"github.com/temporalio/deputy/internal/pin"
)

func TestResolveVerificationMode(t *testing.T) {
	newCmd := func() *cobra.Command {
		c := &cobra.Command{}
		c.Flags().String("verification", "warn", "")
		c.Flags().Bool("skip-verification", false, "")
		return c
	}

	t.Run("default is warn", func(t *testing.T) {
		got, err := resolveVerificationMode(newCmd())
		if err != nil || got != pin.VerificationWarn {
			t.Fatalf("got (%q, %v), want (warn, nil)", got, err)
		}
	})

	t.Run("explicit error", func(t *testing.T) {
		c := newCmd()
		_ = c.Flags().Set("verification", "error")
		got, err := resolveVerificationMode(c)
		if err != nil || got != pin.VerificationError {
			t.Fatalf("got (%q, %v), want (error, nil)", got, err)
		}
	})

	t.Run("skip-verification maps to off", func(t *testing.T) {
		c := newCmd()
		_ = c.Flags().Set("skip-verification", "true")
		got, err := resolveVerificationMode(c)
		if err != nil || got != pin.VerificationOff {
			t.Fatalf("got (%q, %v), want (off, nil)", got, err)
		}
	})

	t.Run("explicit --verification overrides --skip-verification", func(t *testing.T) {
		c := newCmd()
		_ = c.Flags().Set("verification", "error")
		_ = c.Flags().Set("skip-verification", "true")
		got, err := resolveVerificationMode(c)
		if err != nil || got != pin.VerificationError {
			t.Fatalf("got (%q, %v), want (error, nil)", got, err)
		}
	})

	t.Run("invalid value errors", func(t *testing.T) {
		c := newCmd()
		_ = c.Flags().Set("verification", "bogus")
		if _, err := resolveVerificationMode(c); err == nil {
			t.Fatal("expected an error for an invalid --verification value")
		}
	})
}

// pinnedReport builds a report with a single freshly-pinned result.
func pinnedReport() *pin.Report {
	r := &pin.Report{
		Results: []pin.Result{{
			Ref:         pin.Ref{Name: "actions/checkout", Version: "v4", FilePath: "/repo/.github/workflows/ci.yml"},
			Status:      pin.StatusPinned,
			PreviousRef: "v4",
			PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683",
			VersionTag:  "v4.2.2",
		}},
		Stats: pin.Stats{Total: 1, Pinned: 1},
	}
	return r
}

func TestRenderPinReport_DryRunWording(t *testing.T) {
	var buf bytes.Buffer
	renderPinReport(&buf, pinnedReport(), true)
	out := stripANSI(buf.String())

	// Dry run must NOT claim files were pinned.
	if strings.Contains(out, "Dependencies Pinned:") {
		t.Errorf("dry run should not say 'Dependencies Pinned:', got:\n%s", out)
	}
	for _, want := range []string{"Dependencies to Pin:", "would be pinned", "no files were modified"} {
		if !strings.Contains(out, want) {
			t.Errorf("dry run output missing %q, got:\n%s", want, out)
		}
	}
}

func TestRenderPinReport_RealRunWording(t *testing.T) {
	var buf bytes.Buffer
	renderPinReport(&buf, pinnedReport(), false)
	out := stripANSI(buf.String())

	if !strings.Contains(out, "Dependencies Pinned:") {
		t.Errorf("real run should say 'Dependencies Pinned:', got:\n%s", out)
	}
	if strings.Contains(out, "would be pinned") || strings.Contains(out, "no files were modified") {
		t.Errorf("real run leaked dry-run wording, got:\n%s", out)
	}
}

func TestRenderPinReport_VerifiedCaveatSurfaced(t *testing.T) {
	report := &pin.Report{
		Results: []pin.Result{{
			Ref:         pin.Ref{Name: "actions/checkout", FilePath: "/repo/.github/workflows/ci.yml"},
			Status:      pin.StatusVerified,
			PinnedValue: "11bd71901bbe5b1630ceea73d27597364c9af683",
			Verification: &pin.Verification{
				SignatureValid: true,
				OnBranch:       false,
				Warnings:       []string{"commit has diverged from main"},
			},
		}},
		Stats: pin.Stats{Total: 1, Verified: 1},
	}

	var buf bytes.Buffer
	renderPinReport(&buf, report, false)
	out := stripANSI(buf.String())

	if !strings.Contains(out, "signed") {
		t.Errorf("expected 'signed' in output, got:\n%s", out)
	}
	if !strings.Contains(out, "diverged from main") {
		t.Errorf("verified caveat was dropped; expected 'diverged from main', got:\n%s", out)
	}
}

func TestRenderPinReport_AlreadyPinnedReasonSurfaced(t *testing.T) {
	report := &pin.Report{
		Results: []pin.Result{
			{
				Ref:         pin.Ref{Name: "go", FilePath: "/repo/mise.toml"},
				Status:      pin.StatusAlreadyPinned,
				PinnedValue: "1.25.1",
				Reason:      "no pin-time provenance check",
			},
			{
				Ref:         pin.Ref{Name: "node", FilePath: "/repo/mise.toml"},
				Status:      pin.StatusAlreadyPinned,
				PinnedValue: "22.5.0",
				Reason:      "already pinned", // the default; must not produce a dangling separator
			},
		},
		Stats: pin.Stats{Total: 2, AlreadyPinned: 2},
	}

	var buf bytes.Buffer
	renderPinReport(&buf, report, false)
	out := stripANSI(buf.String())

	// A non-default reason (verify mode) is surfaced so verify differs from check.
	if !strings.Contains(out, "no pin-time provenance check") {
		t.Errorf("expected verify reason to be surfaced, got:\n%s", out)
	}
	// The default "already pinned" reason must not be echoed as a redundant suffix.
	if strings.Contains(out, "already pinned — already pinned") {
		t.Errorf("default reason produced a redundant suffix, got:\n%s", out)
	}
}

// stripANSI removes ANSI escape sequences so assertions match visible text.
func stripANSI(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		if s[i] == 0x1b {
			// skip until the terminating 'm'
			for i < len(s) && s[i] != 'm' {
				i++
			}
			continue
		}
		b.WriteByte(s[i])
	}
	return b.String()
}

func TestBuildPinStrategies(t *testing.T) {
	tests := []struct {
		name            string
		ecosystems      []string
		allowedHostBins []string
		wantLen         int
		wantErr         string
	}{
		{
			name:       "default github-actions",
			ecosystems: []string{"github-actions"},
			wantLen:    1,
		},
		{
			name:       "all expands to supported",
			ecosystems: []string{"all"},
			wantLen:    len(supportedPinEcosystems),
		},
		{
			name:       "container-image",
			ecosystems: []string{"container-image"},
			wantLen:    1,
		},
		{
			name:       "unsupported ecosystem",
			ecosystems: []string{"npm"},
			wantErr:    "unsupported ecosystem for pinning",
		},
		{
			name:       "mixed valid and invalid",
			ecosystems: []string{"github-actions", "cargo"},
			wantErr:    "unsupported ecosystem for pinning",
		},
		{
			name:       "mise uses native resolver by default",
			ecosystems: []string{"mise"},
			wantLen:    1,
		},
		{
			name:            "host fallback allowlist requires absolute path",
			ecosystems:      []string{"mise"},
			allowedHostBins: []string{"mise"},
			wantErr:         "absolute",
		},
		{
			name:       "deduplicates",
			ecosystems: []string{"github-actions", "github-actions"},
			wantLen:    1,
		},
		{
			name:       "empty slice",
			ecosystems: []string{},
			wantErr:    "no ecosystems selected",
		},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			strategies, err := buildPinStrategies(t.Context(), tc.ecosystems, false, tc.allowedHostBins)
			if tc.wantErr != "" {
				if err == nil {
					t.Fatalf("expected error containing %q, got nil", tc.wantErr)
				}
				if !strings.Contains(err.Error(), tc.wantErr) {
					t.Fatalf("expected error containing %q, got %v", tc.wantErr, err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if len(strategies) != tc.wantLen {
				t.Errorf("expected %d strategies, got %d", tc.wantLen, len(strategies))
			}
			for _, s := range strategies {
				eco := s.Ecosystem()
				if !slices.Contains(supportedPinEcosystems, eco) {
					t.Errorf("unexpected ecosystem: %s", eco)
				}
			}
		})
	}
}

func TestAllowedMiseBin(t *testing.T) {
	dir := t.TempDir()
	misePath := filepath.Join(dir, "mise")
	otherPath := filepath.Join(dir, "git")

	got, err := allowedMiseBin([]string{otherPath, misePath})
	if err != nil {
		t.Fatalf("allowedMiseBin: %v", err)
	}
	if got != misePath {
		t.Errorf("allowedMiseBin = %q, want %q", got, misePath)
	}

	if _, err := allowedMiseBin([]string{"mise"}); err == nil {
		t.Fatal("allowedMiseBin returned nil error for relative path, want error")
	}

	otherMisePath := filepath.Join(t.TempDir(), "mise")
	if _, err := allowedMiseBin([]string{misePath, otherMisePath}); err == nil {
		t.Fatal("allowedMiseBin returned nil error for multiple mise paths, want error")
	}
}
