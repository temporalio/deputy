package cmd

import (
	"bytes"
	"context"
	"strings"
	"testing"

	"github.com/temporalio/deputy/internal/pin"
	"github.com/temporalio/deputy/internal/pin/container"
	"github.com/temporalio/deputy/internal/pin/githubactions"
)

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
		name       string
		ecosystems []string
		wantLen    int
		wantErr    string
	}{
		{
			name:       "default github-actions",
			ecosystems: []string{"github-actions"},
			wantLen:    1,
		},
		{
			name:       "all expands to supported",
			ecosystems: []string{"all"},
			wantLen:    len(supportedPinEcosystems), // github-actions + container-image
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
			strategies, err := buildPinStrategies(context.Background(), tc.ecosystems, false)
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
				if eco != githubactions.Ecosystem && eco != container.Ecosystem {
					t.Errorf("unexpected ecosystem: %s", eco)
				}
			}
		})
	}
}
