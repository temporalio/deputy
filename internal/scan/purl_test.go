package scan

import (
	"context"
	"testing"

	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/analysis/osv"
	"github.com/picatz/deputy/internal/targets"
	"github.com/picatz/deputy/internal/vulnerability"
)

func TestScanPURL(t *testing.T) {
	t.Parallel()

	var captured []osv.PkgInput
	svc := NewServiceWithConfig(&ServiceConfig{
		QueryVulnerabilities: func(ctx context.Context, client osv.Client, inputs []osv.PkgInput) ([]vulnerability.Finding, map[string]vulnerabilityv1.Advisory, error) {
			captured = append([]osv.PkgInput(nil), inputs...)
			return nil, nil, nil
		},
	})

	exec, err := svc.ScanPURL(context.Background(), "pkg:npm/lodash@4.17.21", Options{})
	if err != nil {
		t.Fatalf("ScanPURL: %v", err)
	}
	if exec == nil {
		t.Fatal("ScanPURL returned nil execution")
	}
	if exec.Result.Target.Kind != targets.KindPURL {
		t.Fatalf("target kind=%q, want %q", exec.Result.Target.Kind, targets.KindPURL)
	}
	if exec.Result.PackagesScanned != 1 {
		t.Fatalf("packages scanned=%d, want 1", exec.Result.PackagesScanned)
	}
	if len(captured) != 1 {
		t.Fatalf("expected 1 input, got %d", len(captured))
	}
	got := captured[0]
	if got.PURL != "pkg:npm/lodash@4.17.21" {
		t.Fatalf("purl=%q, want %q", got.PURL, "pkg:npm/lodash@4.17.21")
	}
	if got.Name != "lodash" {
		t.Fatalf("name=%q, want %q", got.Name, "lodash")
	}
	if got.Ecosystem != "npm" {
		t.Fatalf("ecosystem=%q, want %q", got.Ecosystem, "npm")
	}
	if !got.IsDirect {
		t.Fatalf("expected IsDirect=true")
	}
	if exec.Result.Inventory.Direct[got.PURL] != true {
		t.Fatalf("expected direct map to include %q", got.PURL)
	}
}

func TestScanPURLRequiresVersion(t *testing.T) {
	t.Parallel()

	svc := NewService()
	if _, err := svc.ScanPURL(context.Background(), "pkg:npm/lodash", Options{}); err == nil {
		t.Fatal("expected error for missing version")
	}
}
