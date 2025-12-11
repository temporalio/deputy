package cmd

import "testing"

func TestAdjustLicenseOptions_UseLicenseCheckForcesScan(t *testing.T) {
	enrich, src := adjustLicenseOptions(true, false, "depsdev")
	if !enrich {
		t.Fatalf("expected enrichment enabled when using use-licensecheck")
	}
	if src != "scan" {
		t.Fatalf("expected license source scan, got %s", src)
	}
}

func TestAdjustLicenseOptions_RespectExplicitEnrichment(t *testing.T) {
	enrich, src := adjustLicenseOptions(true, true, "depsdev")
	if !enrich || src != "depsdev" {
		t.Fatalf("expected existing enrichment untouched, got enrich=%v src=%s", enrich, src)
	}
}

func TestAdjustLicenseOptions_NoopWhenNotRequested(t *testing.T) {
	enrich, src := adjustLicenseOptions(false, false, "depsdev")
	if enrich || src != "depsdev" {
		t.Fatalf("expected no change when use-licensecheck is false, got enrich=%v src=%s", enrich, src)
	}
}
