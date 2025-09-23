package cmd

import (
	"testing"

	"github.com/google/osv-scalibr/extractor"
)

func TestDetectModuleDeprecationsDirectOnly(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "github.com/aws/aws-sdk-go/service/s3", Version: "1.0.0"},
	}
	direct := map[string]bool{"stdlib": true, "github.com/aws/aws-sdk-go": true}
	got := detectModuleDeprecations(pkgs, direct)
	if len(got) != 1 {
		t.Fatalf("expected 1 deprecation, got %d", len(got))
	}
	if got[0].Module != "github.com/aws/aws-sdk-go" {
		t.Fatalf("unexpected module %q", got[0].Module)
	}
}

func TestDetectModuleDeprecationsSkipsIndirect(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "github.com/aws/aws-sdk-go/service/s3", Version: "1.0.0"},
	}
	direct := map[string]bool{"stdlib": true}
	if got := detectModuleDeprecations(pkgs, direct); len(got) != 0 {
		t.Fatalf("expected no deprecations for indirect module, got %d", len(got))
	}
}
