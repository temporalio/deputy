package cmd

import "testing"

func TestParseSBOMPackagesCycloneDX(t *testing.T) {
	data := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.4",
  "version": 1,
  "components": [
    {
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0"
    }
  ]
}`
	pkgs, err := parseSBOMPackages([]byte(data), "auto")
	if err != nil {
		t.Fatalf("parseSBOMPackages auto cyclonedx: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "left-pad" || pkgs[0].Version != "1.3.0" {
		t.Fatalf("unexpected package %+v", pkgs[0])
	}
	if pkgs[0].PURLType != "npm" {
		t.Fatalf("expected npm PURL type, got %q", pkgs[0].PURLType)
	}
}

func TestParseSBOMPackagesSPDX(t *testing.T) {
	data := `{
  "spdxVersion": "SPDX-2.3",
  "SPDXID": "SPDXRef-DOCUMENT",
  "name": "example",
  "dataLicense": "CC0-1.0",
  "documentNamespace": "http://example.com/spdxdocs/example-1",
  "creationInfo": {
    "created": "2024-01-01T00:00:00Z",
    "creators": ["Tool: test"]
  },
  "packages": [
    {
      "name": "left-pad",
      "SPDXID": "SPDXRef-Package-left-pad",
      "versionInfo": "1.3.0",
      "downloadLocation": "NONE",
      "externalRefs": [
        {
          "referenceCategory": "PACKAGE-MANAGER",
          "referenceType": "purl",
          "referenceLocator": "pkg:npm/left-pad@1.3.0"
        }
      ]
    }
  ]
}`
	pkgs, err := parseSBOMPackages([]byte(data), "spdx-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages spdx: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if pkgs[0].Name != "left-pad" || pkgs[0].Version != "1.3.0" {
		t.Fatalf("unexpected package %+v", pkgs[0])
	}
	if pkgs[0].PURLType != "npm" {
		t.Fatalf("expected npm PURL type, got %q", pkgs[0].PURLType)
	}
}
