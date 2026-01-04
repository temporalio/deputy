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
	pkgs, _, _, purls, err := parseSBOMPackages([]byte(data), "auto")
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
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("unexpected purls %v", purls)
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
	pkgs, _, _, purls, err := parseSBOMPackages([]byte(data), "spdx-json")
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
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("unexpected purls %v", purls)
	}
}

func TestParseSBOMPackagesProtobomDirect(t *testing.T) {
	data := `{
  "nodeList": {
    "nodes": [
      {
        "id": "node-1",
        "name": "left-pad",
        "version": "1.3.0",
        "identifiers": {
          "1": "pkg:npm/left-pad@1.3.0"
        },
        "properties": [
          {
            "name": "deputy:direct",
            "data": "true"
          }
        ]
      }
    ]
  }
}`
	pkgs, direct, _, purls, err := parseSBOMPackages([]byte(data), "protobom")
	if err != nil {
		t.Fatalf("parseSBOMPackages protobom: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if !direct["pkg:npm/left-pad@1.3.0"] {
		t.Fatalf("expected direct dependency")
	}
	if len(purls) != 1 || purls[0] != "pkg:npm/left-pad@1.3.0" {
		t.Fatalf("unexpected purls %v", purls)
	}
}

func TestParseSBOMPackagesImageCycloneDX(t *testing.T) {
	data := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "name": "alpine",
      "version": "3.19",
      "purl": "pkg:docker/library/alpine@3.19"
    }
  ]
}`
	pkgs, _, images, purls, err := parseSBOMPackages([]byte(data), "cyclonedx-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages cyclonedx image: %v", err)
	}
	if len(pkgs) != 0 {
		t.Fatalf("expected 0 packages, got %d", len(pkgs))
	}
	if len(images) != 1 {
		t.Fatalf("expected 1 image, got %d", len(images))
	}
	if images[0].Ref != "docker://library/alpine:3.19" {
		t.Fatalf("unexpected image ref %q", images[0].Ref)
	}
	if len(purls) != 1 || purls[0] != "pkg:docker/library/alpine@3.19" {
		t.Fatalf("unexpected purls %v", purls)
	}
}

func TestImageRefFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want string
		plat string
	}{
		{
			purl: "pkg:docker/library/alpine@3.19",
			want: "docker://library/alpine:3.19",
		},
		{
			purl: "pkg:oci/ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
			want: "oci://ghcr.io/acme/app@sha256:aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		},
		{
			purl: "pkg:docker/app@1.0?registry_url=ghcr.io",
			want: "docker://ghcr.io/app:1.0",
		},
		{
			purl: "pkg:docker/app@1.0?repository_url=https://ghcr.io/acme/app",
			want: "docker://ghcr.io/acme/app:1.0",
		},
		{
			purl: "pkg:docker/library/alpine@3.19?os=linux&arch=amd64",
			want: "docker://library/alpine:3.19",
			plat: "linux/amd64",
		},
		{
			purl: "pkg:docker/library/alpine@3.19?platform=linux/arm64",
			want: "docker://library/alpine:3.19",
			plat: "linux/arm64",
		},
	}
	for _, tt := range tests {
		got, ok := imageRefFromPURL(tt.purl)
		if !ok {
			t.Fatalf("imageRefFromPURL(%q) returned ok=false", tt.purl)
		}
		if got.Ref != tt.want {
			t.Fatalf("imageRefFromPURL(%q)=%q, want %q", tt.purl, got.Ref, tt.want)
		}
		if got.Platform != tt.plat {
			t.Fatalf("imageRefFromPURL(%q) platform=%q, want %q", tt.purl, got.Platform, tt.plat)
		}
	}
}

func TestDedupeImageRefs(t *testing.T) {
	t.Parallel()

	refs := []imageSBOMRef{
		{Ref: "docker://alpine:3.19", Platform: "linux/amd64"},
		{Ref: "docker://alpine:3.19", Platform: "linux/amd64"},
		{Ref: "docker://alpine:3.19", Platform: "linux/arm64"},
		{Ref: "docker://alpine:3.19", Platform: ""},
	}
	deduped := dedupeImageRefs(refs)
	if len(deduped) != 3 {
		t.Fatalf("expected 3 refs, got %d", len(deduped))
	}
	if deduped[0].Ref == "" {
		t.Fatalf("expected non-empty ref")
	}
}

func TestParseSBOMPackagesProtobomLicenses(t *testing.T) {
	data := `{
  "nodeList": {
    "nodes": [
      {
        "id": "node-1",
        "name": "left-pad",
        "version": "1.3.0",
        "licenses": ["MIT", "Apache-2.0"],
        "identifiers": {
          "1": "pkg:npm/left-pad@1.3.0"
        }
      }
    ]
  }
}`
	pkgs, _, _, _, err := parseSBOMPackages([]byte(data), "protobom")
	if err != nil {
		t.Fatalf("parseSBOMPackages protobom with licenses: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if len(pkgs[0].Licenses) != 2 {
		t.Fatalf("expected 2 licenses, got %d: %v", len(pkgs[0].Licenses), pkgs[0].Licenses)
	}
	if pkgs[0].Licenses[0] != "MIT" || pkgs[0].Licenses[1] != "Apache-2.0" {
		t.Fatalf("unexpected licenses: %v", pkgs[0].Licenses)
	}
}

func TestParseSBOMPackagesCycloneDXLicenses(t *testing.T) {
	data := `{
  "bomFormat": "CycloneDX",
  "specVersion": "1.5",
  "version": 1,
  "components": [
    {
      "name": "left-pad",
      "version": "1.3.0",
      "purl": "pkg:npm/left-pad@1.3.0",
      "licenses": [
        {"license": {"id": "MIT"}},
        {"expression": "Apache-2.0"}
      ]
    }
  ]
}`
	pkgs, _, _, _, err := parseSBOMPackages([]byte(data), "cyclonedx-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages cyclonedx with licenses: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if len(pkgs[0].Licenses) != 2 {
		t.Fatalf("expected 2 licenses, got %d: %v", len(pkgs[0].Licenses), pkgs[0].Licenses)
	}
	// MIT from license.id, Apache-2.0 from expression
	hasMIT := false
	hasApache := false
	for _, l := range pkgs[0].Licenses {
		if l == "MIT" {
			hasMIT = true
		}
		if l == "Apache-2.0" {
			hasApache = true
		}
	}
	if !hasMIT || !hasApache {
		t.Fatalf("expected MIT and Apache-2.0, got: %v", pkgs[0].Licenses)
	}
}

func TestParseSBOMPackagesSPDXLicenses(t *testing.T) {
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
      "licenseConcluded": "MIT",
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
	pkgs, _, _, _, err := parseSBOMPackages([]byte(data), "spdx-json")
	if err != nil {
		t.Fatalf("parseSBOMPackages spdx with licenses: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("expected 1 package, got %d", len(pkgs))
	}
	if len(pkgs[0].Licenses) != 1 || pkgs[0].Licenses[0] != "MIT" {
		t.Fatalf("expected [MIT], got: %v", pkgs[0].Licenses)
	}
}
