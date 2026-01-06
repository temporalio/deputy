package sbomx

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func TestDetectFormat(t *testing.T) {
	tests := []struct {
		name string
		data string
		want Format
	}{
		{
			name: "CycloneDX with bomFormat",
			data: `{"bomFormat": "CycloneDX", "specVersion": "1.4"}`,
			want: FormatCycloneDX,
		},
		{
			name: "CycloneDX with schema",
			data: `{"$schema": "http://cyclonedx.org/schema/bom-1.4.schema.json"}`,
			want: FormatCycloneDX,
		},
		{
			name: "SPDX",
			data: `{"spdxVersion": "SPDX-2.3", "SPDXID": "SPDXRef-DOCUMENT"}`,
			want: FormatSPDX,
		},
		{
			name: "Protobom",
			data: `{"nodeList": {"nodes": []}}`,
			want: FormatProtobom,
		},
		{
			name: "Unknown format",
			data: `{"foo": "bar"}`,
			want: FormatUnknown,
		},
		{
			name: "Invalid JSON",
			data: `not json`,
			want: FormatUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := DetectFormat([]byte(tt.data))
			if got != tt.want {
				t.Errorf("DetectFormat() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestReadCycloneDX(t *testing.T) {
	data := []byte(`{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{
				"name": "lodash",
				"version": "4.17.21",
				"purl": "pkg:npm/lodash@4.17.21",
				"licenses": [{"license": {"id": "MIT"}}]
			},
			{
				"name": "express",
				"version": "4.18.0",
				"purl": "pkg:npm/express@4.18.0"
			}
		]
	}`)

	doc, err := ReadCycloneDX(data)
	if err != nil {
		t.Fatalf("ReadCycloneDX() error = %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(doc.NodeList.Nodes))
	}

	// Check first node
	node := doc.NodeList.Nodes[0]
	if node.Name != "lodash" {
		t.Errorf("expected name 'lodash', got %q", node.Name)
	}
	if node.Version != "4.17.21" {
		t.Errorf("expected version '4.17.21', got %q", node.Version)
	}
	if purl := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; purl != "pkg:npm/lodash@4.17.21" {
		t.Errorf("expected PURL 'pkg:npm/lodash@4.17.21', got %q", purl)
	}
	if len(node.Licenses) != 1 || node.Licenses[0] != "MIT" {
		t.Errorf("expected licenses [MIT], got %v", node.Licenses)
	}
}

func TestReadSPDX(t *testing.T) {
	// SPDX JSON uses "licenseConcluded" not "packageLicenseConcluded"
	data := []byte(`{
		"spdxVersion": "SPDX-2.3",
		"SPDXID": "SPDXRef-DOCUMENT",
		"name": "test",
		"dataLicense": "CC0-1.0",
		"creationInfo": {
			"creators": ["Tool: deputy"],
			"created": "2024-01-01T00:00:00Z"
		},
		"packages": [
			{
				"name": "gin",
				"versionInfo": "1.9.0",
				"SPDXID": "SPDXRef-gin",
				"licenseConcluded": "MIT",
				"downloadLocation": "NOASSERTION",
				"filesAnalyzed": false,
				"externalRefs": [
					{
						"referenceCategory": "PACKAGE-MANAGER",
						"referenceType": "purl",
						"referenceLocator": "pkg:golang/github.com/gin-gonic/gin@v1.9.0"
					}
				]
			}
		]
	}`)

	doc, err := ReadSPDX(data)
	if err != nil {
		t.Fatalf("ReadSPDX() error = %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(doc.NodeList.Nodes))
	}

	node := doc.NodeList.Nodes[0]
	if node.Name != "gin" {
		t.Errorf("expected name 'gin', got %q", node.Name)
	}
	if node.Version != "1.9.0" {
		t.Errorf("expected version '1.9.0', got %q", node.Version)
	}
	if purl := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; purl != "pkg:golang/github.com/gin-gonic/gin@v1.9.0" {
		t.Errorf("expected PURL, got %q", purl)
	}
	if len(node.Licenses) != 1 || node.Licenses[0] != "MIT" {
		t.Errorf("expected licenses [MIT], got %v", node.Licenses)
	}
}

func TestReadProtobom(t *testing.T) {
	data := []byte(`{
		"nodeList": {
			"nodes": [
				{
					"name": "react",
					"version": "18.2.0",
					"identifiers": {"1": "pkg:npm/react@18.2.0"},
					"licenses": ["MIT"]
				}
			]
		}
	}`)

	doc, err := ReadProtobom(data)
	if err != nil {
		t.Fatalf("ReadProtobom() error = %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(doc.NodeList.Nodes))
	}

	node := doc.NodeList.Nodes[0]
	if node.Name != "react" {
		t.Errorf("expected name 'react', got %q", node.Name)
	}
	if node.Version != "18.2.0" {
		t.Errorf("expected version '18.2.0', got %q", node.Version)
	}
}

func TestRead_AutoDetect(t *testing.T) {
	tests := []struct {
		name    string
		data    string
		wantPkg string
	}{
		{
			name:    "Auto-detect CycloneDX",
			data:    `{"bomFormat": "CycloneDX", "components": [{"name": "test-cdx", "version": "1.0.0"}]}`,
			wantPkg: "test-cdx",
		},
		{
			name:    "Auto-detect SPDX",
			data:    `{"spdxVersion": "SPDX-2.3", "packages": [{"name": "test-spdx", "versionInfo": "1.0.0"}]}`,
			wantPkg: "test-spdx",
		},
		{
			name:    "Auto-detect Protobom",
			data:    `{"nodeList": {"nodes": [{"name": "test-pb", "version": "1.0.0"}]}}`,
			wantPkg: "test-pb",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			doc, err := Read([]byte(tt.data))
			if err != nil {
				t.Fatalf("Read() error = %v", err)
			}
			if doc.NodeList == nil || len(doc.NodeList.Nodes) == 0 {
				t.Fatal("expected at least one node")
			}
			if doc.NodeList.Nodes[0].Name != tt.wantPkg {
				t.Errorf("expected package name %q, got %q", tt.wantPkg, doc.NodeList.Nodes[0].Name)
			}
		})
	}
}
