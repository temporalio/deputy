package sbomx

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"

	cdx "github.com/CycloneDX/cyclonedx-go"
	"github.com/protobom/protobom/pkg/sbom"
	spdxjson "github.com/spdx/tools-golang/json"
	spdxdoc "github.com/spdx/tools-golang/spdx"
	"google.golang.org/protobuf/encoding/protojson"
)

// Format represents an SBOM format type.
type Format string

// Supported SBOM formats.
const (
	FormatUnknown   Format = ""
	FormatProtobom  Format = "protobom"
	FormatCycloneDX Format = "cyclonedx"
	FormatSPDX      Format = "spdx"
)

// DetectFormat attempts to identify the SBOM format from JSON data.
// Returns FormatUnknown if the format cannot be determined.
func DetectFormat(data []byte) Format {
	var probe map[string]any
	if err := json.Unmarshal(data, &probe); err != nil {
		return FormatUnknown
	}
	// CycloneDX: check bomFormat field or $schema
	if v, ok := probe["bomFormat"].(string); ok && strings.EqualFold(v, "cyclonedx") {
		return FormatCycloneDX
	}
	if schema, ok := probe["$schema"].(string); ok && strings.Contains(strings.ToLower(schema), "cyclonedx") {
		return FormatCycloneDX
	}
	// SPDX: check spdxVersion field
	if _, ok := probe["spdxVersion"]; ok {
		return FormatSPDX
	}
	// Protobom: check nodeList field
	if _, ok := probe["nodeList"]; ok {
		return FormatProtobom
	}
	return FormatUnknown
}

// ReadFile reads an SBOM file and returns it as a protobom Document.
// Auto-detects the format (CycloneDX, SPDX, or Protobom) and converts to protobom.
func ReadFile(path string) (*sbom.Document, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return Read(data)
}

// Read parses SBOM data and returns it as a protobom Document.
// Auto-detects the format (CycloneDX, SPDX, or Protobom) and converts to protobom.
func Read(data []byte) (*sbom.Document, error) {
	format := DetectFormat(data)

	switch format {
	case FormatProtobom:
		return ReadProtobom(data)
	case FormatCycloneDX:
		return ReadCycloneDX(data)
	case FormatSPDX:
		return ReadSPDX(data)
	default:
		// Try formats in order as fallback
		if doc, err := ReadProtobom(data); err == nil && doc.NodeList != nil {
			return doc, nil
		}
		if doc, err := ReadCycloneDX(data); err == nil {
			return doc, nil
		}
		if doc, err := ReadSPDX(data); err == nil {
			return doc, nil
		}
		return nil, fmt.Errorf("unsupported SBOM format (expected protobom-json, cyclonedx-json, or spdx-json)")
	}
}

// ReadProtobom parses a Protobom JSON document.
func ReadProtobom(data []byte) (*sbom.Document, error) {
	doc := &sbom.Document{}
	if err := protojson.Unmarshal(data, doc); err != nil {
		return nil, fmt.Errorf("parse protobom: %w", err)
	}
	return doc, nil
}

// ReadCycloneDX parses a CycloneDX JSON document and converts it to protobom format.
func ReadCycloneDX(data []byte) (*sbom.Document, error) {
	var bom cdx.BOM
	if err := cdx.NewBOMDecoder(bytes.NewReader(data), cdx.BOMFileFormatJSON).Decode(&bom); err != nil {
		return nil, fmt.Errorf("parse cyclonedx: %w", err)
	}
	return cycloneDXToProtobom(&bom), nil
}

// ReadSPDX parses an SPDX JSON document and converts it to protobom format.
func ReadSPDX(data []byte) (*sbom.Document, error) {
	spdxDoc, err := spdxjson.Read(bytes.NewReader(data))
	if err != nil {
		return nil, fmt.Errorf("parse spdx: %w", err)
	}
	return spdxToProtobom(spdxDoc), nil
}

// cycloneDXToProtobom converts a CycloneDX BOM to a protobom Document.
func cycloneDXToProtobom(bom *cdx.BOM) *sbom.Document {
	doc := sbom.NewDocument()
	doc.NodeList = &sbom.NodeList{}

	if bom.Components == nil {
		return doc
	}

	for _, comp := range *bom.Components {
		node := sbom.NewNode()
		node.Name = comp.Name
		node.Version = comp.Version
		if comp.PackageURL != "" {
			if node.Identifiers == nil {
				node.Identifiers = make(map[int32]string)
			}
			node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = comp.PackageURL
		}
		// Extract licenses
		if comp.Licenses != nil {
			for _, lic := range *comp.Licenses {
				if lic.License != nil && lic.License.ID != "" {
					node.Licenses = append(node.Licenses, lic.License.ID)
				} else if lic.License != nil && lic.License.Name != "" {
					node.Licenses = append(node.Licenses, lic.License.Name)
				} else if lic.Expression != "" {
					node.Licenses = append(node.Licenses, lic.Expression)
				}
			}
		}
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	}

	return doc
}

// spdxToProtobom converts an SPDX document to a protobom Document.
func spdxToProtobom(spdxDoc *spdxdoc.Document) *sbom.Document {
	doc := sbom.NewDocument()
	doc.NodeList = &sbom.NodeList{}

	if spdxDoc == nil {
		return doc
	}

	for _, pkg := range spdxDoc.Packages {
		node := sbom.NewNode()
		node.Name = pkg.PackageName
		node.Version = pkg.PackageVersion

		// Extract PURL from external refs
		for _, ref := range pkg.PackageExternalReferences {
			if ref.RefType == "purl" {
				if node.Identifiers == nil {
					node.Identifiers = make(map[int32]string)
				}
				node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = ref.Locator
				break
			}
		}

		// Extract license
		if pkg.PackageLicenseConcluded != "" && pkg.PackageLicenseConcluded != "NOASSERTION" {
			node.Licenses = append(node.Licenses, pkg.PackageLicenseConcluded)
		}

		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	}

	return doc
}
