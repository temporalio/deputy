package cmd

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"

	"google.golang.org/protobuf/encoding/protojson"

	sbomv1 "github.com/temporalio/deputy/gen/deputy/sbom/v1"
	sbomx "github.com/temporalio/deputy/internal/sbom"
	"github.com/temporalio/deputy/internal/sbom/diff"
)

func TestCalculateSBOMDiff_Basic(t *testing.T) {
	// Create test SBOMs
	oldSBOM := `{
		"metadata": {"id": "old"},
		"nodeList": {
			"nodes": [
				{"name": "lodash", "version": "4.17.20"},
				{"name": "express", "version": "4.18.0"},
				{"name": "removed-pkg", "version": "1.0.0"}
			]
		}
	}`
	newSBOM := `{
		"metadata": {"id": "new"},
		"nodeList": {
			"nodes": [
				{"name": "lodash", "version": "4.17.21"},
				{"name": "express", "version": "4.18.0"},
				{"name": "new-pkg", "version": "2.0.0"}
			]
		}
	}`

	// Write temp files
	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old.json")
	newPath := filepath.Join(tmpDir, "new.json")
	if err := os.WriteFile(oldPath, []byte(oldSBOM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(newSBOM), 0644); err != nil {
		t.Fatal(err)
	}

	// Read and diff using the diff package
	oldDoc, err := sbomx.ReadFile(oldPath)
	if err != nil {
		t.Fatalf("failed to read old SBOM: %v", err)
	}
	newDoc, err := sbomx.ReadFile(newPath)
	if err != nil {
		t.Fatalf("failed to read new SBOM: %v", err)
	}

	result, err := diff.Compare(oldDoc, newDoc)
	if err != nil {
		t.Fatalf("failed to compare SBOMs: %v", err)
	}

	stats := result.Stats()

	// Verify stats
	if stats.Added != 1 {
		t.Errorf("Added = %d, want 1", stats.Added)
	}
	if stats.Removed != 1 {
		t.Errorf("Removed = %d, want 1", stats.Removed)
	}
	if stats.Changed != 1 {
		t.Errorf("Changed = %d, want 1", stats.Changed)
	}

	// Verify added
	if len(result.Added) != 1 || result.Added[0].Name != "new-pkg" {
		t.Errorf("Added = %+v, want new-pkg", result.Added)
	}

	// Verify removed
	if len(result.Removed) != 1 || result.Removed[0].Name != "removed-pkg" {
		t.Errorf("Removed = %+v, want removed-pkg", result.Removed)
	}

	// Verify changed
	if len(result.Changed) != 1 || result.Changed[0].Name != "lodash" {
		t.Errorf("Changed = %+v, want lodash", result.Changed)
	}
	if result.Changed[0].OldVersion != "4.17.20" || result.Changed[0].NewVersion != "4.17.21" {
		t.Errorf("Changed versions = %s -> %s, want 4.17.20 -> 4.17.21",
			result.Changed[0].OldVersion, result.Changed[0].NewVersion)
	}
}

func TestOutputDiffJSON(t *testing.T) {
	// Create a minimal diff using the diff package
	oldSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "old-pkg", "version": "0.9.0"}
			]
		}
	}`
	newSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "new-pkg", "version": "1.0.0"}
			]
		}
	}`

	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old.json")
	newPath := filepath.Join(tmpDir, "new.json")
	if err := os.WriteFile(oldPath, []byte(oldSBOM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(newSBOM), 0644); err != nil {
		t.Fatal(err)
	}

	oldDoc, _ := sbomx.ReadFile(oldPath)
	newDoc, _ := sbomx.ReadFile(newPath)
	result, _ := diff.Compare(oldDoc, newDoc)

	var buf bytes.Buffer
	if err := outputDiffJSON(&buf, result); err != nil {
		t.Fatalf("outputDiffJSON: %v", err)
	}

	var parsed sbomv1.DiffResponse
	if err := protojson.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(parsed.Added) != 1 || parsed.Added[0].Name != "new-pkg" {
		t.Errorf("JSON Added = %+v", parsed.Added)
	}
	if len(parsed.Removed) != 1 || parsed.Removed[0].Name != "old-pkg" {
		t.Errorf("JSON Removed = %+v", parsed.Removed)
	}
}

func TestOutputDiffText(t *testing.T) {
	// Create a minimal diff using the diff package
	oldSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "old-pkg", "version": "0.9.0"},
				{"name": "updated", "version": "1.0.0"}
			]
		}
	}`
	newSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "new-pkg", "version": "1.0.0"},
				{"name": "updated", "version": "2.0.0"}
			]
		}
	}`

	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old.json")
	newPath := filepath.Join(tmpDir, "new.json")
	if err := os.WriteFile(oldPath, []byte(oldSBOM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(newSBOM), 0644); err != nil {
		t.Fatal(err)
	}

	oldDoc, _ := sbomx.ReadFile(oldPath)
	newDoc, _ := sbomx.ReadFile(newPath)
	result, _ := diff.Compare(oldDoc, newDoc)

	var buf bytes.Buffer
	if err := outputDiffText(&buf, result, "old.json", "new.json"); err != nil {
		t.Fatalf("outputDiffText: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("+ new-pkg@1.0.0")) {
		t.Errorf("output missing added package: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("- old-pkg@0.9.0")) {
		t.Errorf("output missing removed package: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("~ updated: 1.0.0 -> 2.0.0")) {
		t.Errorf("output missing changed package: %s", output)
	}
}

func TestReadSBOMForDiff_CycloneDX(t *testing.T) {
	cdx := `{
		"bomFormat": "CycloneDX",
		"specVersion": "1.4",
		"components": [
			{"name": "lodash", "version": "4.17.21", "purl": "pkg:npm/lodash@4.17.21"},
			{"name": "express", "version": "4.18.2"}
		]
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "cdx.json")
	if err := os.WriteFile(path, []byte(cdx), 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := sbomx.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %+v", doc.NodeList)
	}

	// Check first node
	node := doc.NodeList.Nodes[0]
	if node.Name != "lodash" || node.Version != "4.17.21" {
		t.Errorf("node[0] = %s@%s, want lodash@4.17.21", node.Name, node.Version)
	}
}

func TestReadSBOMForDiff_SPDX(t *testing.T) {
	spdx := `{
		"spdxVersion": "SPDX-2.3",
		"packages": [
			{
				"name": "lodash",
				"versionInfo": "4.17.21",
				"externalRefs": [
					{"referenceType": "purl", "referenceLocator": "pkg:npm/lodash@4.17.21"}
				]
			}
		]
	}`

	tmpDir := t.TempDir()
	path := filepath.Join(tmpDir, "spdx.json")
	if err := os.WriteFile(path, []byte(spdx), 0644); err != nil {
		t.Fatal(err)
	}

	doc, err := sbomx.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile: %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %+v", doc.NodeList)
	}

	node := doc.NodeList.Nodes[0]
	if node.Name != "lodash" || node.Version != "4.17.21" {
		t.Errorf("node = %s@%s, want lodash@4.17.21", node.Name, node.Version)
	}
}

func TestChangeKindIndicators(t *testing.T) {
	// Test that the change kind indicators are displayed correctly
	// Create SBOMs with different version change types
	oldSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "major-change", "version": "1.0.0"},
				{"name": "minor-change", "version": "1.0.0"},
				{"name": "patch-change", "version": "1.0.0"},
				{"name": "downgrade", "version": "2.0.0"}
			]
		}
	}`
	newSBOM := `{
		"nodeList": {
			"nodes": [
				{"name": "major-change", "version": "2.0.0"},
				{"name": "minor-change", "version": "1.1.0"},
				{"name": "patch-change", "version": "1.0.1"},
				{"name": "downgrade", "version": "1.0.0"}
			]
		}
	}`

	tmpDir := t.TempDir()
	oldPath := filepath.Join(tmpDir, "old.json")
	newPath := filepath.Join(tmpDir, "new.json")
	if err := os.WriteFile(oldPath, []byte(oldSBOM), 0644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(newPath, []byte(newSBOM), 0644); err != nil {
		t.Fatal(err)
	}

	oldDoc, _ := sbomx.ReadFile(oldPath)
	newDoc, _ := sbomx.ReadFile(newPath)
	result, _ := diff.Compare(oldDoc, newDoc)

	var buf bytes.Buffer
	if err := outputDiffText(&buf, result, "old.json", "new.json"); err != nil {
		t.Fatalf("outputDiffText: %v", err)
	}

	output := buf.String()

	// Check for change kind indicators
	if !bytes.Contains([]byte(output), []byte("[BREAKING]")) {
		t.Errorf("output missing [BREAKING] indicator: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("[minor]")) {
		t.Errorf("output missing [minor] indicator: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("[patch]")) {
		t.Errorf("output missing [patch] indicator: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("[DOWNGRADE]")) {
		t.Errorf("output missing [DOWNGRADE] indicator: %s", output)
	}
}
