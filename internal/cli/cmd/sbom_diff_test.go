package cmd

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
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

	// Read and diff
	oldDoc, err := readSBOMForDiff(oldPath)
	if err != nil {
		t.Fatalf("failed to read old SBOM: %v", err)
	}
	newDoc, err := readSBOMForDiff(newPath)
	if err != nil {
		t.Fatalf("failed to read new SBOM: %v", err)
	}

	diff := calculateSBOMDiff(oldDoc, newDoc)

	// Verify stats
	if diff.Stats.OldTotal != 3 {
		t.Errorf("OldTotal = %d, want 3", diff.Stats.OldTotal)
	}
	if diff.Stats.NewTotal != 3 {
		t.Errorf("NewTotal = %d, want 3", diff.Stats.NewTotal)
	}
	if diff.Stats.AddedCount != 1 {
		t.Errorf("AddedCount = %d, want 1", diff.Stats.AddedCount)
	}
	if diff.Stats.RemovedCount != 1 {
		t.Errorf("RemovedCount = %d, want 1", diff.Stats.RemovedCount)
	}
	if diff.Stats.ChangedCount != 1 {
		t.Errorf("ChangedCount = %d, want 1", diff.Stats.ChangedCount)
	}
	if diff.Stats.UnchangedCount != 1 {
		t.Errorf("UnchangedCount = %d, want 1", diff.Stats.UnchangedCount)
	}

	// Verify added
	if len(diff.Added) != 1 || diff.Added[0].Name != "new-pkg" {
		t.Errorf("Added = %+v, want new-pkg", diff.Added)
	}

	// Verify removed
	if len(diff.Removed) != 1 || diff.Removed[0].Name != "removed-pkg" {
		t.Errorf("Removed = %+v, want removed-pkg", diff.Removed)
	}

	// Verify changed
	if len(diff.Changed) != 1 || diff.Changed[0].Name != "lodash" {
		t.Errorf("Changed = %+v, want lodash", diff.Changed)
	}
	if diff.Changed[0].OldVersion != "4.17.20" || diff.Changed[0].NewVersion != "4.17.21" {
		t.Errorf("Changed versions = %s -> %s, want 4.17.20 -> 4.17.21",
			diff.Changed[0].OldVersion, diff.Changed[0].NewVersion)
	}
}

func TestOutputDiffJSON(t *testing.T) {
	diff := SBOMDiff{
		Added:   []PackageSummary{{Name: "new-pkg", Version: "1.0.0"}},
		Removed: []PackageSummary{{Name: "old-pkg", Version: "0.9.0"}},
		Changed: []PackageChange{{Name: "updated", OldVersion: "1.0", NewVersion: "2.0"}},
		Stats: DiffStats{
			OldTotal:       2,
			NewTotal:       2,
			AddedCount:     1,
			RemovedCount:   1,
			ChangedCount:   1,
			UnchangedCount: 0,
		},
	}

	var buf bytes.Buffer
	if err := outputDiffJSON(&buf, diff); err != nil {
		t.Fatalf("outputDiffJSON: %v", err)
	}

	var parsed SBOMDiff
	if err := json.Unmarshal(buf.Bytes(), &parsed); err != nil {
		t.Fatalf("failed to parse JSON output: %v", err)
	}

	if len(parsed.Added) != 1 || parsed.Added[0].Name != "new-pkg" {
		t.Errorf("JSON Added = %+v", parsed.Added)
	}
}

func TestOutputDiffText(t *testing.T) {
	diff := SBOMDiff{
		Added:   []PackageSummary{{Name: "new-pkg", Version: "1.0.0"}},
		Removed: []PackageSummary{{Name: "old-pkg", Version: "0.9.0"}},
		Changed: []PackageChange{{Name: "updated", OldVersion: "1.0", NewVersion: "2.0"}},
		Stats: DiffStats{
			OldTotal:       2,
			NewTotal:       2,
			AddedCount:     1,
			RemovedCount:   1,
			ChangedCount:   1,
			UnchangedCount: 0,
		},
	}

	var buf bytes.Buffer
	if err := outputDiffText(&buf, diff, "old.json", "new.json"); err != nil {
		t.Fatalf("outputDiffText: %v", err)
	}

	output := buf.String()
	if !bytes.Contains([]byte(output), []byte("+ new-pkg@1.0.0")) {
		t.Errorf("output missing added package: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("- old-pkg@0.9.0")) {
		t.Errorf("output missing removed package: %s", output)
	}
	if !bytes.Contains([]byte(output), []byte("~ updated: 1.0 -> 2.0")) {
		t.Errorf("output missing changed package: %s", output)
	}
}

func TestExtractNameFromPURL(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:npm/lodash@4.17.21", "lodash"},
		{"pkg:golang/github.com/foo/bar@v1.0.0", "github.com/foo/bar"},
		{"pkg:pypi/requests@2.28.0", "requests"},
		{"pkg:maven/org.apache/commons@1.0", "org.apache/commons"},
		{"invalid", "invalid"},
	}

	for _, tt := range tests {
		got := extractNameFromPURL(tt.purl)
		if got != tt.want {
			t.Errorf("extractNameFromPURL(%q) = %q, want %q", tt.purl, got, tt.want)
		}
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

	doc, err := readSBOMForDiff(path)
	if err != nil {
		t.Fatalf("readSBOMForDiff: %v", err)
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

	doc, err := readSBOMForDiff(path)
	if err != nil {
		t.Fatalf("readSBOMForDiff: %v", err)
	}

	if doc.NodeList == nil || len(doc.NodeList.Nodes) != 1 {
		t.Fatalf("expected 1 node, got %+v", doc.NodeList)
	}

	node := doc.NodeList.Nodes[0]
	if node.Name != "lodash" || node.Version != "4.17.21" {
		t.Errorf("node = %s@%s, want lodash@4.17.21", node.Name, node.Version)
	}
}
