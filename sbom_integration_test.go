package main

import (
	"bytes"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/object"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

func Test_SBOM_Integration_LocalRepo(t *testing.T) {
	if testing.Short() {
		t.Skip("skipping SBOM integration test in short mode")
	}

	ctx := t.Context()
	dir := t.TempDir()

	// Initialize a git repository with a minimal go.mod and LICENSE
	repo, err := git.PlainInit(dir, false)
	if err != nil {
		t.Fatalf("git init: %v", err)
	}
	wt, err := repo.Worktree()
	if err != nil {
		t.Fatalf("worktree: %v", err)
	}

	gomod := []byte("module example.com/testrepo\n\ngo 1.22\n\nrequire github.com/sirupsen/logrus v1.9.2\n")
	if err := writeFile(dir, "go.mod", gomod); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	license := []byte("MIT License\n\n" +
		"Permission is hereby granted, free of charge, to any person obtaining a copy\n" +
		"of this software and associated documentation files (the \"Software\"), to deal\n" +
		"in the Software without restriction, including without limitation the rights\n" +
		"to use, copy, modify, merge, publish, distribute, sublicense, and/or sell\n" +
		"copies of the Software, and to permit persons to whom the Software is\n" +
		"furnished to do so, subject to the following conditions:\n\n" +
		"THE SOFTWARE IS PROVIDED \"AS IS\", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR\n" +
		"IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,\n" +
		"FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE\n" +
		"AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER\n" +
		"LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,\n" +
		"OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE\n" +
		"SOFTWARE.\n")
	if err := writeFile(dir, "LICENSE", license); err != nil {
		t.Fatalf("write LICENSE: %v", err)
	}

	// Add and commit
	if _, err := wt.Add("go.mod"); err != nil {
		t.Fatalf("git add go.mod: %v", err)
	}
	if _, err := wt.Add("LICENSE"); err != nil {
		t.Fatalf("git add LICENSE: %v", err)
	}
	_, err = wt.Commit("initial", &git.CommitOptions{Author: &object.Signature{Name: "t", Email: "t@x", When: time.Now()}})
	if err != nil {
		t.Fatalf("commit: %v", err)
	}

	// Sanity: open and resolve HEAD
	if _, err := repo.Head(); err != nil {
		t.Fatalf("head: %v", err)
	}

	// Collect inventory at HEAD
	pkgs, err := collectInventoryForScan(ctx, dir, "HEAD", []string{"go"})
	if err != nil {
		t.Fatalf("collect inventory: %v", err)
	}
	if len(pkgs) == 0 {
		t.Fatalf("expected at least one package from go.mod")
	}

	// Build doc and enrich from local scan
	doc, err := buildProtobomDocument(dir, "HEAD", "integration@test", pkgs)
	if err != nil {
		t.Fatalf("build doc: %v", err)
	}
	if err := enrichProtobomLicensesScanLocal(ctx, doc, dir); err != nil {
		t.Fatalf("enrich local: %v", err)
	}
	// Root node should have at least one license id
	if len(doc.NodeList.RootElements) == 0 {
		t.Fatalf("missing root element")
	}
	var root *sbom.Node
	for _, n := range doc.NodeList.Nodes {
		if n.Id == doc.NodeList.RootElements[0] {
			root = n
			break
		}
	}
	if root == nil || len(root.Licenses) == 0 {
		t.Fatalf("expected root licenses from local scan")
	}

	// Serialize CycloneDX and SPDX
	var cdx, spdx bytes.Buffer
	if err := writer.New(writer.WithFormat(formats.CDX16JSON)).WriteStream(doc, &cdx); err != nil {
		t.Fatalf("cyclonedx write: %v", err)
	}
	if err := writer.New(writer.WithFormat(formats.SPDX23JSON)).WriteStream(doc, &spdx); err != nil {
		t.Fatalf("spdx write: %v", err)
	}
	if cdx.Len() == 0 || spdx.Len() == 0 {
		t.Fatalf("expected non-empty outputs")
	}
}

// writeFile writes a file relative to dir.
func writeFile(dir, name string, data []byte) error {
	p := filepath.Join(dir, name)
	return os.WriteFile(p, data, 0o644)
}
