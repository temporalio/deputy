package main

import (
	"bytes"
	"context"
	"encoding/json"
	"io"
	"os"
	"path/filepath"
	"testing"

	pb "deps.dev/api/v3"
	billy "github.com/go-git/go-billy/v5"
	memfs "github.com/go-git/go-billy/v5/memfs"
	"github.com/google/osv-scalibr/extractor"
	packageurl "github.com/package-url/packageurl-go"
	"github.com/protobom/protobom/pkg/formats"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/protobom/protobom/pkg/writer"
)

// Minimal CycloneDX JSON writer used only in tests
type cdxComponent struct {
	Type    string `json:"type"`
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
	Purl    string `json:"purl,omitempty"`
}

type cdxBom struct {
	BomFormat   string         `json:"bomFormat"`
	SpecVersion string         `json:"specVersion"`
	Version     int            `json:"version"`
	Components  []cdxComponent `json:"components"`
}

func writeMinimalCycloneDXJSON(w io.Writer, pkgs []*extractor.Package) error {
	bom := cdxBom{BomFormat: "CycloneDX", SpecVersion: "1.4", Version: 1}
	bom.Components = make([]cdxComponent, 0, len(pkgs))
	for _, p := range pkgs {
		purl := ""
		if pu := p.PURL(); pu != nil {
			purl = pu.String()
		}
		bom.Components = append(bom.Components, cdxComponent{
			Type:    "library",
			Name:    p.Name,
			Version: p.Version,
			Purl:    purl,
		})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(bom)
}

// minimal structure for verifying output
type testCdxBom struct {
	BomFormat  string `json:"bomFormat"`
	Components []struct {
		Name    string `json:"name"`
		Version string `json:"version"`
		Purl    string `json:"purl"`
	} `json:"components"`
}

func Test_writeMinimalCycloneDXJSON(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "github.com/acme/lib", Version: "1.2.3"},
		{Name: "leftpad", Version: "0.1.0"},
	}
	var buf bytes.Buffer
	if err := writeMinimalCycloneDXJSON(&buf, pkgs); err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	var bom testCdxBom
	if err := json.Unmarshal(buf.Bytes(), &bom); err != nil {
		t.Fatalf("invalid json: %v", err)
	}
	if bom.BomFormat != "CycloneDX" {
		t.Fatalf("expected CycloneDX bomFormat, got %q", bom.BomFormat)
	}
	if len(bom.Components) != 2 {
		t.Fatalf("expected 2 components, got %d", len(bom.Components))
	}
	if bom.Components[0].Name == "" || bom.Components[0].Version == "" {
		t.Fatalf("component 0 missing fields: %+v", bom.Components[0])
	}
}

func Test_buildProtobomDocument_basic(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "github.com/acme/lib", Version: "1.2.3"},
		{Name: "leftpad", Version: "0.1.0"},
	}
	doc, err := buildProtobomDocument("myrepo", "v1.0.0", "myrepo@v1.0.0", pkgs)
	if err != nil {
		t.Fatalf("buildProtobomDocument error: %v", err)
	}
	if doc.Metadata == nil || doc.Metadata.Name != "myrepo@v1.0.0" {
		t.Fatalf("unexpected metadata name: %+v", doc.Metadata)
	}
	if doc.NodeList == nil || len(doc.NodeList.RootElements) != 1 {
		t.Fatalf("expected one root element, got %+v", doc.NodeList)
	}
	rootID := doc.NodeList.RootElements[0]
	if rootID == "" {
		t.Fatalf("root element id is empty")
	}
	// Expect 1 root + len(pkgs) nodes
	if got, want := len(doc.NodeList.Nodes), 1+len(pkgs); got != want {
		t.Fatalf("unexpected node count: got %d want %d", got, want)
	}
	// Verify each package node exists and is linked from root with a contains edge
	for _, p := range pkgs {
		expectedID := "pkg:" + p.Name + "@" + p.Version
		var found bool
		for _, n := range doc.NodeList.Nodes {
			if n.Id == expectedID {
				found = true
				if n.Name != p.Name || n.Version != p.Version {
					t.Fatalf("node fields mismatch: %+v vs %+v", n, p)
				}
				break
			}
		}
		if !found {
			t.Fatalf("expected node id %q not found", expectedID)
		}
		var edgeFound bool
		for _, e := range doc.NodeList.Edges {
			if e.From == rootID {
				for _, to := range e.To {
					if to == expectedID {
						edgeFound = true
						break
					}
				}
			}
		}
		if !edgeFound {
			t.Fatalf("edge from root to %q not found", expectedID)
		}
	}
}

func Test_writer_serialization_formats(t *testing.T) {
	pkgs := []*extractor.Package{
		{Name: "github.com/acme/lib", Version: "1.2.3"},
		{Name: "leftpad", Version: "0.1.0"},
	}
	doc, err := buildProtobomDocument("myrepo", "v1.0.0", "myrepo@v1.0.0", pkgs)
	if err != nil {
		t.Fatalf("buildProtobomDocument error: %v", err)
	}

	// CycloneDX JSON
	var cdx bytes.Buffer
	if err := writer.New(writer.WithFormat(formats.CDX16JSON)).WriteStream(doc, &cdx); err != nil {
		t.Fatalf("cyclonedx write error: %v", err)
	}
	if !bytes.Contains(cdx.Bytes(), []byte("github.com/acme/lib")) {
		t.Fatalf("cyclonedx output does not contain package name: %s", cdx.String())
	}

	// SPDX 2.3 JSON
	var spdx bytes.Buffer
	if err := writer.New(writer.WithFormat(formats.SPDX23JSON)).WriteStream(doc, &spdx); err != nil {
		t.Fatalf("spdx write error: %v", err)
	}
	if !bytes.Contains(spdx.Bytes(), []byte("leftpad")) {
		t.Fatalf("spdx output does not contain package name: %s", spdx.String())
	}
}

func Test_normalizeGolangPURLString(t *testing.T) {
	dir := t.TempDir()
	// write go.mod with module path
	gomod := []byte("module github.com/hashicorp/vault\n\n go 1.22\n")
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), gomod, 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	cases := []struct {
		in  string
		out string
	}{
		{in: "pkg:golang/./api@v1.16.0", out: "pkg:golang/github.com/hashicorp/vault/api@v1.16.0"},
		{in: "pkg:golang/./sdk@v1.16.0", out: "pkg:golang/github.com/hashicorp/vault/sdk@v1.16.0"},
		{in: "pkg:golang/github.com/hashicorp/vault@v1.16.0", out: "pkg:golang/github.com/hashicorp/vault@v1.16.0"},
		{in: "pkg:npm/%40scope/name@1.0.0", out: "pkg:npm/%40scope/name@1.0.0"},
	}
	for _, tc := range cases {
		got := normalizeGolangPURLString(tc.in, dir)
		if got != tc.out {
			t.Fatalf("normalizeGolangPURLString(%q) = %q; want %q", tc.in, got, tc.out)
		}
	}
}

// fake deps.dev client for enrichment tests
type fakeDepsClient struct{ byKey map[string]*pb.Version }

func (f *fakeDepsClient) GetVersion(_ context.Context, req *pb.GetVersionRequest) (*pb.Version, error) {
	return f.byKey[key(req.GetVersionKey().GetSystem(), req.GetVersionKey().GetName(), req.GetVersionKey().GetVersion())], nil
}

func key(system pb.System, name, version string) string {
	return string(system) + "|" + name + "|" + version
}

func Test_mapPURLToDepsDev(t *testing.T) {
	p, _ := packageurl.FromString("pkg:golang/github.com/acme/lib@1.2.3")
	sys, name, ver := mapPURLToDepsDev(p)
	if sys != pb.System_GO || name != "github.com/acme/lib" || ver != "v1.2.3" {
		t.Fatalf("mapping go purl wrong: %v %q %q", sys, name, ver)
	}

	p2, _ := packageurl.FromString("pkg:npm/leftpad@0.1.0")
	sys, name, ver = mapPURLToDepsDev(p2)
	if sys != pb.System_NPM || name != "leftpad" || ver != "0.1.0" {
		t.Fatalf("mapping npm purl wrong: %v %q %q", sys, name, ver)
	}
}

func Test_enrichProtobomLicensesDepsDevWithClient(t *testing.T) {
	// Build a document with two nodes with purls
	d := sbom.NewDocument()
	n1 := sbom.NewNode()
	n1.Id = "pkg:golang/github.com/acme/lib@v1.2.3"
	n1.Type = sbom.Node_PACKAGE
	n1.Name = "github.com/acme/lib"
	n1.Version = "v1.2.3"
	n1.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): n1.Id}

	n2 := sbom.NewNode()
	n2.Id = "pkg:npm/leftpad@0.1.0"
	n2.Type = sbom.Node_PACKAGE
	n2.Name = "leftpad"
	n2.Version = "0.1.0"
	n2.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): n2.Id}

	d.NodeList.Nodes = append(d.NodeList.Nodes, n1, n2)

	// Fake client preloaded with licenses
	fc := &fakeDepsClient{byKey: map[string]*pb.Version{
		key(pb.System_GO, "github.com/acme/lib", "v1.2.3"): {Licenses: []string{"Apache-2.0"}},
		key(pb.System_NPM, "leftpad", "0.1.0"):             {Licenses: []string{"MIT", "MIT"}}, // test dedupe
	}}

	if err := enrichProtobomLicensesDepsDevWithClient(context.Background(), d, fc); err != nil {
		t.Fatalf("enrich error: %v", err)
	}

	if len(n1.Licenses) != 1 || n1.Licenses[0] != "Apache-2.0" {
		t.Fatalf("unexpected licenses for n1: %+v", n1.Licenses)
	}
	if len(n2.Licenses) != 1 || n2.Licenses[0] != "MIT" {
		t.Fatalf("unexpected licenses for n2: %+v", n2.Licenses)
	}
}

// fake fetcher that returns a preloaded billy FS
type fakeFetcher struct {
	fs   billy.Filesystem
	root string
}

func (f *fakeFetcher) Fetch(ctx context.Context, p packageurl.PackageURL) (billy.Filesystem, string, error) {
	return f.fs, f.root, nil
}

func Test_enrichProtobomLicensesScanWithFetcher(t *testing.T) {
	// Prepare in-memory FS with an Apache license
	fs := memfs.New()
	_ = fs.MkdirAll("/repo", 0o755)
	f, _ := fs.Create("/repo/LICENSE")
	_, _ = f.Write([]byte(
		"Apache License\n" +
			"Version 2.0, January 2004\n\n" +
			"Licensed under the Apache License, Version 2.0 (the \"License\");\n" +
			"you may not use this file except in compliance with the License.\n" +
			"You may obtain a copy of the License at\n\n" +
			"    http://www.apache.org/licenses/LICENSE-2.0\n\n" +
			"Unless required by applicable law or agreed to in writing, software\n" +
			"distributed under the License is distributed on an \"AS IS\" BASIS,\n" +
			"WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.\n" +
			"See the License for the specific language governing permissions and\n" +
			"limitations under the License.\n"))
	_ = f.Close()

	d := sbom.NewDocument()
	n := sbom.NewNode()
	n.Id = "pkg:golang/github.com/acme/lib@v1.2.3"
	n.Type = sbom.Node_PACKAGE
	n.Name = "github.com/acme/lib"
	n.Version = "v1.2.3"
	n.Identifiers = map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): n.Id}
	d.NodeList.Nodes = append(d.NodeList.Nodes, n)

	fetcher := &fakeFetcher{fs: fs, root: "/repo"}
	if err := enrichProtobomLicensesScanWithFetcher(context.Background(), d, fetcher); err != nil {
		t.Fatalf("enrich scan with fetcher error: %v", err)
	}
	if len(n.Licenses) == 0 {
		t.Fatalf("expected licenses on node, got none")
	}
}

func Test_enrichProtobomLicensesScanLocal(t *testing.T) {
	dir := t.TempDir()
	// Write an MIT license file
	mit := "MIT License\n\n" +
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
		"SOFTWARE.\n"
	if err := os.WriteFile(filepath.Join(dir, "LICENSE"), []byte(mit), 0o644); err != nil {
		t.Fatalf("write license: %v", err)
	}
	d := sbom.NewDocument()
	app := sbom.NewNode()
	app.Id = "application:root"
	app.Type = sbom.Node_PACKAGE
	app.Name = "app"
	d.NodeList.Nodes = append(d.NodeList.Nodes, app)
	d.NodeList.RootElements = append(d.NodeList.RootElements, app.Id)
	if err := enrichProtobomLicensesScanLocal(context.Background(), d, dir); err != nil {
		t.Fatalf("enrich scan local error: %v", err)
	}
	if len(app.Licenses) == 0 {
		t.Fatalf("expected app licenses, got none")
	}
}

func Test_deriveGitURLAndRef(t *testing.T) {
	cases := []struct {
		name   string
		purl   string
		gitURL string
		ref    string
		subdir string
	}{
		{
			name:   "github basic with tag",
			purl:   "pkg:github/acme/repo@v1.2.3",
			gitURL: "https://github.com/acme/repo.git",
			ref:    "refs/tags/v1.2.3",
			subdir: "",
		},
		{
			name:   "go module on github with subdir and v version",
			purl:   "pkg:golang/github.com/org/repo/sub/pkg@v1.2.3",
			gitURL: "https://github.com/org/repo.git",
			ref:    "refs/tags/v1.2.3",
			subdir: "sub/pkg",
		},
		{
			name:   "go module on github without v prefix",
			purl:   "pkg:golang/github.com/org/repo@1.2.3",
			gitURL: "https://github.com/org/repo.git",
			ref:    "refs/tags/v1.2.3",
			subdir: "",
		},
		{
			name:   "go module non-github unsupported",
			purl:   "pkg:golang/golang.org/x/sys@v0.5.0",
			gitURL: "",
			ref:    "",
			subdir: "",
		},
		{
			name:   "github without version",
			purl:   "pkg:github/acme/repo",
			gitURL: "https://github.com/acme/repo.git",
			ref:    "",
			subdir: "",
		},
		{
			name:   "unsupported type",
			purl:   "pkg:maven/com.acme/app@1.0.0",
			gitURL: "",
			ref:    "",
			subdir: "",
		},
	}

	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			p, err := packageurl.FromString(tc.purl)
			if err != nil {
				t.Fatalf("parse purl: %v", err)
			}
			gotURL, gotRef, gotSub := deriveGitURLAndRef(p)
			if gotURL != tc.gitURL || gotRef != tc.ref || gotSub != tc.subdir {
				t.Fatalf("derive mismatch:\n got: url=%q ref=%q sub=%q\nwant: url=%q ref=%q sub=%q",
					gotURL, gotRef, gotSub, tc.gitURL, tc.ref, tc.subdir)
			}
		})
	}
}

func Test_mapPURLToDepsDev_more(t *testing.T) {
	cases := []struct {
		purl    string
		system  pb.System
		name    string
		version string
	}{
		{purl: "pkg:npm/%40scope/name@1.2.3", system: pb.System_NPM, name: "@scope/name", version: "1.2.3"},
		{purl: "pkg:maven/com.acme/app@1.0.0", system: pb.System_MAVEN, name: "com.acme:app", version: "1.0.0"},
		{purl: "pkg:pypi/requests@2.31.0", system: pb.System_PYPI, name: "requests", version: "2.31.0"},
		{purl: "pkg:cargo/serde@1.0.0", system: pb.System_CARGO, name: "serde", version: "1.0.0"},
		{purl: "pkg:nuget/Newtonsoft.Json@13.0.1", system: pb.System_NUGET, name: "Newtonsoft.Json", version: "13.0.1"},
	}
	for _, tc := range cases {
		p, err := packageurl.FromString(tc.purl)
		if err != nil {
			t.Fatalf("parse purl %q: %v", tc.purl, err)
		}
		sys, name, ver := mapPURLToDepsDev(p)
		if sys != tc.system || name != tc.name || ver != tc.version {
			t.Fatalf("map mismatch for %q: got (%v,%q,%q) want (%v,%q,%q)", tc.purl, sys, name, ver, tc.system, tc.name, tc.version)
		}
	}
}
