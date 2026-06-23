package sbomx

import (
	"context"
	"os"
	"path/filepath"
	"slices"
	"testing"
	"time"

	pb "deps.dev/api/v3"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/go-git/go-git/v5/plumbing/transport"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/temporalio/deputy/internal/dockerfile"
	"github.com/temporalio/deputy/internal/purlx"
	"github.com/temporalio/deputy/internal/repository/workspace"
)

func Test_NormalizeGolangPURLString(t *testing.T) {
	dir := t.TempDir()
	// create go.mod with module path
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module github.com/example/project\n\ngo 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	cases := []struct{ in, want string }{
		{in: "", want: ""},
		{in: "pkg:golang/github.com/foo/bar@v1.0.0", want: "pkg:golang/github.com/foo/bar@v1.0.0"},
		{in: "pkg:golang/.@v1.2.3", want: "pkg:golang/github.com/example/project@v1.2.3"},
		{in: "pkg:golang/./sub@v0.0.1", want: "pkg:golang/github.com/example/project/sub@v0.0.1"},
	}
	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()
	for _, c := range cases {
		if got := normalizeGolangPURLString(c.in, ws); got != c.want {
			t.Errorf("normalizeGolangPURLString(%q)=%q want %q", c.in, got, c.want)
		}
	}
}

func Test_ReadModulePath(t *testing.T) {
	dir := t.TempDir()
	ws, err := workspace.NewDir(dir)
	if err != nil {
		t.Fatalf("workspace: %v", err)
	}
	defer ws.Close()
	if p := readModulePath(ws); p != "" {
		t.Errorf("expected empty without go.mod got %q", p)
	}
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.com/xyz\n\n go 1.23\n"), 0o644); err != nil {
		t.Fatalf("write go.mod: %v", err)
	}
	if p := readModulePath(ws); p != "example.com/xyz" {
		t.Errorf("readModulePath got %q want example.com/xyz", p)
	}
}

func Test_DeriveDisplayName(t *testing.T) {
	cases := []struct{ name, purl, want string }{
		{name: "plain", purl: "", want: "plain"},
		{name: "ignored", purl: "pkg:golang/github.com/foo/bar@v1.0.0", want: "bar"},
	}
	for _, c := range cases {
		if got := deriveDisplayName(c.name, c.purl); got != c.want {
			t.Errorf("deriveDisplayName(%q,%q)=%q want %q", c.name, c.purl, got, c.want)
		}
	}
}

func Test_SPDXSafeIDFromPURL_and_Sanitize(t *testing.T) {
	cases := []struct{ in string }{
		{in: "pkg:golang/github.com/foo/bar@v1.0.0"},
		{in: "pkg:golang/github.com/foo/bar%2Bplus@v1.0.0"},
	}
	for _, c := range cases {
		id := spdxSafeIDFromPURL(c.in)
		if id == "" {
			t.Errorf("expected id for %q", c.in)
		}
		for _, r := range id {
			if !(r >= 'A' && r <= 'Z') && !(r >= 'a' && r <= 'z') && !(r >= '0' && r <= '9') && r != '-' && r != '_' && r != '.' {
				t.Errorf("unexpected rune %q in id %q", r, id)
				break
			}
		}
	}
}

func TestBuildProtobomDocument_GitHubActionsResolutionProperties(t *testing.T) {
	orig := listRemoteRefsForSBOM
	t.Cleanup(func() { listRemoteRefsForSBOM = orig })

	listRemoteRefsForSBOM = func(ctx context.Context, remoteURL string, _ transport.AuthMethod) ([]*plumbing.Reference, error) {
		if remoteURL != "https://github.com/actions/checkout.git" {
			t.Fatalf("unexpected remoteURL %q", remoteURL)
		}
		return []*plumbing.Reference{
			plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2"), plumbing.NewHash("aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")),
			plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2.0.0"), plumbing.NewHash("bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb")),
			plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2.1.3"), plumbing.NewHash("cccccccccccccccccccccccccccccccccccccccc")),
			plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2.1.3^{}"), plumbing.NewHash("dddddddddddddddddddddddddddddddddddddddd")),
			plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2.2.0"), plumbing.NewHash("eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee")),
		}, nil
	}

	ws := workspace.NewMemory()
	defer ws.Close()

	doc, err := buildProtobomDocument(t.Context(), ws, "https://example.invalid/repo.git", "HEAD", "test", []*extractor.Package{
		{Name: "actions/checkout", Version: "v2", PURLType: purlx.TypeGitHubActions},
	}, nil, nil)
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}

	var node *sbom.Node
	for _, n := range doc.GetNodeList().GetNodes() {
		if n == nil {
			continue
		}
		if got := n.GetIdentifiers()[int32(sbom.SoftwareIdentifierType_PURL)]; got == "pkg:githubactions/actions/checkout@v2" {
			node = n
			break
		}
	}
	if node == nil {
		t.Fatalf("expected github actions node")
	}
	if node.GetVersion() != "v2" {
		t.Fatalf("expected node version to remain requested ref v2, got %q", node.GetVersion())
	}
	props := map[string]string{}
	for _, p := range node.GetProperties() {
		props[p.GetName()] = p.GetData()
	}
	if props["deputy:requestedRef"] != "v2" {
		t.Fatalf("requestedRef=%q", props["deputy:requestedRef"])
	}
	if props["deputy:direct"] != "true" {
		t.Fatalf("direct=%q", props["deputy:direct"])
	}
	if props["deputy:resolvedVersion"] != "v2.2.0" {
		t.Fatalf("resolvedVersion=%q", props["deputy:resolvedVersion"])
	}
	if props["deputy:resolvedTag"] != "v2.2.0" {
		t.Fatalf("resolvedTag=%q", props["deputy:resolvedTag"])
	}
	if props["deputy:resolvedCommit"] != "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee" {
		t.Fatalf("resolvedCommit=%q", props["deputy:resolvedCommit"])
	}
}

func Test_appendUniqueLicenses(t *testing.T) {
	tests := []struct {
		name string
		dst  []string
		src  []string
		want []string
	}{
		{name: "empty src", dst: []string{"MIT"}, src: nil, want: []string{"MIT"}},
		{name: "empty dst", dst: nil, src: []string{"MIT"}, want: []string{"MIT"}},
		{name: "no overlap", dst: []string{"MIT"}, src: []string{"Apache-2.0"}, want: []string{"MIT", "Apache-2.0"}},
		{name: "with overlap", dst: []string{"MIT"}, src: []string{"MIT", "Apache-2.0"}, want: []string{"MIT", "Apache-2.0"}},
		{name: "whitespace trimmed", dst: nil, src: []string{"  MIT  ", ""}, want: []string{"MIT"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := appendUniqueLicenses(tt.dst, tt.src)
			if len(got) != len(tt.want) {
				t.Fatalf("len=%d want %d", len(got), len(tt.want))
			}
			for i := range got {
				if got[i] != tt.want[i] {
					t.Errorf("got[%d]=%q want %q", i, got[i], tt.want[i])
				}
			}
		})
	}
}

func Test_looksLikeCommitSHA(t *testing.T) {
	tests := []struct {
		input string
		want  bool
	}{
		{"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", true},
		{"AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA", true},
		{"0123456789abcdef0123456789abcdef01234567", true},
		{"abc", false},
		{"gggggggggggggggggggggggggggggggggggggggg", false}, // 'g' is invalid hex
		{"v1.0.0", false},
		{"", false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := looksLikeCommitSHA(tt.input); got != tt.want {
				t.Errorf("looksLikeCommitSHA(%q)=%v want %v", tt.input, got, tt.want)
			}
		})
	}
}

func Test_parseGHARollingRef(t *testing.T) {
	tests := []struct {
		input     string
		wantMajor int
		wantMinor int
		wantOK    bool
	}{
		{"v2", 2, -1, true},
		{"2", 2, -1, true},
		{"v2.3", 2, 3, true},
		{"2.3", 2, 3, true},
		{"v1.2.3", 0, 0, false}, // full semver, not rolling
		{"main", 0, 0, false},
		{"", 0, 0, false},
		{"v0", 0, 0, false}, // v0 not allowed (must be >0)
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			major, minor, ok := parseGHARollingRef(tt.input)
			if ok != tt.wantOK || major != tt.wantMajor || minor != tt.wantMinor {
				t.Errorf("parseGHARollingRef(%q)=(%d,%d,%v) want (%d,%d,%v)",
					tt.input, major, minor, ok, tt.wantMajor, tt.wantMinor, tt.wantOK)
			}
		})
	}
}

func Test_goModuleFromPURL(t *testing.T) {
	tests := []struct {
		namespace string
		name      string
		want      string
	}{
		{"github.com/foo", "bar", "github.com/foo/bar"},
		{"", "simple", "simple"},
		{"github.com/foo/", "bar", "github.com/foo/bar"}, // trailing slash handled
	}
	for _, tt := range tests {
		t.Run(tt.want, func(t *testing.T) {
			pu := &purl.PackageURL{Namespace: tt.namespace, Name: tt.name}
			if got := goModuleFromPURL(pu); got != tt.want {
				t.Errorf("goModuleFromPURL=%q want %q", got, tt.want)
			}
		})
	}
	// nil case
	if got := goModuleFromPURL(nil); got != "" {
		t.Errorf("goModuleFromPURL(nil)=%q want empty", got)
	}
}

func Test_rootNode(t *testing.T) {
	// nil doc
	if got := rootNode(nil); got != nil {
		t.Error("expected nil for nil doc")
	}
	// doc without root elements
	doc := sbom.NewDocument()
	if got := rootNode(doc); got != nil {
		t.Error("expected nil without root elements")
	}
	// doc with root element
	node := sbom.NewNode()
	node.Id = "test-root"
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	doc.NodeList.RootElements = append(doc.NodeList.RootElements, "test-root")
	if got := rootNode(doc); got == nil || got.Id != "test-root" {
		t.Errorf("expected root node with id test-root, got %v", got)
	}
}

func Test_nodePackageURL(t *testing.T) {
	tests := []struct {
		name    string
		node    *sbom.Node
		wantNil bool
		wantPkg string
	}{
		{name: "nil node", node: nil, wantNil: true},
		{name: "empty identifiers", node: &sbom.Node{}, wantNil: true},
		{name: "no purl identifier", node: &sbom.Node{Identifiers: map[int32]string{0: "other"}}, wantNil: true},
		{
			name:    "valid purl",
			node:    &sbom.Node{Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "pkg:golang/github.com/foo/bar@v1.0.0"}},
			wantPkg: "bar",
		},
		{name: "whitespace purl", node: &sbom.Node{Identifiers: map[int32]string{int32(sbom.SoftwareIdentifierType_PURL): "   "}}, wantNil: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := nodePackageURL(tt.node)
			if tt.wantNil && got != nil {
				t.Errorf("expected nil, got %v", got)
			}
			if !tt.wantNil && got == nil {
				t.Error("expected non-nil purl")
			}
			if !tt.wantNil && got != nil && got.Name != tt.wantPkg {
				t.Errorf("got name %q want %q", got.Name, tt.wantPkg)
			}
		})
	}
}

func Test_systemFromPURL(t *testing.T) {
	tests := []struct {
		purlType string
		wantSys  string
	}{
		{purl.TypeGolang, "GO"},
		{purl.TypeNPM, "NPM"},
		{purl.TypeCargo, "CARGO"},
		{purl.TypePyPi, "PYPI"},
		{purl.TypeGem, "RUBYGEMS"},
		{purl.TypeMaven, "MAVEN"},
		{purl.TypeNuget, "NUGET"},
		{"unknown", "SYSTEM_UNSPECIFIED"},
	}
	for _, tt := range tests {
		t.Run(tt.purlType, func(t *testing.T) {
			pu := &purl.PackageURL{Type: tt.purlType}
			got := systemFromPURL(pu)
			if got.String() != tt.wantSys {
				t.Errorf("systemFromPURL(%q)=%s want %s", tt.purlType, got.String(), tt.wantSys)
			}
		})
	}
	// nil case
	if got := systemFromPURL(nil); got.String() != "SYSTEM_UNSPECIFIED" {
		t.Errorf("systemFromPURL(nil)=%s want SYSTEM_UNSPECIFIED", got.String())
	}
}

func Test_packageNameForLicenseLookup(t *testing.T) {
	tests := []struct {
		name      string
		purlType  string
		namespace string
		pkgName   string
		want      string
	}{
		{"golang with namespace", purl.TypeGolang, "github.com/foo", "bar", "github.com/foo/bar"},
		{"golang no namespace", purl.TypeGolang, "", "simple", "simple"},
		{"github with namespace", purl.TypeGithub, "owner", "repo", "github.com/owner/repo"},
		{"github no namespace", purl.TypeGithub, "", "repo", "github.com/repo"},
		{"npm with namespace", purl.TypeNPM, "scope", "pkg", "scope/pkg"},
		{"npm no namespace", purl.TypeNPM, "", "lodash", "lodash"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			pu := &purl.PackageURL{Type: tt.purlType, Namespace: tt.namespace, Name: tt.pkgName}
			if got := packageNameForLicenseLookup(pu); got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
	if got := packageNameForLicenseLookup(nil); got != "" {
		t.Errorf("packageNameForLicenseLookup(nil)=%q want empty", got)
	}
}

func Test_normalizeVersionForSystem(t *testing.T) {
	tests := []struct {
		name    string
		sysName string
		version string
		want    string
	}{
		{"go adds v prefix", "GO", "1.2.3", "v1.2.3"},
		{"go keeps v prefix", "GO", "v1.2.3", "v1.2.3"},
		{"npm unchanged", "NPM", "1.2.3", "1.2.3"},
		{"empty version", "GO", "", ""},
		{"whitespace trimmed", "NPM", "  1.0.0  ", "1.0.0"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Map system name to pb.System
			var sys pb.System
			switch tt.sysName {
			case "GO":
				sys = pb.System_GO
			case "NPM":
				sys = pb.System_NPM
			default:
				sys = pb.System_SYSTEM_UNSPECIFIED
			}
			if got := normalizeVersionForSystem(sys, tt.version); got != tt.want {
				t.Errorf("got %q want %q", got, tt.want)
			}
		})
	}
}

func Test_sanitizeForSPDXID(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"simple", "simple"},
		{"with spaces", "with-spaces"},
		{"with/slashes", "with-slashes"},
		{"with@special#chars!", "with-special-chars-"},
		{"multiple---dashes", "multiple---dashes"},
		{"123-numbers.okay_underscore", "123-numbers.okay_underscore"},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			if got := sanitizeForSPDXID(tt.input); got != tt.want {
				t.Errorf("sanitizeForSPDXID(%q)=%q want %q", tt.input, got, tt.want)
			}
		})
	}
}

func Test_isDockerfileFilename(t *testing.T) {
	tests := []struct {
		name string
		want bool
	}{
		// Exact matches
		{"Dockerfile", true},
		{"Containerfile", true},
		{"dockerfile", true},
		{"containerfile", true},

		// Prefix patterns
		{"Dockerfile.prod", true},
		{"Dockerfile.dev", true},
		{"Containerfile.staging", true},

		// Suffix patterns (*.dockerfile)
		{"app.dockerfile", true},
		{"build.dockerfile", true},
		{"test.containerfile", true},

		// Suffix patterns (*Dockerfile)
		{"test-Dockerfile", true},
		{"my.Dockerfile", true},
		{"prod-Containerfile", true},

		// Should NOT match
		{"README.md", false},
		{"Makefile", false},
		{"docker-compose.yml", false},
		{"main.go", false},
		{".dockerignore", false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := isDockerfileFilename(tt.name); got != tt.want {
				t.Errorf("isDockerfileFilename(%q) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

func Test_buildContainerPURL(t *testing.T) {
	tests := []struct {
		name     string
		registry string
		repo     string
		tag      string
		digest   string
		want     string
	}{
		{
			name:     "docker hub library image",
			registry: "index.docker.io",
			repo:     "library/alpine",
			tag:      "3.19",
			want:     "pkg:docker/library/alpine@3.19",
		},
		{
			name:     "docker hub user image",
			registry: "docker.io",
			repo:     "nginx",
			tag:      "latest",
			want:     "pkg:docker/nginx@latest",
		},
		{
			name:     "ghcr image",
			registry: "ghcr.io",
			repo:     "owner/app",
			tag:      "v1.0.0",
			want:     "pkg:oci/ghcr.io/owner/app@v1.0.0",
		},
		{
			name:     "gcr image with digest",
			registry: "gcr.io",
			repo:     "project/image",
			digest:   "sha256:abc123",
			want:     "pkg:oci/gcr.io/project/image@sha256:abc123",
		},
		{
			name:     "empty registry (docker hub default)",
			registry: "",
			repo:     "myimage",
			tag:      "v1",
			want:     "pkg:docker/myimage@v1",
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ref := &dockerfile.ImageRef{
				Registry:   tt.registry,
				Repository: tt.repo,
				Tag:        tt.tag,
				Digest:     tt.digest,
			}
			got := buildContainerPURL(ref)
			if got != tt.want {
				t.Errorf("buildContainerPURL() = %q, want %q", got, tt.want)
			}
		})
	}

	// Test nil case
	if got := buildContainerPURL(nil); got != "" {
		t.Errorf("buildContainerPURL(nil) = %q, want empty", got)
	}
}

func Test_createBaseImageNode(t *testing.T) {
	stage := &dockerfile.Stage{
		Index:     0,
		Name:      "builder",
		BaseImage: "golang:1.22",
		BaseImageResolved: &dockerfile.ImageRef{
			Full:       "golang:1.22",
			Registry:   "index.docker.io",
			Repository: "library/golang",
			Tag:        "1.22",
		},
		Platform: "linux/amd64",
	}

	node := createBaseImageNode(stage, "Dockerfile")

	if node == nil {
		t.Fatal("expected non-nil node")
	}

	// Check basic fields
	if node.Type != sbom.Node_PACKAGE {
		t.Errorf("node.Type = %v, want PACKAGE", node.Type)
	}
	if node.Name != "library/golang" {
		t.Errorf("node.Name = %q, want %q", node.Name, "library/golang")
	}
	if node.Version != "1.22" {
		t.Errorf("node.Version = %q, want %q", node.Version, "1.22")
	}

	// Check PURL identifier
	purlStr := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
	if purlStr != "pkg:docker/library/golang@1.22" {
		t.Errorf("PURL = %q, want %q", purlStr, "pkg:docker/library/golang@1.22")
	}

	// Check properties
	props := map[string]string{}
	for _, p := range node.Properties {
		props[p.Name] = p.Data
	}
	if props["deputy:type"] != "container-base-image" {
		t.Errorf("deputy:type = %q, want container-base-image", props["deputy:type"])
	}
	if props["deputy:location"] != "Dockerfile" {
		t.Errorf("deputy:location = %q, want Dockerfile", props["deputy:location"])
	}
	if props["deputy:dockerfile-stage"] != "builder" {
		t.Errorf("deputy:dockerfile-stage = %q, want builder", props["deputy:dockerfile-stage"])
	}
	if props["deputy:platform"] != "linux/amd64" {
		t.Errorf("deputy:platform = %q, want linux/amd64", props["deputy:platform"])
	}
	if props["deputy:direct"] != "true" {
		t.Errorf("deputy:direct = %q, want true", props["deputy:direct"])
	}
}

func Test_createBaseImageNode_nilStage(t *testing.T) {
	if got := createBaseImageNode(nil, "Dockerfile"); got != nil {
		t.Errorf("createBaseImageNode(nil) = %v, want nil", got)
	}
}

func Test_addDockerfileBaseImagesToSBOM(t *testing.T) {
	doc := sbom.NewDocument()
	app := sbom.NewNode()
	app.Id = "application:root"
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, app)

	dockerfiles := []*dockerfile.Info{
		{
			Path: "Dockerfile",
			Stages: []dockerfile.Stage{
				{
					Index:     0,
					Name:      "builder",
					BaseImage: "golang:1.22",
					BaseImageResolved: &dockerfile.ImageRef{
						Full:       "golang:1.22",
						Registry:   "index.docker.io",
						Repository: "library/golang",
						Tag:        "1.22",
					},
				},
				{
					Index:     1,
					BaseImage: "alpine:3.19",
					BaseImageResolved: &dockerfile.ImageRef{
						Full:       "alpine:3.19",
						Registry:   "index.docker.io",
						Repository: "library/alpine",
						Tag:        "3.19",
					},
				},
			},
		},
	}

	addDockerfileBaseImagesToSBOM(doc, dockerfiles, app.Id)

	// Should have added 2 nodes (golang and alpine)
	// Total nodes: 1 (app) + 2 (base images) = 3
	if len(doc.NodeList.Nodes) != 3 {
		t.Errorf("expected 3 nodes, got %d", len(doc.NodeList.Nodes))
	}

	// Should have 2 edges
	if len(doc.NodeList.Edges) != 2 {
		t.Errorf("expected 2 edges, got %d", len(doc.NodeList.Edges))
	}

	// Verify edges point from app to base images
	for _, edge := range doc.NodeList.Edges {
		if edge.From != app.Id {
			t.Errorf("edge.From = %q, want %q", edge.From, app.Id)
		}
	}
}

func Test_addDockerfileBaseImagesToSBOM_deduplication(t *testing.T) {
	doc := sbom.NewDocument()
	app := sbom.NewNode()
	app.Id = "application:root"
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, app)

	// Two Dockerfiles referencing the same base image
	dockerfiles := []*dockerfile.Info{
		{
			Path: "Dockerfile",
			Stages: []dockerfile.Stage{
				{
					BaseImage: "alpine:3.19",
					BaseImageResolved: &dockerfile.ImageRef{
						Full:       "alpine:3.19",
						Registry:   "index.docker.io",
						Repository: "library/alpine",
						Tag:        "3.19",
					},
				},
			},
		},
		{
			Path: "Dockerfile.prod",
			Stages: []dockerfile.Stage{
				{
					BaseImage: "alpine:3.19", // Same base image
					BaseImageResolved: &dockerfile.ImageRef{
						Full:       "alpine:3.19",
						Registry:   "index.docker.io",
						Repository: "library/alpine",
						Tag:        "3.19",
					},
				},
			},
		},
	}

	addDockerfileBaseImagesToSBOM(doc, dockerfiles, app.Id)

	// Should have only 1 base image node (deduplicated)
	// Total nodes: 1 (app) + 1 (alpine) = 2
	if len(doc.NodeList.Nodes) != 2 {
		t.Errorf("expected 2 nodes (deduplicated), got %d", len(doc.NodeList.Nodes))
	}
}

func Test_addDockerfileBaseImagesToSBOM_skipScratch(t *testing.T) {
	doc := sbom.NewDocument()
	app := sbom.NewNode()
	app.Id = "application:root"
	doc.NodeList.Nodes = append(doc.NodeList.Nodes, app)

	dockerfiles := []*dockerfile.Info{
		{
			Path: "Dockerfile",
			Stages: []dockerfile.Stage{
				{
					BaseImage: "golang:1.22",
					BaseImageResolved: &dockerfile.ImageRef{
						Full:       "golang:1.22",
						Registry:   "index.docker.io",
						Repository: "library/golang",
						Tag:        "1.22",
					},
				},
				{
					BaseImage: "scratch",
					IsScratch: true, // Should be skipped
				},
			},
		},
	}

	addDockerfileBaseImagesToSBOM(doc, dockerfiles, app.Id)

	// Should have only 1 base image node (scratch skipped)
	// Total nodes: 1 (app) + 1 (golang) = 2
	if len(doc.NodeList.Nodes) != 2 {
		t.Errorf("expected 2 nodes (scratch skipped), got %d", len(doc.NodeList.Nodes))
	}
}

func Test_discoverAndParseDockerfiles(t *testing.T) {
	// Create an in-memory workspace with a Dockerfile
	ws := workspace.NewMemory()
	defer ws.Close()

	dockerfileContent := `FROM golang:1.22 AS builder
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app /app
CMD ["/app"]
`
	if err := ws.WriteFile("Dockerfile", []byte(dockerfileContent), 0644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}
	if err := ws.WriteFile("README.md", []byte("# Test"), 0644); err != nil {
		t.Fatalf("write README: %v", err)
	}

	dockerfiles, err := discoverAndParseDockerfiles(ws)
	if err != nil {
		t.Fatalf("discoverAndParseDockerfiles: %v", err)
	}

	if len(dockerfiles) != 1 {
		t.Fatalf("expected 1 dockerfile, got %d", len(dockerfiles))
	}

	df := dockerfiles[0]
	if df.Path != "Dockerfile" {
		t.Errorf("path = %q, want Dockerfile", df.Path)
	}
	if len(df.Stages) != 2 {
		t.Errorf("expected 2 stages, got %d", len(df.Stages))
	}
}

func Test_buildProtobomDocument_filtersDockerfileBaseImages(t *testing.T) {
	ws := workspace.NewMemory()
	defer ws.Close()

	const dockerfileContent = `FROM golang:1.22 AS builder
RUN go build -o app .

FROM alpine:3.19
COPY --from=builder /app /app
`
	if err := ws.WriteFile("Dockerfile", []byte(dockerfileContent), 0o644); err != nil {
		t.Fatalf("write Dockerfile: %v", err)
	}

	doc, err := buildProtobomDocument(t.Context(), ws, "https://example.com/repo", "HEAD", "test", nil, nil, []string{"mise"})
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}
	if got := countContainerBaseImageNodes(doc); got != 0 {
		t.Fatalf("container base image nodes = %d, want 0", got)
	}

	doc, err = buildProtobomDocument(t.Context(), ws, "https://example.com/repo", "HEAD", "test", nil, nil, []string{"dockerfile"})
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}
	if got := countContainerBaseImageNodes(doc); got != 2 {
		t.Fatalf("container base image nodes = %d, want 2", got)
	}
}

func Test_includeDockerfileBaseImages(t *testing.T) {
	tests := []struct {
		name       string
		ecosystems []string
		want       bool
	}{
		{name: "empty means all", want: true},
		{name: "all", ecosystems: []string{"all"}, want: true},
		{name: "dockerfile", ecosystems: []string{"dockerfile"}, want: true},
		{name: "container image alias", ecosystems: []string{"container-image"}, want: true},
		{name: "mixed includes container", ecosystems: []string{"mise", "container"}, want: true},
		{name: "mise only", ecosystems: []string{"mise"}, want: false},
		{name: "go only", ecosystems: []string{"go"}, want: false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := includeDockerfileBaseImages(tt.ecosystems); got != tt.want {
				t.Errorf("includeDockerfileBaseImages(%v) = %v, want %v", tt.ecosystems, got, tt.want)
			}
		})
	}
}

// countContainerBaseImageNodes returns the number of SBOM nodes tagged as
// Dockerfile-derived base image components.
func countContainerBaseImageNodes(doc *sbom.Document) int {
	if doc == nil || doc.NodeList == nil {
		return 0
	}
	count := 0
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}
		for _, prop := range node.Properties {
			if prop != nil && prop.Name == "deputy:type" && prop.Data == "container-base-image" {
				count++
				break
			}
		}
	}
	return count
}

func Test_resolveGitHubActionsRefFromRefs(t *testing.T) {
	refs := []*plumbing.Reference{
		plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v1.0.0"), plumbing.NewHash("1111111111111111111111111111111111111111")),
		plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v1.1.0"), plumbing.NewHash("2222222222222222222222222222222222222222")),
		plumbing.NewHashReference(plumbing.ReferenceName("refs/tags/v2.0.0"), plumbing.NewHash("3333333333333333333333333333333333333333")),
		plumbing.NewHashReference(plumbing.ReferenceName("refs/heads/main"), plumbing.NewHash("4444444444444444444444444444444444444444")),
	}

	tests := []struct {
		name    string
		ref     string
		wantTag string
		wantVer string
		wantSHA string
	}{
		{"rolling v1", "v1", "v1.1.0", "v1.1.0", "2222222222222222222222222222222222222222"},
		{"exact semver", "v2.0.0", "v2.0.0", "v2.0.0", "3333333333333333333333333333333333333333"},
		{"branch main", "main", "main", "", "4444444444444444444444444444444444444444"},
		{"commit SHA", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa", "", "", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"},
		{"empty", "", "", "", ""},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			res := resolveGitHubActionsRefFromRefs(refs, tt.ref)
			if res.ResolvedTag != tt.wantTag {
				t.Errorf("ResolvedTag=%q want %q", res.ResolvedTag, tt.wantTag)
			}
			if res.ResolvedVersion != tt.wantVer {
				t.Errorf("ResolvedVersion=%q want %q", res.ResolvedVersion, tt.wantVer)
			}
			if res.ResolvedCommit != tt.wantSHA {
				t.Errorf("ResolvedCommit=%q want %q", res.ResolvedCommit, tt.wantSHA)
			}
		})
	}
}

// License enrichment tests

func Test_enrichProtobomLicensesScanLocal(t *testing.T) {
	t.Run("enriches root node with local license", func(t *testing.T) {
		licenseText := `MIT License

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in all
copies or substantial portions of the Software.

THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
SOFTWARE.`

		ws := workspace.NewMemory()
		defer ws.Close()
		if err := ws.WriteFile("LICENSE", []byte(licenseText), 0644); err != nil {
			t.Fatalf("write license: %v", err)
		}

		doc := sbom.NewDocument()
		root := sbom.NewNode()
		root.Id = "root"
		root.Type = sbom.Node_PACKAGE
		root.Name = "test-app"
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, root)
		doc.NodeList.RootElements = append(doc.NodeList.RootElements, root.Id)

		err := enrichProtobomLicensesScanLocal(context.Background(), doc, ws)
		if err != nil {
			t.Fatalf("enrichProtobomLicensesScanLocal: %v", err)
		}

		if len(root.Licenses) == 0 {
			t.Error("expected licenses to be added to root node")
		}
		hasMIT := slices.Contains(root.Licenses, "MIT")
		if !hasMIT {
			t.Errorf("expected MIT license, got %v", root.Licenses)
		}
	})

	t.Run("handles nil workspace gracefully", func(t *testing.T) {
		doc := sbom.NewDocument()
		err := enrichProtobomLicensesScanLocal(context.Background(), doc, nil)
		if err != nil {
			t.Errorf("expected no error for nil workspace, got %v", err)
		}
	})

	t.Run("handles nil document gracefully", func(t *testing.T) {
		ws := workspace.NewMemory()
		defer ws.Close()
		err := enrichProtobomLicensesScanLocal(context.Background(), nil, ws)
		if err != nil {
			t.Errorf("expected no error for nil document, got %v", err)
		}
	})

	t.Run("does not error when no LICENSE file exists", func(t *testing.T) {
		ws := workspace.NewMemory()
		defer ws.Close()
		// No license file written

		doc := sbom.NewDocument()
		root := sbom.NewNode()
		root.Id = "root"
		root.Name = "test-app"
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, root)
		doc.NodeList.RootElements = append(doc.NodeList.RootElements, root.Id)

		err := enrichProtobomLicensesScanLocal(context.Background(), doc, ws)
		if err != nil {
			t.Errorf("expected no error, got %v", err)
		}
		if len(root.Licenses) > 0 {
			t.Errorf("expected no licenses without LICENSE file, got %v", root.Licenses)
		}
	})
}

func Test_enrichProtobomLicensesScanWithFetcher_nilHandling(t *testing.T) {
	t.Run("handles nil document", func(t *testing.T) {
		fetcher := &remoteFetcher{Timeout: time.Second}
		err := enrichProtobomLicensesScanWithFetcher(context.Background(), nil, fetcher)
		if err != nil {
			t.Errorf("expected no error for nil document, got %v", err)
		}
	})

	t.Run("handles nil fetcher", func(t *testing.T) {
		doc := sbom.NewDocument()
		err := enrichProtobomLicensesScanWithFetcher(context.Background(), doc, nil)
		if err != nil {
			t.Errorf("expected no error for nil fetcher, got %v", err)
		}
	})

	t.Run("skips nodes with existing licenses", func(t *testing.T) {
		doc := sbom.NewDocument()
		node := sbom.NewNode()
		node.Id = "pkg:npm/test@1.0.0"
		node.Type = sbom.Node_PACKAGE
		node.Name = "test"
		node.Version = "1.0.0"
		node.Licenses = []string{"MIT"} // Already has license
		node.Identifiers = map[int32]string{
			int32(sbom.SoftwareIdentifierType_PURL): "pkg:npm/test@1.0.0",
		}
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)

		fetcher := &remoteFetcher{Timeout: time.Second}
		err := enrichProtobomLicensesScanWithFetcher(context.Background(), doc, fetcher)
		if err != nil {
			t.Errorf("unexpected error: %v", err)
		}
		// License should remain unchanged
		if len(node.Licenses) != 1 || node.Licenses[0] != "MIT" {
			t.Errorf("license should not have changed, got %v", node.Licenses)
		}
	})
}

func Test_buildProtobomDocument_includesToolMetadata(t *testing.T) {
	ws := workspace.NewMemory()
	defer ws.Close()

	doc, err := buildProtobomDocument(t.Context(), ws, "https://example.com/repo", "HEAD", "test-doc", nil, nil, nil)
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}

	// Verify tool metadata
	if doc.Metadata == nil {
		t.Fatal("expected metadata to be set")
	}
	if len(doc.Metadata.Tools) == 0 {
		t.Fatal("expected at least one tool in metadata")
	}

	foundDeputy := false
	for _, tool := range doc.Metadata.Tools {
		if tool.Name == "deputy" {
			foundDeputy = true
			if tool.Vendor != "github.com/temporalio/deputy" {
				t.Errorf("expected vendor 'github.com/temporalio/deputy', got %q", tool.Vendor)
			}
			// Version should be set (may be empty in test context)
			break
		}
	}
	if !foundDeputy {
		t.Error("expected 'deputy' tool in metadata")
	}
}

func Test_buildProtobomDocument_setsDocumentName(t *testing.T) {
	ws := workspace.NewMemory()
	defer ws.Close()

	doc, err := buildProtobomDocument(t.Context(), ws, "https://example.com/repo", "HEAD", "my-custom-name", nil, nil, nil)
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}

	if doc.Metadata.Name != "my-custom-name" {
		t.Errorf("expected document name 'my-custom-name', got %q", doc.Metadata.Name)
	}
}

func Test_buildProtobomDocument_setsTimestamp(t *testing.T) {
	ws := workspace.NewMemory()
	defer ws.Close()

	before := time.Now().Unix()
	doc, err := buildProtobomDocument(t.Context(), ws, "https://example.com/repo", "HEAD", "test", nil, nil, nil)
	if err != nil {
		t.Fatalf("buildProtobomDocument: %v", err)
	}
	after := time.Now().Unix()

	if doc.Metadata.Date == nil {
		t.Fatal("expected metadata date to be set")
	}
	ts := doc.Metadata.Date.AsTime().Unix()
	if ts < before || ts > after {
		t.Errorf("timestamp %d not in expected range [%d, %d]", ts, before, after)
	}
}
