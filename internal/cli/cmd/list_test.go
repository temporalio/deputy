package cmd

import (
	"bytes"
	"strings"
	"testing"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"google.golang.org/protobuf/types/known/timestamppb"
)

func TestProtoPackagesToListItems(t *testing.T) {
	pkgs := []*dependencyv1.Package{
		{
			Name:      "github.com/acme/foo",
			Version:   "v1.0.0",
			Ecosystem: "golang",
			Purl:      "pkg:golang/github.com/acme/foo@v1.0.0",
			Direct:    true,
			Locations: []string{"go.mod"},
		},
		{
			Name:      "gopkg.in/yaml.v3",
			Version:   "v3.0.1",
			Ecosystem: "golang",
			Purl:      "pkg:golang/gopkg.in/yaml.v3@v3.0.1",
			Direct:    true,
			Locations: []string{"go.mod", "go.sum"},
		},
		{
			Name:      "github.com/acme/bar",
			Version:   "v0.5.0",
			Ecosystem: "golang",
			Purl:      "pkg:golang/github.com/acme/bar@v0.5.0",
			Direct:    false,
			Locations: []string{"go.sum"},
		},
	}

	items := protoPackagesToListItems(pkgs)
	if len(items) != 3 {
		t.Fatalf("expected 3 items, got %d: %+v", len(items), items)
	}

	// Verify first item
	if items[0].Name != "github.com/acme/foo" {
		t.Errorf("expected first item name to be github.com/acme/foo, got %s", items[0].Name)
	}
	if items[0].Version != "v1.0.0" {
		t.Errorf("expected first item version to be v1.0.0, got %s", items[0].Version)
	}
	if !items[0].IsDirect {
		t.Errorf("expected first item to be direct")
	}
	if items[0].PURL != "pkg:golang/github.com/acme/foo@v1.0.0" {
		t.Errorf("expected first item PURL to be pkg:golang/github.com/acme/foo@v1.0.0, got %s", items[0].PURL)
	}

	// Verify indirect item
	if items[2].IsDirect {
		t.Errorf("expected third item to be indirect")
	}

	// Verify locations are joined
	if items[1].Sources != "go.mod, go.sum" {
		t.Errorf("expected sources to be 'go.mod, go.sum', got %s", items[1].Sources)
	}
}

func TestProtoPackagesToListItems_NilPackage(t *testing.T) {
	pkgs := []*dependencyv1.Package{
		{Name: "foo", Version: "1.0", Ecosystem: "npm", Purl: "pkg:npm/foo@1.0", Direct: true},
		nil, // should be skipped
		{Name: "bar", Version: "2.0", Ecosystem: "npm", Purl: "pkg:npm/bar@2.0", Direct: false},
	}

	items := protoPackagesToListItems(pkgs)
	if len(items) != 2 {
		t.Fatalf("expected 2 items (nil skipped), got %d", len(items))
	}
}

func TestProtoPackagesToListItems_Empty(t *testing.T) {
	items := protoPackagesToListItems(nil)
	if len(items) != 0 {
		t.Fatalf("expected 0 items for nil input, got %d", len(items))
	}

	items = protoPackagesToListItems([]*dependencyv1.Package{})
	if len(items) != 0 {
		t.Fatalf("expected 0 items for empty input, got %d", len(items))
	}
}

func TestWriteListTSV_NoHeader_PURLOnly(t *testing.T) {
	items := []ListItem{
		{
			Ecosystem: "Go",
			Name:      "github.com/acme/foo",
			Version:   "v1.0.0",
			IsDirect:  true,
			PURL:      "pkg:golang/github.com/acme/foo@v1.0.0",
		},
	}
	var buf bytes.Buffer
	if err := writeListTSV(&buf, items, false, false, true); err != nil {
		t.Fatalf("writeListTSV: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "name\tversion") || strings.Contains(out, "purl\tdirect\n") {
		t.Fatalf("unexpected header in output: %q", out)
	}
	if !strings.HasPrefix(out, "pkg:golang/github.com/acme/foo@v1.0.0\ttrue") {
		t.Fatalf("unexpected row: %q", out)
	}
}

func TestWriteListTSV_WithHeader(t *testing.T) {
	items := []ListItem{
		{Name: "foo", Version: "1.0", IsDirect: true, PURL: "pkg:npm/foo@1.0"},
		{Name: "bar", Version: "2.0", IsDirect: false, PURL: "pkg:npm/bar@2.0"},
	}
	var buf bytes.Buffer
	if err := writeListTSV(&buf, items, true, false, true); err != nil {
		t.Fatalf("writeListTSV: %v", err)
	}
	out := buf.String()
	if !strings.HasPrefix(out, "purl\tdirect\n") {
		t.Fatalf("expected header, got: %q", out)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 3 {
		t.Fatalf("expected 3 lines (header + 2 items), got %d", len(lines))
	}
}

func TestWriteListTSV_WithSources(t *testing.T) {
	items := []ListItem{
		{Name: "foo", Version: "1.0", IsDirect: true, PURL: "pkg:npm/foo@1.0", Sources: "package.json"},
	}
	var buf bytes.Buffer
	if err := writeListTSV(&buf, items, true, true, true); err != nil {
		t.Fatalf("writeListTSV: %v", err)
	}
	out := buf.String()
	if !strings.Contains(out, "purl\tdirect\tsources") {
		t.Fatalf("expected sources header, got: %q", out)
	}
	if !strings.Contains(out, "package.json") {
		t.Fatalf("expected sources in output, got: %q", out)
	}
}

func TestWriteListTSV_NoDirect(t *testing.T) {
	// When showDirect is false (e.g., for container images), the direct column should be omitted
	items := []ListItem{
		{Name: "alpine-base", Version: "3.19", IsDirect: false, PURL: "pkg:apk/alpine/alpine-base@3.19"},
		{Name: "musl", Version: "1.2.4", IsDirect: false, PURL: "pkg:apk/alpine/musl@1.2.4"},
	}
	var buf bytes.Buffer
	if err := writeListTSV(&buf, items, true, false, false); err != nil {
		t.Fatalf("writeListTSV: %v", err)
	}
	out := buf.String()
	// Should only have "purl" header, not "purl\tdirect"
	if !strings.HasPrefix(out, "purl\n") {
		t.Fatalf("expected only purl header, got: %q", out)
	}
	// Should not contain "true" or "false" (direct column values)
	if strings.Contains(out, "\ttrue") || strings.Contains(out, "\tfalse") {
		t.Fatalf("direct column should be omitted when showDirect=false, got: %q", out)
	}
}

func TestSupportsDirectIndirect(t *testing.T) {
	tests := []struct {
		kind targetv1.TargetKind
		want bool
	}{
		{targetv1.TargetKind_TARGET_KIND_DIR, true},
		{targetv1.TargetKind_TARGET_KIND_GIT, true},
		{targetv1.TargetKind_TARGET_KIND_FILE, true},
		{targetv1.TargetKind_TARGET_KIND_CONTAINER_IMAGE, false},
		{targetv1.TargetKind_TARGET_KIND_BINARY, false},
		{targetv1.TargetKind_TARGET_KIND_VM_IMAGE, false},
		{targetv1.TargetKind_TARGET_KIND_CLOUD_RESOURCE, false},
		{targetv1.TargetKind_TARGET_KIND_SBOM, false},
		{targetv1.TargetKind_TARGET_KIND_PURL, false},
		{targetv1.TargetKind_TARGET_KIND_UNSPECIFIED, false},
	}
	for _, tt := range tests {
		t.Run(tt.kind.String(), func(t *testing.T) {
			got := supportsDirectIndirect(tt.kind)
			if got != tt.want {
				t.Errorf("supportsDirectIndirect(%v) = %v, want %v", tt.kind, got, tt.want)
			}
		})
	}
}

func TestFilterOnlyDirect(t *testing.T) {
	items := []ListItem{
		{Name: "foo", IsDirect: true},
		{Name: "bar", IsDirect: false},
		{Name: "baz", IsDirect: true},
		{Name: "qux", IsDirect: false},
	}
	filtered := filterOnlyDirect(items)
	if len(filtered) != 2 {
		t.Fatalf("expected 2 direct items, got %d", len(filtered))
	}
	for _, it := range filtered {
		if !it.IsDirect {
			t.Errorf("expected only direct items, got indirect: %s", it.Name)
		}
	}
}

// Tests for collection type detection and text formatters

func TestDetectCollectionType(t *testing.T) {
	tests := []struct {
		name    string
		targets []*listv1.DiscoveredTarget
		want    collectionType
	}{
		{
			name:    "empty targets",
			targets: nil,
			want:    collectionUnknown,
		},
		{
			name: "github refs (tags)",
			targets: []*listv1.DiscoveredTarget{
				{Name: "v1.0.0", Metadata: map[string]string{"ref_type": "tag", "sha": "abc123"}},
			},
			want: collectionGitHubRefs,
		},
		{
			name: "github refs (branches)",
			targets: []*listv1.DiscoveredTarget{
				{Name: "main", Metadata: map[string]string{"ref_type": "branch", "sha": "def456"}},
			},
			want: collectionGitHubRefs,
		},
		{
			name: "github repos",
			targets: []*listv1.DiscoveredTarget{
				{Name: "my-repo", Metadata: map[string]string{"default_branch": "main", "stars": "100"}},
			},
			want: collectionGitHubRepos,
		},
		{
			name: "container tags",
			targets: []*listv1.DiscoveredTarget{
				{Name: "v1.0", Metadata: map[string]string{"repository": "docker.io/library/nginx", "tag": "v1.0"}},
			},
			want: collectionContainerTags,
		},
		{
			name: "aws resources",
			targets: []*listv1.DiscoveredTarget{
				{Name: "my-ami", Metadata: map[string]string{"region": "us-west-2", "ami_id": "ami-123"}},
			},
			want: collectionAWSResources,
		},
		{
			name: "unknown - no metadata",
			targets: []*listv1.DiscoveredTarget{
				{Name: "something"},
			},
			want: collectionUnknown,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := detectCollectionType(tt.targets)
			if got != tt.want {
				t.Errorf("detectCollectionType() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestCollectionLabels(t *testing.T) {
	tests := []struct {
		ct          collectionType
		wantHeader  string
		wantSummary string
	}{
		{collectionContainerTags, "TAG", "tags"},
		{collectionGitHubRepos, "REPO", "repositories"},
		{collectionGitHubRefs, "REF", "refs"},
		{collectionAWSResources, "RESOURCE", "resources"},
		{collectionUnknown, "NAME", "targets"},
	}

	for _, tt := range tests {
		t.Run(tt.wantHeader, func(t *testing.T) {
			gotHeader, gotSummary := collectionLabels(tt.ct)
			if gotHeader != tt.wantHeader {
				t.Errorf("collectionLabels() header = %v, want %v", gotHeader, tt.wantHeader)
			}
			if gotSummary != tt.wantSummary {
				t.Errorf("collectionLabels() summary = %v, want %v", gotSummary, tt.wantSummary)
			}
		})
	}
}

func TestWriteGitHubRefsText(t *testing.T) {
	targets := []*listv1.DiscoveredTarget{
		{
			Name: "v1.0.0",
			Metadata: map[string]string{
				"ref_type": "tag",
				"sha":      "abc123def456789",
			},
		},
		{
			Name: "main",
			Metadata: map[string]string{
				"ref_type": "branch",
				"sha":      "def456abc789012",
			},
		},
	}

	var buf bytes.Buffer
	err := writeGitHubRefsText(&buf, targets, true, "refs", nil)
	if err != nil {
		t.Fatalf("writeGitHubRefsText: %v", err)
	}

	out := buf.String()

	// Check header
	if !strings.Contains(out, "REF") {
		t.Errorf("expected REF header, got: %s", out)
	}
	if !strings.Contains(out, "TYPE") {
		t.Errorf("expected TYPE header, got: %s", out)
	}
	if !strings.Contains(out, "SHA") {
		t.Errorf("expected SHA header, got: %s", out)
	}

	// Verify headers are properly spaced (not concatenated like "REFTYPESHA")
	headerLine := strings.Split(out, "\n")[0]
	if strings.Contains(headerLine, "REFTYPE") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}
	if strings.Contains(headerLine, "TYPESHA") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}

	// Check content
	if !strings.Contains(out, "v1.0.0") {
		t.Errorf("expected v1.0.0 in output, got: %s", out)
	}
	if !strings.Contains(out, "tag") {
		t.Errorf("expected tag type in output, got: %s", out)
	}
	if !strings.Contains(out, "abc123d") { // short SHA
		t.Errorf("expected short SHA in output, got: %s", out)
	}

	// Check summary
	if !strings.Contains(out, "2 refs discovered") {
		t.Errorf("expected '2 refs discovered' summary, got: %s", out)
	}
}

func TestWriteGitHubReposText(t *testing.T) {
	ts := timestamppb.Now()
	targets := []*listv1.DiscoveredTarget{
		{
			Name:      "sdk-go",
			CreatedAt: ts,
			Metadata: map[string]string{
				"default_branch": "main",
				"stars":          "521",
				"language":       "Go",
			},
		},
		{
			Name:      "temporal",
			CreatedAt: ts,
			Metadata: map[string]string{
				"default_branch": "main",
				"stars":          "8234",
				"language":       "Go",
			},
		},
	}

	var buf bytes.Buffer
	err := writeGitHubReposText(&buf, targets, true, "repositories", nil)
	if err != nil {
		t.Fatalf("writeGitHubReposText: %v", err)
	}

	out := buf.String()

	// Check header
	if !strings.Contains(out, "REPO") {
		t.Errorf("expected REPO header, got: %s", out)
	}
	if !strings.Contains(out, "STARS") {
		t.Errorf("expected STARS header, got: %s", out)
	}
	if !strings.Contains(out, "LANGUAGE") {
		t.Errorf("expected LANGUAGE header, got: %s", out)
	}
	if !strings.Contains(out, "CREATED") {
		t.Errorf("expected CREATED header, got: %s", out)
	}

	// Verify headers are properly spaced (not concatenated like "REPOSTARSLANGUAGECREATED")
	headerLine := strings.Split(out, "\n")[0]
	if strings.Contains(headerLine, "REPOSTARS") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}
	if strings.Contains(headerLine, "STARSLANGUAGE") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}
	if strings.Contains(headerLine, "LANGUAGECREATED") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}

	// Check content
	if !strings.Contains(out, "sdk-go") {
		t.Errorf("expected sdk-go in output, got: %s", out)
	}
	if !strings.Contains(out, "521") {
		t.Errorf("expected stars count in output, got: %s", out)
	}
	if !strings.Contains(out, "Go") {
		t.Errorf("expected language in output, got: %s", out)
	}

	// Check summary
	if !strings.Contains(out, "2 repositories discovered") {
		t.Errorf("expected '2 repositories discovered' summary, got: %s", out)
	}
}

func TestWriteContainerTagsText(t *testing.T) {
	ts := timestamppb.Now()
	targets := []*listv1.DiscoveredTarget{
		{
			Name:      "3.19",
			CreatedAt: ts,
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "3.19",
				"digest":     "sha256:abc123def456789012345678901234567890",
			},
		},
		{
			Name:      "latest",
			CreatedAt: ts,
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "latest",
				"digest":     "sha256:def456abc789012345678901234567890123",
			},
		},
	}

	var buf bytes.Buffer
	err := writeContainerTagsText(&buf, targets, true, "tags", nil)
	if err != nil {
		t.Fatalf("writeContainerTagsText: %v", err)
	}

	out := buf.String()

	// Check header
	if !strings.Contains(out, "TAG") {
		t.Errorf("expected TAG header, got: %s", out)
	}
	if !strings.Contains(out, "DIGEST") {
		t.Errorf("expected DIGEST header, got: %s", out)
	}
	if !strings.Contains(out, "CREATED") {
		t.Errorf("expected CREATED header, got: %s", out)
	}

	// Check content
	if !strings.Contains(out, "3.19") {
		t.Errorf("expected 3.19 in output, got: %s", out)
	}
	if !strings.Contains(out, "sha256:abc123d") { // truncated digest
		t.Errorf("expected truncated digest in output, got: %s", out)
	}

	// Verify headers are properly spaced (not concatenated like "TAGDIGESTCREATED")
	// The header line should have spaces between columns
	headerLine := strings.Split(out, "\n")[0]
	if strings.Contains(headerLine, "TAGDIGEST") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}
	if strings.Contains(headerLine, "DIGESTCREATED") {
		t.Errorf("headers should have spacing, got squished: %s", headerLine)
	}

	// Check summary
	if !strings.Contains(out, "2 tags discovered") {
		t.Errorf("expected '2 tags discovered' summary, got: %s", out)
	}
}

func TestWriteContainerTagsText_QuickMode(t *testing.T) {
	// Quick mode: no digest, no created_at
	targets := []*listv1.DiscoveredTarget{
		{
			Name: "3.19",
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "3.19",
			},
		},
		{
			Name: "latest",
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "latest",
			},
		},
	}

	var buf bytes.Buffer
	err := writeContainerTagsText(&buf, targets, true, "tags", nil)
	if err != nil {
		t.Fatalf("writeContainerTagsText: %v", err)
	}

	out := buf.String()

	// Should only have TAG header (no DIGEST, no CREATED)
	if !strings.Contains(out, "TAG") {
		t.Errorf("expected TAG header, got: %s", out)
	}
	// Digest and Created headers should not be present when no data
	lines := strings.Split(out, "\n")
	headerLine := lines[0]
	if strings.Contains(headerLine, "DIGEST") {
		t.Errorf("DIGEST header should not be present in quick mode, got: %s", headerLine)
	}
	if strings.Contains(headerLine, "CREATED") {
		t.Errorf("CREATED header should not be present in quick mode, got: %s", headerLine)
	}

	// Should show tip about using JSON for full details
	if !strings.Contains(out, "Tip:") {
		t.Errorf("expected tip about JSON format, got: %s", out)
	}
}

func TestWriteContainerTagsText_PartialMetadata(t *testing.T) {
	// When some tags have metadata and some don't, show a note explaining "-"
	ts := timestamppb.Now()
	targets := []*listv1.DiscoveredTarget{
		{
			Name:      "3.19",
			CreatedAt: ts,
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "3.19",
				"digest":     "sha256:abc123def456789012345678901234567890",
			},
		},
		{
			Name: "latest", // No digest, no created - simulates failed metadata fetch
			Metadata: map[string]string{
				"repository": "docker.io/library/alpine",
				"tag":        "latest",
			},
		},
	}

	var buf bytes.Buffer
	err := writeContainerTagsText(&buf, targets, true, "tags", nil)
	if err != nil {
		t.Fatalf("writeContainerTagsText: %v", err)
	}

	out := buf.String()

	// Should have DIGEST and CREATED headers (because some entries have them)
	if !strings.Contains(out, "DIGEST") {
		t.Errorf("expected DIGEST header for partial metadata, got: %s", out)
	}
	if !strings.Contains(out, "CREATED") {
		t.Errorf("expected CREATED header for partial metadata, got: %s", out)
	}

	// Should have "-" for missing metadata
	if !strings.Contains(out, "-") {
		t.Errorf("expected '-' for missing metadata, got: %s", out)
	}

	// Should show note about missing metadata
	if !strings.Contains(out, "Note:") {
		t.Errorf("expected note about missing metadata, got: %s", out)
	}
	if !strings.Contains(out, "unavailable") {
		t.Errorf("expected 'unavailable' in metadata note, got: %s", out)
	}
}

func TestWriteDiscoveredTargetsText_ContextAware(t *testing.T) {
	// Test that writeDiscoveredTargetsText routes to correct formatter
	tests := []struct {
		name            string
		targets         []*listv1.DiscoveredTarget
		expectHeader    string
		expectSummary   string
	}{
		{
			name: "github refs",
			targets: []*listv1.DiscoveredTarget{
				{Name: "v1.0", Metadata: map[string]string{"ref_type": "tag", "sha": "abc"}},
			},
			expectHeader:  "REF",
			expectSummary: "refs discovered",
		},
		{
			name: "github repos",
			targets: []*listv1.DiscoveredTarget{
				{Name: "repo", Metadata: map[string]string{"default_branch": "main"}},
			},
			expectHeader:  "REPO",
			expectSummary: "repositories discovered",
		},
		{
			name: "container tags",
			targets: []*listv1.DiscoveredTarget{
				{Name: "latest", Metadata: map[string]string{"repository": "nginx", "tag": "latest"}},
			},
			expectHeader:  "TAG",
			expectSummary: "tags discovered",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeDiscoveredTargetsText(&buf, tt.targets, true, nil)
			if err != nil {
				t.Fatalf("writeDiscoveredTargetsText: %v", err)
			}

			out := buf.String()
			if !strings.Contains(out, tt.expectHeader) {
				t.Errorf("expected header %q, got: %s", tt.expectHeader, out)
			}
			if !strings.Contains(out, tt.expectSummary) {
				t.Errorf("expected summary %q, got: %s", tt.expectSummary, out)
			}
		})
	}
}

func TestWriteDiscoveredTargetsText_WithPagination(t *testing.T) {
	targets := []*listv1.DiscoveredTarget{
		{Name: "v1.0.0", Metadata: map[string]string{"ref_type": "tag", "sha": "abc123"}},
		{Name: "main", Metadata: map[string]string{"ref_type": "branch", "sha": "def456"}},
	}

	tests := []struct {
		name           string
		pagination     *paginationInfo
		expectMore     bool
		expectNextCmd  bool
		expectDiscover bool
	}{
		{
			name:           "no pagination",
			pagination:     nil,
			expectMore:     false,
			expectNextCmd:  false,
			expectDiscover: true,
		},
		{
			name: "has more pages",
			pagination: &paginationInfo{
				nextPageToken: "tags:2",
				pageSize:      100,
				currentTarget: "github://owner/repo/",
			},
			expectMore:     true,
			expectNextCmd:  true,
			expectDiscover: false,
		},
		{
			name: "last page (no more)",
			pagination: &paginationInfo{
				nextPageToken: "",
				pageSize:      100,
				currentTarget: "github://owner/repo/",
			},
			expectMore:     false,
			expectNextCmd:  false,
			expectDiscover: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var buf bytes.Buffer
			err := writeDiscoveredTargetsText(&buf, targets, true, tt.pagination)
			if err != nil {
				t.Fatalf("writeDiscoveredTargetsText: %v", err)
			}

			out := buf.String()

			// Check for "more available" vs "discovered"
			if tt.expectMore {
				if !strings.Contains(out, "more available") {
					t.Errorf("expected 'more available' in output, got: %s", out)
				}
			}
			if tt.expectDiscover {
				if !strings.Contains(out, "discovered") {
					t.Errorf("expected 'discovered' in output, got: %s", out)
				}
			}

			// Check for next page command
			if tt.expectNextCmd {
				if !strings.Contains(out, "Next page:") {
					t.Errorf("expected 'Next page:' in output, got: %s", out)
				}
				if !strings.Contains(out, "--page-token") {
					t.Errorf("expected '--page-token' in output, got: %s", out)
				}
			} else {
				if strings.Contains(out, "Next page:") {
					t.Errorf("unexpected 'Next page:' in output, got: %s", out)
				}
			}
		})
	}
}
