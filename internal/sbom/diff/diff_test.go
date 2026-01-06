package diff

import (
	"testing"

	"github.com/protobom/protobom/pkg/sbom"
)

func makeDoc(pkgs ...Package) *sbom.Document {
	doc := sbom.NewDocument()
	doc.NodeList = &sbom.NodeList{}

	for _, pkg := range pkgs {
		node := sbom.NewNode()
		node.Name = pkg.Name
		node.Version = pkg.Version
		node.Licenses = pkg.Licenses
		if pkg.PURL != "" {
			if node.Identifiers == nil {
				node.Identifiers = make(map[int32]string)
			}
			node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)] = pkg.PURL
		}
		doc.NodeList.Nodes = append(doc.NodeList.Nodes, node)
	}

	return doc
}

func TestCompare_NilInputs(t *testing.T) {
	doc := makeDoc(Package{Name: "a", Version: "1.0.0"})

	_, err := Compare(nil, doc)
	if err == nil {
		t.Error("expected error for nil old")
	}

	_, err = Compare(doc, nil)
	if err == nil {
		t.Error("expected error for nil new")
	}
}

func TestCompare_EmptyDocs(t *testing.T) {
	old := makeDoc()
	new := makeDoc()

	diff, err := Compare(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if !diff.Empty() {
		t.Error("expected empty diff")
	}
}

func TestCompare_Added(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
		Package{Name: "b", Version: "2.0.0"},
	)

	diff, err := Compare(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(diff.Added) != 1 {
		t.Fatalf("expected 1 added, got %d", len(diff.Added))
	}
	if diff.Added[0].Name != "b" {
		t.Errorf("expected added package 'b', got %s", diff.Added[0].Name)
	}
}

func TestCompare_Removed(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
		Package{Name: "b", Version: "2.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
	)

	diff, err := Compare(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(diff.Removed) != 1 {
		t.Fatalf("expected 1 removed, got %d", len(diff.Removed))
	}
	if diff.Removed[0].Name != "b" {
		t.Errorf("expected removed package 'b', got %s", diff.Removed[0].Name)
	}
}

func TestCompare_Changed(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "1.1.0"},
	)

	diff, err := Compare(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(diff.Changed) != 1 {
		t.Fatalf("expected 1 changed, got %d", len(diff.Changed))
	}
	if diff.Changed[0].OldVersion != "1.0.0" {
		t.Errorf("expected old version 1.0.0, got %s", diff.Changed[0].OldVersion)
	}
	if diff.Changed[0].NewVersion != "1.1.0" {
		t.Errorf("expected new version 1.1.0, got %s", diff.Changed[0].NewVersion)
	}
}

func TestClassifyChange(t *testing.T) {
	tests := []struct {
		old  string
		new  string
		want ChangeKind
	}{
		{"1.0.0", "2.0.0", ChangeKindMajor},
		{"1.0.0", "1.1.0", ChangeKindMinor},
		{"1.0.0", "1.0.1", ChangeKindPatch},
		{"2.0.0", "1.0.0", ChangeKindDowngrade},
		{"v1.0.0", "v1.1.0", ChangeKindMinor},
		{"abc", "def", ChangeKindUnknown},
		{"", "1.0.0", ChangeKindUnknown},
	}

	for _, tt := range tests {
		got := classifyChange(tt.old, tt.new)
		if got != tt.want {
			t.Errorf("classifyChange(%q, %q) = %s, want %s", tt.old, tt.new, got, tt.want)
		}
	}
}

func TestCompareLicenses(t *testing.T) {
	tests := []struct {
		name        string
		old         []string
		new         []string
		wantAdded   []string
		wantRemoved []string
	}{
		{
			name:        "no change",
			old:         []string{"MIT"},
			new:         []string{"MIT"},
			wantAdded:   nil,
			wantRemoved: nil,
		},
		{
			name:        "added license",
			old:         []string{"MIT"},
			new:         []string{"MIT", "Apache-2.0"},
			wantAdded:   []string{"Apache-2.0"},
			wantRemoved: nil,
		},
		{
			name:        "removed license",
			old:         []string{"MIT", "Apache-2.0"},
			new:         []string{"MIT"},
			wantAdded:   nil,
			wantRemoved: []string{"Apache-2.0"},
		},
		{
			name:        "license swap",
			old:         []string{"MIT"},
			new:         []string{"Apache-2.0"},
			wantAdded:   []string{"Apache-2.0"},
			wantRemoved: []string{"MIT"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := compareLicenses(tt.old, tt.new)

			if len(got.Added) != len(tt.wantAdded) {
				t.Errorf("added = %v, want %v", got.Added, tt.wantAdded)
			}
			if len(got.Removed) != len(tt.wantRemoved) {
				t.Errorf("removed = %v, want %v", got.Removed, tt.wantRemoved)
			}
		})
	}
}

func TestStats(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
		Package{Name: "b", Version: "1.0.0"},
		Package{Name: "c", Version: "2.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "2.0.0"}, // major change
		Package{Name: "b", Version: "0.9.0"}, // downgrade
		Package{Name: "d", Version: "1.0.0"}, // added
	)

	diff, err := Compare(old, new)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	stats := diff.Stats()

	if stats.Added != 1 {
		t.Errorf("expected 1 added, got %d", stats.Added)
	}
	if stats.Removed != 1 {
		t.Errorf("expected 1 removed, got %d", stats.Removed)
	}
	if stats.Changed != 2 {
		t.Errorf("expected 2 changed, got %d", stats.Changed)
	}
	if stats.Breaking != 1 {
		t.Errorf("expected 1 breaking, got %d", stats.Breaking)
	}
	if stats.Downgrades != 1 {
		t.Errorf("expected 1 downgrade, got %d", stats.Downgrades)
	}
}

func TestSummary(t *testing.T) {
	old := makeDoc(Package{Name: "a", Version: "1.0.0"})
	new := makeDoc(Package{Name: "b", Version: "1.0.0"})

	diff, _ := Compare(old, new)
	summary := diff.Summary()

	if summary == "" {
		t.Error("expected non-empty summary")
	}
	if summary == "No changes detected" {
		t.Error("expected changes to be detected")
	}
}

func TestSummary_Empty(t *testing.T) {
	old := makeDoc(Package{Name: "a", Version: "1.0.0"})
	new := makeDoc(Package{Name: "a", Version: "1.0.0"})

	diff, _ := Compare(old, new)
	summary := diff.Summary()

	if summary != "No changes detected" {
		t.Errorf("expected 'No changes detected', got %q", summary)
	}
}

func TestBreakingChanges(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
		Package{Name: "b", Version: "1.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "2.0.0"}, // breaking
		Package{Name: "b", Version: "1.1.0"}, // minor
	)

	diff, _ := Compare(old, new)
	breaking := diff.BreakingChanges()

	if len(breaking) != 1 {
		t.Fatalf("expected 1 breaking change, got %d", len(breaking))
	}
	if breaking[0].Name != "a" {
		t.Errorf("expected 'a', got %s", breaking[0].Name)
	}
}

func TestDowngrades(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "2.0.0"},
	)
	new := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
	)

	diff, _ := Compare(old, new)
	downgrades := diff.Downgrades()

	if len(downgrades) != 1 {
		t.Fatalf("expected 1 downgrade, got %d", len(downgrades))
	}
}

func TestLicenseOnlyChanges(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0", Licenses: []string{"MIT"}},
	)
	new := makeDoc(
		Package{Name: "a", Version: "1.0.0", Licenses: []string{"Apache-2.0"}},
	)

	diff, _ := Compare(old, new)
	licenseOnly := diff.LicenseOnlyChanges()

	if len(licenseOnly) != 1 {
		t.Fatalf("expected 1 license-only change, got %d", len(licenseOnly))
	}
}

func TestPackageString(t *testing.T) {
	p := Package{Name: "foo", Version: "1.0.0"}
	if p.String() != "foo@1.0.0" {
		t.Errorf("expected 'foo@1.0.0', got %q", p.String())
	}

	p2 := Package{Name: "bar"}
	if p2.String() != "bar" {
		t.Errorf("expected 'bar', got %q", p2.String())
	}
}

func TestChangeString(t *testing.T) {
	c := Change{
		Name:       "foo",
		OldVersion: "1.0.0",
		NewVersion: "2.0.0",
		Kind:       ChangeKindMajor,
	}

	got := c.String()
	if got != "foo: 1.0.0 -> 2.0.0 (major)" {
		t.Errorf("unexpected string: %s", got)
	}
}

func TestExtractEcosystem(t *testing.T) {
	tests := []struct {
		purl string
		want string
	}{
		{"pkg:npm/lodash@4.17.21", "npm"},
		{"pkg:golang/github.com/foo/bar@v1.0.0", "golang"},
		{"pkg:pypi/requests@2.28.0", "pypi"},
		{"invalid", ""},
		{"", ""},
	}

	for _, tt := range tests {
		got := extractEcosystem(tt.purl)
		if got != tt.want {
			t.Errorf("extractEcosystem(%q) = %q, want %q", tt.purl, got, tt.want)
		}
	}
}

func TestAddedRemovedChangedNames(t *testing.T) {
	old := makeDoc(
		Package{Name: "a", Version: "1.0.0"},
		Package{Name: "b", Version: "1.0.0"},
	)
	new := makeDoc(
		Package{Name: "b", Version: "2.0.0"},
		Package{Name: "c", Version: "1.0.0"},
	)

	diff, _ := Compare(old, new)

	added := diff.AddedNames()
	if len(added) != 1 || added[0] != "c" {
		t.Errorf("unexpected added names: %v", added)
	}

	removed := diff.RemovedNames()
	if len(removed) != 1 || removed[0] != "a" {
		t.Errorf("unexpected removed names: %v", removed)
	}

	changed := diff.ChangedNames()
	if len(changed) != 1 || changed[0] != "b" {
		t.Errorf("unexpected changed names: %v", changed)
	}
}
