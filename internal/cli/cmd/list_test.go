package cmd

import (
	"bytes"
	"strings"
	"testing"

	"github.com/spf13/cobra"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
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

func TestListDirectAliasRegistered(t *testing.T) {
	root := &cobra.Command{Use: "deputy"}
	AddListCommand(root, nil)

	listCmd, _, err := root.Find([]string{"list"})
	if err != nil {
		t.Fatalf("find list command: %v", err)
	}
	if listCmd == nil {
		t.Fatal("expected list command to be registered")
	}

	for _, name := range []string{"direct", "only-direct"} {
		flag := listCmd.Flags().Lookup(name)
		if flag == nil {
			t.Fatalf("expected --%s flag to be registered", name)
		}
		if flag.DefValue != "false" {
			t.Fatalf("expected --%s default false, got %q", name, flag.DefValue)
		}
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

func TestSortListItemsUsesStableIdentityOrder(t *testing.T) {
	items := []ListItem{
		{Name: "zeta", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/zeta@1.0.0", IsDirect: false},
		{Name: "alpha", Version: "2.0.0", Ecosystem: "npm", PURL: "pkg:npm/alpha@2.0.0", IsDirect: false},
		{Name: "empty-transitive", Version: "1.0.0", Ecosystem: "npm", IsDirect: false},
		{Name: "empty-direct", Version: "1.0.0", Ecosystem: "npm", IsDirect: true},
		{Name: "alpha", Version: "1.0.0", Ecosystem: "npm", PURL: "pkg:npm/alpha@1.0.0", IsDirect: true},
	}

	sortListItems(items)

	want := []string{
		"empty-direct",
		"empty-transitive",
		"alpha",
		"alpha",
		"zeta",
	}
	for i := range want {
		if items[i].Name != want[i] {
			t.Fatalf("sorted item %d = %q, want %q; full order: %+v", i, items[i].Name, want[i], items)
		}
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
	if err := writeListTSV(&buf, items, false, false); err != nil {
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
	if err := writeListTSV(&buf, items, true, false); err != nil {
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
	if err := writeListTSV(&buf, items, true, true); err != nil {
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
