package graph

import (
	"context"
	"testing"
)

func TestRubyGemsResolver_Ecosystem(t *testing.T) {
	resolver := NewRubyGemsResolver()
	if got := resolver.Ecosystem(); got != "RubyGems" {
		t.Errorf("Ecosystem() = %q, want %q", got, "RubyGems")
	}
}

func TestRubyGemsResolver_ResolveEdges(t *testing.T) {
	gemfileLock := `GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
      nio4r (~> 2.0)
    actionpack (7.0.4)
      rack (~> 2.0)
    nio4r (2.5.8)
    rack (2.2.6)
    rails (7.0.4)
      actioncable (= 7.0.4)
      actionpack (= 7.0.4)

PLATFORMS
  ruby

DEPENDENCIES
  rails
  pg

BUNDLED WITH
   2.4.10
`

	files := &mockFileReader{
		files: map[string][]byte{
			"Gemfile.lock": []byte(gemfileLock),
		},
	}

	g := New()
	g.AddNode(&Node{
		Purl:      "pkg:gem/rails@7.0.4",
		Name:      "rails",
		Version:   "7.0.4",
		Ecosystem: "RubyGems",
	})
	g.AddNode(&Node{
		Purl:      "pkg:gem/actioncable@7.0.4",
		Name:      "actioncable",
		Version:   "7.0.4",
		Ecosystem: "RubyGems",
	})
	g.AddNode(&Node{
		Purl:      "pkg:gem/actionpack@7.0.4",
		Name:      "actionpack",
		Version:   "7.0.4",
		Ecosystem: "RubyGems",
	})
	g.AddNode(&Node{
		Purl:      "pkg:gem/nio4r@2.5.8",
		Name:      "nio4r",
		Version:   "2.5.8",
		Ecosystem: "RubyGems",
	})
	g.AddNode(&Node{
		Purl:      "pkg:gem/rack@2.2.6",
		Name:      "rack",
		Version:   "2.2.6",
		Ecosystem: "RubyGems",
	})

	resolver := NewRubyGemsResolver()
	err := resolver.ResolveEdges(context.Background(), g, files)
	if err != nil {
		t.Fatalf("ResolveEdges failed: %v", err)
	}

	// Check edges were created
	edgeCount := 0
	for range g.Edges() {
		edgeCount++
	}
	if edgeCount == 0 {
		t.Error("expected edges to be created, got 0")
	}

	// Verify rails is direct
	railsNode := g.Node("pkg:gem/rails@7.0.4")
	if railsNode == nil {
		t.Fatal("expected rails node to exist")
	}
	if !railsNode.Direct {
		t.Error("expected rails to be marked as direct")
	}

	// Verify rack is transitive (not in DEPENDENCIES)
	rackNode := g.Node("pkg:gem/rack@2.2.6")
	if rackNode == nil {
		t.Fatal("expected rack node to exist")
	}
	if rackNode.Direct {
		t.Error("expected rack to NOT be marked as direct")
	}

	// Verify edge exists: rails -> actioncable
	foundEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:gem/rails@7.0.4" && edge.To == "pkg:gem/actioncable@7.0.4" {
			foundEdge = true
			break
		}
	}
	if !foundEdge {
		t.Error("expected edge from rails to actioncable")
	}

	// Verify edge exists: actionpack -> rack
	foundRackEdge := false
	for edge := range g.Edges() {
		if edge.From == "pkg:gem/actionpack@7.0.4" && edge.To == "pkg:gem/rack@2.2.6" {
			foundRackEdge = true
			break
		}
	}
	if !foundRackEdge {
		t.Error("expected edge from actionpack to rack")
	}
}

func TestRubyGemsResolver_ParseGemfileLock(t *testing.T) {
	gemfileLock := []byte(`GEM
  remote: https://rubygems.org/
  specs:
    actioncable (7.0.4)
      actionpack (= 7.0.4)
    actionpack (7.0.4)
      rack (~> 2.0)
    rack (2.2.6)

DEPENDENCIES
  actioncable
  my-gem!

BUNDLED WITH
   2.4.10
`)

	resolver := NewRubyGemsResolver()
	specs, directGems := resolver.parseGemfileLock(gemfileLock)

	// Check we got all specs
	if len(specs) != 3 {
		t.Errorf("expected 3 specs, got %d", len(specs))
	}

	// Check actioncable
	var actioncable gemSpec
	for _, s := range specs {
		if s.name == "actioncable" {
			actioncable = s
			break
		}
	}
	if actioncable.name == "" {
		t.Fatal("expected actioncable spec")
	}
	if actioncable.version != "7.0.4" {
		t.Errorf("actioncable version = %q, want %q", actioncable.version, "7.0.4")
	}
	if len(actioncable.dependencies) != 1 || actioncable.dependencies[0] != "actionpack" {
		t.Errorf("actioncable dependencies = %v, want [actionpack]", actioncable.dependencies)
	}

	// Check direct gems
	if !directGems["actioncable"] {
		t.Error("expected actioncable to be direct")
	}
	if !directGems["my-gem"] {
		t.Error("expected my-gem to be direct (without ! suffix)")
	}
	if directGems["rack"] {
		t.Error("expected rack to NOT be direct")
	}
}

func TestGemPkgToPURL(t *testing.T) {
	tests := []struct {
		name    string
		version string
		want    string
	}{
		{"rails", "7.0.4", "pkg:gem/rails@7.0.4"},
		{"actioncable", "7.0.4", "pkg:gem/actioncable@7.0.4"},
		{"nokogiri", "1.14.0", "pkg:gem/nokogiri@1.14.0"},
		{"rack", "", "pkg:gem/rack"},
	}

	for _, tt := range tests {
		t.Run(tt.name+"@"+tt.version, func(t *testing.T) {
			got := gemPkgToPURL(tt.name, tt.version)
			if got != tt.want {
				t.Errorf("gemPkgToPURL(%q, %q) = %q, want %q", tt.name, tt.version, got, tt.want)
			}
		})
	}
}
