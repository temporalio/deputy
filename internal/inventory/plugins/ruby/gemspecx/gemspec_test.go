package gemspecx

import (
	"context"
	"io/fs"
	"strings"
	"testing"
	"testing/fstest"

	"github.com/google/osv-scalibr/extractor/filesystem"
)

func TestExtractVersionFromConstant(t *testing.T) {
	// Reproduces the sdk-ruby/temporalio case: gemspec uses require_relative
	// and a module constant for the version.
	memFS := fstest.MapFS{
		"temporalio/temporalio.gemspec": &fstest.MapFile{
			Data: []byte(`# frozen_string_literal: true

require_relative 'lib/temporalio/version'

Gem::Specification.new do |spec|
  spec.name = 'temporalio'
  spec.version = Temporalio::VERSION
  spec.authors = ['Temporal Technologies Inc']

  spec.add_dependency 'google-protobuf', '>= 3.25.0'
end
`),
		},
		"temporalio/lib/temporalio/version.rb": &fstest.MapFile{
			Data: []byte(`# frozen_string_literal: true

module Temporalio
  VERSION = '1.4.0'
end
`),
		},
	}

	f, err := memFS.Open("temporalio/temporalio.gemspec")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	input := &filesystem.ScanInput{
		FS:     memFS,
		Path:   "temporalio/temporalio.gemspec",
		Reader: f.(fs.File),
	}

	ext := Extractor{}
	inv, err := ext.Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(inv.Packages) == 0 {
		t.Fatal("expected at least one package")
	}

	pkg := inv.Packages[0]
	if pkg.Name != "temporalio" {
		t.Errorf("name = %q, want %q", pkg.Name, "temporalio")
	}
	if pkg.Version != "1.4.0" {
		t.Errorf("version = %q, want %q", pkg.Version, "1.4.0")
	}
}

func TestExtractVersionLiteral(t *testing.T) {
	gemspec := `Gem::Specification.new do |s|
  s.name = 'simple-gem'
  s.version = '2.0.1'
end
`
	memFS := fstest.MapFS{
		"simple-gem.gemspec": &fstest.MapFile{Data: []byte(gemspec)},
	}

	f, err := memFS.Open("simple-gem.gemspec")
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()

	input := &filesystem.ScanInput{
		FS:     memFS,
		Path:   "simple-gem.gemspec",
		Reader: f.(fs.File),
	}

	inv, err := (&Extractor{}).Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("Extract failed: %v", err)
	}

	if len(inv.Packages) == 0 {
		t.Fatal("expected at least one package")
	}
	if inv.Packages[0].Version != "2.0.1" {
		t.Errorf("version = %q, want %q", inv.Packages[0].Version, "2.0.1")
	}
}

func TestExtractNoSpec(t *testing.T) {
	// A file without Gem::Specification.new should return nothing.
	input := &filesystem.ScanInput{
		FS:     fstest.MapFS{},
		Path:   "empty.gemspec",
		Reader: strings.NewReader("# just a comment"),
	}

	inv, err := (&Extractor{}).Extract(context.Background(), input)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if len(inv.Packages) != 0 {
		t.Errorf("expected no packages, got %d", len(inv.Packages))
	}
}
