// Package nixstore provides extraction of Nix packages from the Nix store.
package nixstore

import (
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/nix-community/go-nix/pkg/derivation"
)

// Derivation wraps a parsed Nix .drv file.
type Derivation struct {
	// Path is the path to the .drv file.
	Path string

	// Name is the derivation name (from env["name"] or structured attrs).
	Name string

	// System is the target platform (e.g., "x86_64-linux", "aarch64-darwin").
	System string

	// Builder is the path to the builder executable.
	Builder string

	// Outputs maps output names to their store paths.
	// e.g., {"out": "/nix/store/...", "dev": "/nix/store/...-dev"}
	Outputs map[string]string

	// InputDerivations maps input .drv paths to their required output names.
	// This represents build-time dependencies.
	InputDerivations map[string][]string

	// InputSources are store paths of source files used in the build.
	InputSources []string

	// Env contains environment variables set during the build.
	Env map[string]string

	// The underlying go-nix derivation (for advanced use).
	raw *derivation.Derivation
}

// DerivationReference represents a reference to another derivation.
type DerivationReference struct {
	// Path is the .drv file path.
	Path string
	// Outputs are the output names used from this derivation.
	Outputs []string
}

// ParseDerivation parses a .drv file from an io.Reader.
func ParseDerivation(r io.Reader, path string) (*Derivation, error) {
	drv, err := derivation.ReadDerivation(r)
	if err != nil {
		return nil, fmt.Errorf("parse derivation: %w", err)
	}

	d := &Derivation{
		Path:             path,
		Name:             drv.Name(),
		System:           drv.Platform,
		Builder:          drv.Builder,
		Outputs:          make(map[string]string),
		InputDerivations: drv.InputDerivations,
		InputSources:     drv.InputSources,
		Env:              drv.Env,
		raw:              drv,
	}

	for name, output := range drv.Outputs {
		if output != nil {
			d.Outputs[name] = output.Path
		}
	}

	return d, nil
}

// ParseDerivationFile parses a .drv file from disk.
func ParseDerivationFile(path string) (*Derivation, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	return ParseDerivation(f, path)
}

// Dependencies returns the derivation references this derivation depends on.
func (d *Derivation) Dependencies() []DerivationReference {
	refs := make([]DerivationReference, 0, len(d.InputDerivations))
	for path, outputs := range d.InputDerivations {
		refs = append(refs, DerivationReference{
			Path:    path,
			Outputs: outputs,
		})
	}
	// Sort for deterministic output
	sort.Slice(refs, func(i, j int) bool {
		return refs[i].Path < refs[j].Path
	})
	return refs
}

// OutputPath returns the store path for a given output name.
// Returns empty string if output doesn't exist.
func (d *Derivation) OutputPath(outputName string) string {
	if outputName == "" {
		outputName = "out"
	}
	return d.Outputs[outputName]
}

// AllOutputPaths returns all output paths for this derivation.
func (d *Derivation) AllOutputPaths() []string {
	paths := make([]string, 0, len(d.Outputs))
	for _, path := range d.Outputs {
		paths = append(paths, path)
	}
	sort.Strings(paths)
	return paths
}

// DerivationStore manages a collection of parsed derivations.
type DerivationStore struct {
	// derivations maps .drv paths to parsed derivations.
	derivations map[string]*Derivation

	// outputToDerivation maps output paths to their derivation.
	outputToDerivation map[string]*Derivation
}

// NewDerivationStore creates a new derivation store.
func NewDerivationStore() *DerivationStore {
	return &DerivationStore{
		derivations:        make(map[string]*Derivation),
		outputToDerivation: make(map[string]*Derivation),
	}
}

// Add adds a derivation to the store.
func (s *DerivationStore) Add(d *Derivation) {
	s.derivations[d.Path] = d
	for _, outputPath := range d.Outputs {
		s.outputToDerivation[outputPath] = d
	}
}

// Get returns a derivation by its .drv path.
func (s *DerivationStore) Get(drvPath string) *Derivation {
	return s.derivations[drvPath]
}

// GetByOutputPath returns the derivation that produces a given output path.
func (s *DerivationStore) GetByOutputPath(outputPath string) *Derivation {
	return s.outputToDerivation[outputPath]
}

// LoadFromDirectory loads all .drv files from a directory.
func (s *DerivationStore) LoadFromDirectory(storeDir string) error {
	if storeDir == "" {
		storeDir = "/nix/store"
	}

	entries, err := os.ReadDir(storeDir)
	if err != nil {
		return fmt.Errorf("read store directory: %w", err)
	}

	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".drv") {
			continue
		}

		path := filepath.Join(storeDir, entry.Name())
		drv, err := ParseDerivationFile(path)
		if err != nil {
			// Skip invalid derivations, log would be nice
			continue
		}

		s.Add(drv)
	}

	return nil
}

// FindDependencies returns all store paths that an output path depends on.
func (s *DerivationStore) FindDependencies(outputPath string) []string {
	drv := s.GetByOutputPath(outputPath)
	if drv == nil {
		return nil
	}

	var deps []string
	for drvPath, outputNames := range drv.InputDerivations {
		inputDrv := s.Get(drvPath)
		if inputDrv == nil {
			continue
		}

		for _, outputName := range outputNames {
			if path := inputDrv.OutputPath(outputName); path != "" {
				deps = append(deps, path)
			}
		}
	}

	// Also include input sources
	deps = append(deps, drv.InputSources...)

	sort.Strings(deps)
	return deps
}

// All returns all derivations in the store.
func (s *DerivationStore) All() []*Derivation {
	result := make([]*Derivation, 0, len(s.derivations))
	for _, d := range s.derivations {
		result = append(result, d)
	}
	return result
}

// ParseStorePath extracts package info from a derivation's output path.
// This is useful for correlating store paths with their derivations.
func ParseStorePath(outputPath string) (hash, name, version, output string) {
	return parseNixStorePath(outputPath)
}
