package sast

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// PythonDialect implements SAST analysis for Python code.
type PythonDialect struct{}

// NewPythonDialect constructs a PythonDialect instance ready for registration.
func NewPythonDialect() *PythonDialect { return &PythonDialect{} }

func (d *PythonDialect) Name() string { return "python" }

func (d *PythonDialect) Supports(target *Target) bool {
	var hasPython bool

	fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".py", ".pyw", ".pyi":
			hasPython = true
			return fs.SkipAll
		}
		return nil
	})

	return hasPython
}

func (d *PythonDialect) DiscoverUnits(ctx context.Context, target *Target) ([]*CompilationUnit, error) {
	var units []*CompilationUnit
	var files []string

	err := fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Skip common directories that don't contain source code
			name := entry.Name()
			if name == "__pycache__" || name == ".git" || name == "venv" ||
				name == ".venv" || name == "env" || name == ".env" ||
				name == "site-packages" || name == ".pytest_cache" ||
				name == "dist" || name == "build" || name == ".tox" {
				return fs.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".py", ".pyw", ".pyi":
			files = append(files, p)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to discover Python files: %w", err)
	}

	sort.Strings(files)

	// Group files by directory to create logical compilation units
	filesByDir := make(map[string][]string)
	for _, file := range files {
		dir := filepath.Dir(file)
		if dir == "." {
			dir = ""
		}
		filesByDir[dir] = append(filesByDir[dir], file)
	}

	// Create compilation units
	for dir, dirFiles := range filesByDir {
		unit := &CompilationUnit{
			Segment: TargetSegment{Path: dir, FS: target.FS},
			Path:    dir,
			Files:   dirFiles,
		}
		units = append(units, unit)
	}

	// Sort units by path for consistent ordering
	sort.Slice(units, func(i, j int) bool { return units[i].Path < units[j].Path })

	return units, nil
}

func (d *PythonDialect) Prepare(ctx context.Context, unit *CompilationUnit) error {
	if len(unit.Files) == 0 {
		return fmt.Errorf("unit %s has no files", unit.Path)
	}

	// Read and concatenate all files in the unit
	var allContent strings.Builder
	for _, file := range unit.Files {
		content, err := fs.ReadFile(unit.Segment.FS, file)
		if err != nil {
			return fmt.Errorf("failed to read file %s: %w", file, err)
		}

		// Add file separator comment for debugging
		allContent.WriteString(fmt.Sprintf("# === FILE: %s ===\n", file))
		allContent.Write(content)
		allContent.WriteString("\n")
	}

	unit.Source = []byte(allContent.String())
	return nil
}

func (d *PythonDialect) LowerToIR(ctx context.Context, unit *CompilationUnit) (*IRPackage, error) {
	if unit.Source == nil {
		return nil, fmt.Errorf("unit %s has no source content", unit.Path)
	}

	content := string(unit.Source)

	// Create a new parser instance
	parser := &pythonParser{
		content:    content,
		unitPath:   unit.Path,
		files:      unit.Files,
		graph:      NewGraph(),
		symbols:    []Symbol{},
		scopeStack: []string{},
	}

	// Parse the Python content
	err := parser.parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse Python content: %w", err)
	}

	// Apply security analysis
	securityAnalyzer := &pythonSecurityAnalyzer{}
	securityAnalyzer.analyze(parser.graph, parser.symbols)

	// Find entry points (main functions, module-level code, etc.)
	var entrypoints []SymbolID
	for _, symbol := range parser.symbols {
		if attrs := symbol.Attributes; attrs != nil {
			if isEntry, exists := attrs["entry_point"]; exists && isEntry.(bool) {
				entrypoints = append(entrypoints, symbol.ID)
			}
		}
	}

	return &IRPackage{
		Dialect:     d.Name(),
		Unit:        unit,
		Graph:       parser.graph,
		Symbols:     parser.symbols,
		Entrypoints: entrypoints,
	}, nil
}

// Ensure PythonDialect implements the Dialect interface
var _ Dialect = (*PythonDialect)(nil)
