package sast

import (
	"context"
	"fmt"
	"io/fs"
	"path/filepath"
	"sort"
	"strings"
)

// JavaScriptDialect implements SAST analysis for JavaScript and TypeScript code.
type JavaScriptDialect struct{}

// NewJavaScriptDialect constructs a JavaScriptDialect instance ready for registration.
func NewJavaScriptDialect() *JavaScriptDialect { return &JavaScriptDialect{} }

func (d *JavaScriptDialect) Name() string { return "javascript" }

func (d *JavaScriptDialect) Supports(target *Target) bool {
	var hasJavaScript bool

	fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		if entry.IsDir() {
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
			hasJavaScript = true
			return fs.SkipAll
		}
		return nil
	})

	return hasJavaScript
}

func (d *JavaScriptDialect) DiscoverUnits(ctx context.Context, target *Target) ([]*CompilationUnit, error) {
	var units []*CompilationUnit
	var files []string

	err := fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			// Skip common directories that don't contain source code
			name := entry.Name()
			if name == "node_modules" || name == ".git" || name == "dist" || name == "build" {
				return fs.SkipDir
			}
			return nil
		}

		ext := strings.ToLower(filepath.Ext(p))
		switch ext {
		case ".js", ".jsx", ".ts", ".tsx", ".mjs", ".cjs":
			files = append(files, p)
		}
		return nil
	})

	if err != nil {
		return nil, fmt.Errorf("failed to walk target filesystem: %w", err)
	}

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

func (d *JavaScriptDialect) Prepare(ctx context.Context, unit *CompilationUnit) error {
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
		allContent.WriteString(fmt.Sprintf("// === FILE: %s ===\n", file))
		allContent.Write(content)
		allContent.WriteString("\n")
	}

	unit.Source = []byte(allContent.String())
	return nil
}

func (d *JavaScriptDialect) LowerToIR(ctx context.Context, unit *CompilationUnit) (*IRPackage, error) {
	if unit.Source == nil {
		return nil, fmt.Errorf("unit %s has no source content", unit.Path)
	}

	content := string(unit.Source)

	// Create a new parser instance
	parser := &jsParser{
		content:    content,
		unitPath:   unit.Path,
		files:      unit.Files,
		graph:      NewGraph(),
		symbols:    []Symbol{},
		scopeStack: []string{},
	}

	// Parse the JavaScript/TypeScript content
	err := parser.parse()
	if err != nil {
		return nil, fmt.Errorf("failed to parse JavaScript content: %w", err)
	}

	// Apply security analysis
	securityAnalyzer := &jsSecurityAnalyzer{}
	securityAnalyzer.analyze(parser.graph, parser.symbols)

	// Find entry points (exported functions, main functions, etc.)
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
