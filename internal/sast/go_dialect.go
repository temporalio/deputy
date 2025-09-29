package sast

import (
	"context"
	"fmt"
	"go/ast"
	"go/parser"
	"go/scanner"
	"go/token"
	"io/fs"
	"path"
	"sort"
	"strings"
)

// GoDialect provides a reference implementation of the Dialect interface for
// Go source code. It uses the Go standard library parser to build a lightweight
// call graph which is then lowered into the shared IR.
type GoDialect struct{}

// NewGoDialect constructs a GoDialect instance.
func NewGoDialect() *GoDialect {
	return &GoDialect{}
}

func (d *GoDialect) Name() string { return "go" }

func (d *GoDialect) Supports(target *Target) bool {
	if target == nil || target.FS == nil {
		return false
	}
	ctx := context.Background()
	found := false
	fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil || found {
			return err
		}
		if entry.IsDir() {
			if shouldSkipDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		if strings.HasSuffix(entry.Name(), ".go") {
			found = true
			return fs.SkipDir
		}
		return nil
	})
	return found && ctx.Err() == nil
}

func (d *GoDialect) DiscoverUnits(ctx context.Context, target *Target) ([]*CompilationUnit, error) {
	if target == nil || target.FS == nil {
		return nil, fmt.Errorf("nil target or filesystem")
	}
	packages := make(map[string][]string)
	err := fs.WalkDir(target.FS, ".", func(p string, entry fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if entry.IsDir() {
			if shouldSkipDir(p) {
				return fs.SkipDir
			}
			return nil
		}
		if !strings.HasSuffix(entry.Name(), ".go") {
			return nil
		}
		dir := path.Dir(p)
		packages[dir] = append(packages[dir], p)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if len(packages) == 0 {
		return nil, fmt.Errorf("no Go packages discovered")
	}
	units := make([]*CompilationUnit, 0, len(packages))
	for dir, files := range packages {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		sort.Strings(files)
		units = append(units, &CompilationUnit{
			Segment: TargetSegment{Path: dir, FS: target.FS},
			Path:    dir,
			Files:   files,
		})
	}
	sort.Slice(units, func(i, j int) bool {
		return units[i].Path < units[j].Path
	})
	return units, nil
}

// goUnit carries parsed files and token metadata through the pipeline.
type goUnit struct {
	FileSet *token.FileSet
	Files   map[string]*ast.File
	Package string
}

func (d *GoDialect) Prepare(ctx context.Context, unit *CompilationUnit) error {
	if unit == nil {
		return fmt.Errorf("nil compilation unit")
	}
	if len(unit.Files) == 0 {
		return fmt.Errorf("unit %s has no files", unit.Path)
	}
	fset := token.NewFileSet()
	parsed := make(map[string]*ast.File, len(unit.Files))
	var tokens []Token
	for _, file := range unit.Files {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}
		src, err := fs.ReadFile(unit.Segment.FS, file)
		if err != nil {
			return fmt.Errorf("read %s: %w", file, err)
		}
		astFile, err := parser.ParseFile(fset, file, src, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", file, err)
		}
		parsed[file] = astFile
		tokens = append(tokens, tokenizeGoFile(fset, astFile, src)...)
	}
	unit.Tokens = tokens
	var pkgName string
	for _, f := range parsed {
		pkgName = f.Name.Name
		break
	}
	unit.AST = &goUnit{
		FileSet: fset,
		Files:   parsed,
		Package: pkgName,
	}
	return nil
}

func (d *GoDialect) LowerToIR(ctx context.Context, unit *CompilationUnit) (*IRPackage, error) {
	data, ok := unit.AST.(*goUnit)
	if !ok {
		return nil, fmt.Errorf("unexpected AST payload for Go unit")
	}
	graph := NewGraph()
	functions := map[string]SymbolID{}
	var symbols []Symbol
	var entrypoints []SymbolID

	type declMeta struct {
		symbol Symbol
		decl   *ast.FuncDecl
	}
	var decls []declMeta

	for filePath, file := range data.Files {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		default:
		}
		for _, decl := range file.Decls {
			fn, ok := decl.(*ast.FuncDecl)
			if !ok {
				continue
			}
			recv := receiverName(fn)
			kind := SymbolKindFunction
			if recv != "" {
				kind = SymbolKindMethod
			}
			id := SymbolID{Dialect: d.Name(), Package: unit.Path, Name: fn.Name.Name, Recv: recv}
			loc := positionFromToken(data.FileSet, fn.Pos())
			display := fn.Name.Name
			if recv != "" {
				display = recv + "." + display
			}
			sym := Symbol{
				ID:        id,
				Kind:      kind,
				Display:   display,
				Locations: []Location{loc},
			}
			if data.Package == "main" && fn.Name.Name == "main" {
				if sym.Attributes == nil {
					sym.Attributes = make(map[string]any)
				}
				sym.Attributes["entrypoint"] = true
				entrypoints = append(entrypoints, sym.ID)
			}
			graph.AddSymbol(sym)
			symbols = append(symbols, sym)
			key := functionKey(fn.Name.Name, recv)
			functions[key] = sym.ID
			decls = append(decls, declMeta{symbol: sym, decl: fn})
		}
		_ = filePath
	}

	for _, meta := range decls {
		fn := meta.decl
		if fn.Body == nil {
			continue
		}
		currentID := meta.symbol.ID
		ast.Inspect(fn.Body, func(n ast.Node) bool {
			select {
			case <-ctx.Done():
				return false
			default:
			}
			call, ok := n.(*ast.CallExpr)
			if !ok {
				return true
			}
			name, recv := callName(call)
			if name == "" {
				return true
			}
			callee, ok := functions[functionKey(name, recv)]
			if !ok {
				return true
			}
			graph.AddEdge(EdgeKindCall, currentID, callee)
			return true
		})
	}

	return &IRPackage{
		Dialect:     d.Name(),
		Unit:        unit,
		Graph:       graph,
		Symbols:     symbols,
		Entrypoints: entrypoints,
	}, nil
}

func shouldSkipDir(name string) bool {
	if name == "." || name == "" {
		return false
	}
	base := path.Base(name)
	if base == "vendor" || strings.HasPrefix(base, ".") {
		return true
	}
	return false
}

func tokenizeGoFile(fset *token.FileSet, file *ast.File, src []byte) []Token {
	var tokens []Token
	tokFile := fset.File(file.Pos())
	if tokFile == nil {
		return tokens
	}
	var s scanner.Scanner
	s.Init(tokFile, src, nil, scanner.ScanComments)
	for {
		pos, tok, lit := s.Scan()
		if tok == token.EOF {
			break
		}
		text := lit
		if text == "" {
			text = tok.String()
		}
		start := fset.Position(pos)
		end := start
		var width int
		if lit != "" {
			w := []rune(lit)
			end.Column += len(w)
			width = len(lit)
		} else {
			w := []rune(text)
			end.Column += len(w)
			width = len(text)
		}
		end.Offset = start.Offset + width
		tokens = append(tokens, Token{
			Kind: TokenKind(tok.String()),
			Text: text,
			Range: Span{
				File: start.Filename,
				Start: Position{
					Line:   start.Line,
					Column: start.Column,
					Offset: start.Offset,
				},
				End: Position{
					Line:   end.Line,
					Column: end.Column,
					Offset: end.Offset,
				},
			},
		})
	}
	return tokens
}

func positionFromToken(fset *token.FileSet, pos token.Pos) Location {
	p := fset.PositionFor(pos, false)
	return Location{File: p.Filename, Line: p.Line, Column: p.Column}
}

func receiverName(fn *ast.FuncDecl) string {
	if fn.Recv == nil || len(fn.Recv.List) == 0 {
		return ""
	}
	typeExpr := fn.Recv.List[0].Type
	switch t := typeExpr.(type) {
	case *ast.Ident:
		return t.Name
	case *ast.StarExpr:
		if ident, ok := t.X.(*ast.Ident); ok {
			return ident.Name
		}
	}
	return ""
}

func callName(call *ast.CallExpr) (name, recv string) {
	switch fun := call.Fun.(type) {
	case *ast.Ident:
		return fun.Name, ""
	case *ast.SelectorExpr:
		if id, ok := fun.X.(*ast.Ident); ok {
			return fun.Sel.Name, id.Name
		}
		return fun.Sel.Name, ""
	}
	return "", ""
}

func functionKey(name, recv string) string {
	if recv == "" {
		return name
	}
	return recv + "." + name
}
