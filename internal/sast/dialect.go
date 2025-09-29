package sast

import (
	"context"
	"io/fs"
)

// Position models a 1-based location in a source file. Offset is optional but
// kept to facilitate SSA builders that require byte-accurate spans.
type Position struct {
	Line   int
	Column int
	Offset int
}

// Span captures the start and end positions for tokens or AST nodes.
type Span struct {
	File       string
	Start, End Position
}

// TokenKind identifies the syntactic category of a token.
type TokenKind string

const (
	TokenKindIdentifier TokenKind = "identifier"
	TokenKindKeyword    TokenKind = "keyword"
)

// Token represents a lexical token produced by a dialect specific lexer.
type Token struct {
	Kind  TokenKind
	Text  string
	Range Span
}

// Lexer is responsible for turning source files into token streams.
type Lexer interface {
	Dialect() string
	Lex(ctx context.Context, path string, reader fs.File) ([]Token, error)
}

// Parser consumes tokens and produces an AST. The AST representation is dialect
// defined (it may be a struct hierarchy, a generic tree, or a pointer to
// language native nodes such as go/ast).
type Parser interface {
	Dialect() string
	Parse(ctx context.Context, unit *CompilationUnit) (any, error)
}

// SemanticAnalyzer performs dialect specific semantic passes prior to IR
// lowering (type resolution, control flow construction, etc.). It can be nil for
// languages where the parser already carries semantic info.
type SemanticAnalyzer interface {
	Dialect() string
	Analyze(ctx context.Context, unit *CompilationUnit) error
}

// CompilationUnit is the canonical container passed between pipeline stages.
// Dialects are responsible for filling the AST field with a type they
// understand. The pipeline remains opaque to the contents.
type CompilationUnit struct {
	Segment TargetSegment
	Path    string
	Files   []string
	Source  []byte
	Tokens  []Token
	AST     any
	IR      *IRPackage
}

// IRPackage groups the IR graph fragments and local metadata emitted by a
// dialect for a compilation unit (package, module, etc.).
type IRPackage struct {
	Dialect     string
	Unit        *CompilationUnit
	Graph       *Graph
	Symbols     []Symbol
	Entrypoints []SymbolID
}

// Dialect describes how to build IR graph fragments for a specific language.
type Dialect interface {
	Name() string
	Supports(target *Target) bool
	DiscoverUnits(ctx context.Context, target *Target) ([]*CompilationUnit, error)
	Prepare(ctx context.Context, unit *CompilationUnit) error
	LowerToIR(ctx context.Context, unit *CompilationUnit) (*IRPackage, error)
}

// DialectRegistry stores available dialects. It chooses the first dialect that
// reports support for a target.
type DialectRegistry struct {
	dialects []Dialect
}

// NewDialectRegistry builds an empty registry ready for registrations.
func NewDialectRegistry() *DialectRegistry {
	return &DialectRegistry{}
}

// Register adds a dialect to the registry.
func (r *DialectRegistry) Register(d Dialect) {
	r.dialects = append(r.dialects, d)
}

// Dialects exposes registered dialects for inspection.
func (r *DialectRegistry) Dialects() []Dialect {
	out := make([]Dialect, len(r.dialects))
	copy(out, r.dialects)
	return out
}

// Resolve selects the first dialect that supports the given target.
func (r *DialectRegistry) Resolve(target *Target) Dialect {
	for _, d := range r.dialects {
		if d.Supports(target) {
			return d
		}
	}
	return nil
}
