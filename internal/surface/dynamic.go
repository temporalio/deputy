package surface

import (
	"go/ast"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"unicode"
)

// dynamic answers check 4: it collects the evidence that a declaration might be
// reached without any package naming it in source. Nothing here proves a
// symbol is live; each signal is a reason the audit records as a doubt instead
// of asserting a finding.
//
// The signals are the ways this module actually reaches code indirectly:
// dispatch through an interface, encoding driven by struct tags, protobuf
// registration, plugin and registry lookup by name, and templates or policies
// that name a field in text rather than in Go.
type dynamic struct {
	// tokens holds every identifier-shaped token found in a Go string literal
	// or in a non-Go repository asset (templates, policies, configuration,
	// documentation). A symbol whose name appears there may be looked up by
	// name rather than referenced.
	tokens map[string]bool

	// interfaceMethods holds every method name in the method set of any
	// interface in the module. A method with such a name can be called through
	// an interface without its own name ever appearing at the call site.
	interfaceMethods map[string]bool

	// taggedFields holds "Type.Field" for every struct field carrying an
	// encoding tag, plus the bare type name, since a tagged struct is normally
	// populated by a decoder rather than by field assignment.
	taggedFields map[string]bool

	// blankImported holds canonical paths imported for side effects only. Such
	// a package's exported symbols are wired up by its own init, not by a
	// caller naming them.
	blankImported map[string]bool
}

// encodingTags are the struct tag keys that mean a field is read or written by
// a reflective codec in this module.
var encodingTags = []string{"json", "yaml", "toml", "protobuf", "cel", "xml", "mapstructure", "kong", "env"}

// assetExtensions are the non-Go files whose text can name a Go symbol: policy
// sources, templates, configuration, fixtures, and documentation.
var assetExtensions = map[string]bool{
	".cel":       true,
	".tmpl":      true,
	".gotmpl":    true,
	".md":        true,
	".yaml":      true,
	".yml":       true,
	".json":      true,
	".toml":      true,
	".proto":     true,
	".txt":       true,
	".textproto": true,
}

// newDynamic gathers the dynamic-reachability evidence for the whole module.
func newDynamic(p *program) *dynamic {
	d := &dynamic{
		tokens:           map[string]bool{},
		interfaceMethods: map[string]bool{},
		taggedFields:     map[string]bool{},
		blankImported:    map[string]bool{},
	}

	p.files(func(v *variant, file *ast.File) bool {
		// Import paths are string literals too, and tokenizing them would put
		// every package and symbol path fragment in the token set, making the
		// "named as a string" signal fire for nearly everything.
		importPaths := map[*ast.BasicLit]bool{}
		for _, imp := range file.Imports {
			importPaths[imp.Path] = true
			if imp.Name != nil && imp.Name.Name == "_" {
				if path, err := strconv.Unquote(imp.Path.Value); err == nil {
					d.blankImported[path] = true
				}
			}
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.BasicLit:
				if node.Kind == token.STRING && !importPaths[node] {
					if s, err := strconv.Unquote(node.Value); err == nil {
						d.addTokens(s)
					}
				}
			case *ast.StructType:
				d.addTaggedFields(v, node)
			}
			return true
		})
		return true
	})

	for _, v := range p.variants() {
		d.addInterfaceMethods(v.pkg.Types.Scope())
	}
	d.addAssets(p.rootHint())
	return d
}

// addTokens splits text into identifier-shaped tokens. Splitting beats
// substring matching: it will not let "Expirable" match inside
// "NotExpirableAtAll", and it costs one pass.
func (d *dynamic) addTokens(text string) {
	start := -1
	for i, r := range text {
		if isIdentRune(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			d.tokens[text[start:i]] = true
			start = -1
		}
	}
	if start >= 0 {
		d.tokens[text[start:]] = true
	}
}

// isIdentRune reports whether r can appear in a Go identifier.
func isIdentRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// addTaggedFields records struct fields carrying an encoding tag, and the
// enclosing named type when one can be determined from the field's own type
// info.
func (d *dynamic) addTaggedFields(v *variant, st *ast.StructType) {
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			continue
		}
		if !hasEncodingTag(tag) {
			continue
		}
		for _, name := range field.Names {
			obj := v.pkg.TypesInfo.Defs[name]
			if obj == nil {
				continue
			}
			d.taggedFields[obj.Name()] = true
		}
	}
}

// hasEncodingTag reports whether a struct tag names a reflective codec.
func hasEncodingTag(tag string) bool {
	for _, key := range encodingTags {
		if strings.Contains(tag, key+":\"") {
			return true
		}
	}
	return false
}

// addInterfaceMethods records the method names of every interface declared in
// a package scope, including methods promoted from embedded interfaces.
func (d *dynamic) addInterfaceMethods(scope *types.Scope) {
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		tn, ok := obj.(*types.TypeName)
		if !ok {
			continue
		}
		iface, ok := tn.Type().Underlying().(*types.Interface)
		if !ok {
			continue
		}
		for m := range iface.NumMethods() {
			d.interfaceMethods[iface.Method(m).Name()] = true
		}
	}
}

// addAssets tokenizes the repository's non-Go text files, so a field named only
// in a template, a CEL policy, or a fixture is not reported as unreferenced.
// Directories the Go tool itself ignores (dot-prefixed, "testdata" excluded
// deliberately since fixtures do name symbols) are skipped along with vendored
// and version-control trees.
func (d *dynamic) addAssets(root string) {
	if root == "" {
		return
	}
	filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if err != nil {
			return nil //nolint:nilerr // an unreadable tree only costs evidence
		}
		name := entry.Name()
		if entry.IsDir() {
			if path != root && (strings.HasPrefix(name, ".") || name == "vendor" || name == "node_modules") {
				return fs.SkipDir
			}
			return nil
		}
		if !assetExtensions[strings.ToLower(filepath.Ext(name))] {
			return nil
		}
		info, statErr := entry.Info()
		if statErr != nil || info.Size() > maxAssetBytes {
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			return nil
		}
		d.addTokens(string(data))
		return nil
	})
}

// maxAssetBytes caps the asset files scanned for identifier tokens, so a large
// generated fixture cannot dominate the audit's runtime.
const maxAssetBytes = 4 << 20

// symbolDoubts returns the reasons a symbol finding might be wrong.
func (d *dynamic) symbolDoubts(obj types.Object, kind SymbolKind, pkgPath string) []string {
	var doubts []string
	if kind == KindMethod && d.interfaceMethods[obj.Name()] {
		doubts = append(doubts, "method name is in an interface method set, so calls can reach it through dispatch")
	}
	if d.tokens[obj.Name()] {
		doubts = append(doubts, "name appears as a token in a Go string literal or repository asset, so it may be looked up by name")
	}
	if d.blankImported[pkgPath] {
		doubts = append(doubts, "declaring package is imported for side effects only, so its exports are wired up by registration")
	}
	if tn, ok := obj.(*types.TypeName); ok && d.protoLike(tn) {
		doubts = append(doubts, "type is a protobuf message, reachable through the proto registry")
	}
	if d.taggedFields[obj.Name()] {
		doubts = append(doubts, "an encoding struct tag names this identifier, so a codec may reach it reflectively")
	}
	return doubts
}

// protoLike reports whether a type implements protoreflect's message contract,
// which makes it reachable through the protobuf registry regardless of what
// references it.
func (d *dynamic) protoLike(tn *types.TypeName) bool {
	ptr := types.NewPointer(tn.Type())
	for _, t := range []types.Type{tn.Type(), ptr} {
		ms := types.NewMethodSet(t)
		for i := range ms.Len() {
			if ms.At(i).Obj().Name() == "ProtoReflect" {
				return true
			}
		}
	}
	return false
}

// interfaceDoubts returns the reasons an interface finding might be wrong.
func (d *dynamic) interfaceDoubts(obj types.Object, pkgPath string) []string {
	var doubts []string
	if d.tokens[obj.Name()] {
		doubts = append(doubts, "name appears as a token in a Go string literal or repository asset")
	}
	if d.blankImported[pkgPath] {
		doubts = append(doubts, "declaring package is imported for side effects only")
	}
	return doubts
}

// packageDoubts returns the reasons an unreachable-package finding might be
// wrong. Go has no dynamic package loading, so the escape hatches are narrow:
// a blank import the canonical indexing failed to attribute, or a package
// imported only from files this platform's build constraints exclude, which the
// import graph handles separately.
func (d *dynamic) packageDoubts(path string) []string {
	if d.blankImported[path] {
		return []string{"package is imported for side effects somewhere, so the import graph does reach it"}
	}
	return nil
}
