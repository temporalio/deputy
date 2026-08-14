package surface

import (
	"go/types"
	"slices"
	"strings"
)

// symbol is one exported declaration under audit, identified by canonical
// package path and name rather than by *types.Object: loading with tests gives
// a package two type-checked instances, so object identity does not survive
// across variants and a stable key must carry the identity instead.
type symbol struct {
	pkg  string
	name string
	kind SymbolKind
	obj  types.Object
}

// key identifies a symbol across compilation variants.
func (s symbol) key() string { return s.pkg + " " + s.name }

// unusedSymbols implements check 2: exported symbols that nothing outside the
// declaring package references. It also returns the total exported surface per
// kind, so a finding count can be read against the surface it came from.
//
// References are read from the type checker's Uses map over every compilation
// variant, which is why a test file in another package counts as a reference.
// The declaring package's own files, including its in-package test files, do
// not: they are inside the boundary an unexport would draw.
func (p *program) unusedSymbols() ([]SymbolFinding, map[SymbolKind]int) {
	declared := p.exportedSymbols()
	totals := map[SymbolKind]int{}
	for _, s := range declared {
		totals[s.kind]++
	}

	reach := p.referenceReach(declared)

	var out []SymbolFinding
	for _, s := range declared {
		r := reach[s.key()]
		if r == ReachProduction {
			continue
		}
		out = append(out, SymbolFinding{
			Package:  s.pkg,
			Name:     s.name,
			Kind:     s.kind,
			Position: p.position(s.obj.Pos()),
			Reach:    r,
			Doubts:   p.dyn.symbolDoubts(s.obj, s.kind, s.pkg),
		})
	}
	slices.SortFunc(out, func(a, b SymbolFinding) int {
		if a.Package != b.Package {
			return strings.Compare(a.Package, b.Package)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, totals
}

// exportedSymbols lists the exported declarations of every audited package: the
// package-level funcs, types, vars, and consts, plus the exported methods
// declared on exported named types. Struct fields are deliberately excluded:
// this module populates most of them through encoding tags, so auditing fields
// would report codec-driven use as dead surface.
func (p *program) exportedSymbols() []symbol {
	var out []symbol
	for _, path := range p.auditedPaths() {
		plain := p.plain(path)
		if plain == nil || plain.Name == "main" {
			continue
		}
		scope := plain.Types.Scope()
		for _, name := range scope.Names() {
			obj := scope.Lookup(name)
			if !obj.Exported() {
				continue
			}
			kind, ok := symbolKind(obj)
			if !ok {
				continue
			}
			out = append(out, symbol{pkg: path, name: name, kind: kind, obj: obj})

			tn, ok := obj.(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			for _, m := range exportedMethods(tn) {
				out = append(out, symbol{
					pkg:  path,
					name: name + "." + m.Name(),
					kind: KindMethod,
					obj:  m,
				})
			}
		}
	}
	return out
}

// symbolKind maps a package-level object to the kind the report uses. Objects
// that are not declarations of interest report false.
func symbolKind(obj types.Object) (SymbolKind, bool) {
	switch o := obj.(type) {
	case *types.Func:
		return KindFunc, true
	case *types.TypeName:
		return KindType, true
	case *types.Const:
		return KindConst, true
	case *types.Var:
		if o.IsField() {
			return "", false
		}
		return KindVar, true
	default:
		return "", false
	}
}

// exportedMethods returns the exported methods a named type declares itself:
// concrete methods for both receiver forms, and an interface's own method set.
// Promoted methods belong to the embedded type and are audited there.
func exportedMethods(tn *types.TypeName) []*types.Func {
	named, ok := tn.Type().(*types.Named)
	if !ok {
		return nil
	}
	var out []*types.Func
	for i := range named.NumMethods() {
		if m := named.Method(i); m.Exported() {
			out = append(out, m)
		}
	}
	if iface, ok := named.Underlying().(*types.Interface); ok {
		for i := range iface.NumExplicitMethods() {
			if m := iface.ExplicitMethod(i); m.Exported() {
				out = append(out, m)
			}
		}
	}
	return out
}

// declaring records which audited symbol an object refers to, keeping the
// declaring package alongside the key so reference classification never has to
// parse a package path back out of a key.
type declaring struct {
	key string
	pkg string
}

// referenceReach computes, for every audited symbol, the furthest a reference
// to it travels. Production use anywhere outside the declaring package wins
// over test-only use, which wins over the package's own black-box test, which
// wins over nothing at all.
func (p *program) referenceReach(declared []symbol) map[string]Reach {
	index := make(map[types.Object]declaring, len(declared)*2)
	reach := make(map[string]Reach, len(declared))
	for _, s := range declared {
		index[s.obj] = declaring{key: s.key(), pkg: s.pkg}
		reach[s.key()] = ReachNone
	}

	// A symbol's object identity differs per compilation variant, so map the
	// in-package test variant's objects onto the same keys. Without this, a
	// reference resolved against the test variant of a package would look like
	// a reference to nothing.
	for _, path := range p.auditedPaths() {
		for _, v := range p.pkgs[path] {
			if !v.test || v.externalTest {
				continue
			}
			indexVariantScope(index, reach, path, v.pkg.Types.Scope())
		}
	}

	for _, v := range p.variants() {
		for _, obj := range v.pkg.TypesInfo.Uses {
			decl, ok := index[origin(obj)]
			if !ok {
				continue
			}
			if decl.pkg == v.canonical && !v.externalTest {
				// The declaring package referring to its own symbol, including
				// from an in-package test file: inside the unexport boundary.
				continue
			}
			candidate := ReachProduction
			switch {
			case v.externalTest && v.canonical == decl.pkg:
				candidate = ReachOwnTest
			case v.test:
				candidate = ReachForeignTest
			}
			if candidate > reach[decl.key] {
				reach[decl.key] = candidate
			}
		}
	}
	return reach
}

// indexVariantScope maps a test variant's objects onto the canonical keys of
// the package's exported symbols.
func indexVariantScope(index map[types.Object]declaring, reach map[string]Reach, path string, scope *types.Scope) {
	for _, name := range scope.Names() {
		obj := scope.Lookup(name)
		if !obj.Exported() {
			continue
		}
		key := path + " " + name
		if _, ok := reach[key]; ok {
			index[obj] = declaring{key: key, pkg: path}
		}
		tn, ok := obj.(*types.TypeName)
		if !ok || tn.IsAlias() {
			continue
		}
		for _, m := range exportedMethods(tn) {
			mkey := path + " " + name + "." + m.Name()
			if _, ok := reach[mkey]; ok {
				index[m] = declaring{key: mkey, pkg: path}
			}
		}
	}
}
