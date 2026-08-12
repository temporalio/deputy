package surface

import (
	"go/ast"
	"go/types"
	"maps"
	"slices"
	"strings"
)

// Roles an interface can occupy in a type expression. Parameter and field are
// the two that make an interface a dependency someone accepts; the rest mean
// the name is used, but not as an abstraction anything is written against.
const (
	roleParameter  = "parameter"
	roleField      = "field"
	roleResult     = "result"
	roleVar        = "var"
	roleEmbedded   = "embedded"
	roleAssertion  = "assertion"
	roleConstraint = "constraint"
	roleComposite  = "composite"

	// roleMethodParam is a parameter of an interface method's own signature.
	// It is tracked apart from roleParameter because an interface whose only
	// "acceptance" is its own method taking itself is not a dependency any
	// caller was written against.
	roleMethodParam = "method-parameter"
)

// unusedInterfaces implements check 3: exported interfaces that no signature
// accepts as a parameter and no struct holds as a field. It returns the
// findings and the total exported interface count.
//
// Roles are read from declaration syntax, because the distinction the check
// cares about is syntactic position, not type identity: the same named type in
// a parameter list and in a return type means very different things for whether
// callers depend on the abstraction. Method sets come from go/types, so an
// interface embedded in another interface is counted as embedded even when the
// syntax only names the outer one.
func (p *program) unusedInterfaces() ([]InterfaceFinding, int) {
	candidates := p.exportedInterfaces()
	if len(candidates) == 0 {
		return nil, 0
	}

	roles := map[string]map[string]bool{}
	record := func(key, role string) {
		if roles[key] == nil {
			roles[key] = map[string]bool{}
		}
		roles[key][role] = true
	}

	// mention walks a resolved type and records the role for every candidate
	// interface it names, so an interface behind a slice, map, pointer, or
	// channel still counts as appearing in that position. Candidates are
	// looked up by package path and name, not by object identity: the same
	// interface has a distinct *types.TypeName in each compilation variant, so
	// identity would silently miss every mention made from a test file.
	mention := func(t types.Type, role string) {
		for _, tn := range namedTypes(t) {
			if tn.Pkg() == nil {
				continue
			}
			key := tn.Pkg().Path() + " " + tn.Name()
			if _, ok := candidates[key]; ok {
				record(key, role)
			}
		}
	}

	// methodSignatures holds the func types belonging to interface method
	// declarations. ast.Inspect is pre-order, so an interface is always seen
	// before its own method signatures.
	methodSignatures := map[*ast.FuncType]bool{}

	p.files(func(v *variant, file *ast.File) bool {
		info := v.pkg.TypesInfo
		typeOf := func(e ast.Expr) types.Type {
			if e == nil {
				return nil
			}
			return info.TypeOf(e)
		}
		ast.Inspect(file, func(n ast.Node) bool {
			switch node := n.(type) {
			case *ast.FuncType:
				paramRole := roleParameter
				if methodSignatures[node] {
					paramRole = roleMethodParam
				}
				if node.Params != nil {
					for _, f := range node.Params.List {
						mention(typeOf(f.Type), paramRole)
					}
				}
				if node.Results != nil {
					for _, f := range node.Results.List {
						mention(typeOf(f.Type), roleResult)
					}
				}
				if node.TypeParams != nil {
					for _, f := range node.TypeParams.List {
						mention(typeOf(f.Type), roleConstraint)
					}
				}
			case *ast.StructType:
				for _, f := range node.Fields.List {
					mention(typeOf(f.Type), roleField)
				}
			case *ast.InterfaceType:
				for _, f := range node.Methods.List {
					if len(f.Names) == 0 {
						mention(typeOf(f.Type), roleEmbedded)
						continue
					}
					if sig, ok := f.Type.(*ast.FuncType); ok {
						methodSignatures[sig] = true
					}
				}
			case *ast.ValueSpec:
				if node.Type != nil {
					mention(typeOf(node.Type), roleVar)
				}
			case *ast.TypeSpec:
				// A named type whose definition is an interface alias or a
				// composite naming the interface still depends on it.
				if _, isIface := node.Type.(*ast.InterfaceType); !isIface {
					mention(typeOf(node.Type), roleComposite)
				}
			case *ast.TypeAssertExpr:
				mention(typeOf(node.Type), roleAssertion)
			case *ast.CaseClause:
				for _, e := range node.List {
					if t := typeOf(e); t != nil {
						mention(t, roleAssertion)
					}
				}
			case *ast.CompositeLit:
				mention(typeOf(node.Type), roleComposite)
			}
			return true
		})
		return true
	})

	reach := p.interfaceReach(candidates)

	var out []InterfaceFinding
	for _, key := range sortedKeys(candidates) {
		c := candidates[key]
		if roles[key][roleParameter] || roles[key][roleField] {
			continue
		}
		out = append(out, InterfaceFinding{
			Package:  c.pkg,
			Name:     c.name.Name(),
			Position: p.position(c.name.Pos()),
			Methods:  c.iface.NumMethods(),
			Roles:    slices.Sorted(maps.Keys(roles[key])),
			Reach:    reach[key],
			Doubts:   p.dyn.interfaceDoubts(c.name, c.pkg),
		})
	}
	slices.SortFunc(out, func(a, b InterfaceFinding) int {
		if a.Package != b.Package {
			return strings.Compare(a.Package, b.Package)
		}
		return strings.Compare(a.Name, b.Name)
	})
	return out, len(candidates)
}

// candidate is an exported interface under audit.
type candidate struct {
	pkg   string
	name  *types.TypeName
	iface *types.Interface
}

// exportedInterfaces collects the exported interface types declared by audited
// packages, keyed by canonical path and name.
func (p *program) exportedInterfaces() map[string]candidate {
	out := map[string]candidate{}
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
			tn, ok := obj.(*types.TypeName)
			if !ok || tn.IsAlias() {
				continue
			}
			iface, ok := tn.Type().Underlying().(*types.Interface)
			if !ok {
				continue
			}
			out[path+" "+name] = candidate{pkg: path, name: tn, iface: iface}
		}
	}
	return out
}

// interfaceReach reuses the symbol reference scan to grade how far references to
// each interface name travel, which separates an interface nothing mentions at
// all from one that is mentioned but never depended on.
func (p *program) interfaceReach(candidates map[string]candidate) map[string]Reach {
	declared := make([]symbol, 0, len(candidates))
	for _, key := range sortedKeys(candidates) {
		c := candidates[key]
		declared = append(declared, symbol{pkg: c.pkg, name: c.name.Name(), kind: KindType, obj: c.name})
	}
	return p.referenceReach(declared)
}

// namedTypes collects the named types a type expression mentions, descending
// through pointers, slices, arrays, maps, channels, function signatures, and
// generic type arguments. Recursion is bounded by a seen set so a recursive
// type cannot loop.
func namedTypes(t types.Type) []*types.TypeName {
	var out []*types.TypeName
	seen := map[types.Type]bool{}

	var walk func(types.Type)
	walk = func(t types.Type) {
		if t == nil || seen[t] {
			return
		}
		seen[t] = true
		switch t := t.(type) {
		case *types.Named:
			out = append(out, t.Obj())
			if args := t.TypeArgs(); args != nil {
				for i := range args.Len() {
					walk(args.At(i))
				}
			}
		case *types.Alias:
			out = append(out, t.Obj())
			walk(types.Unalias(t))
		case *types.Pointer:
			walk(t.Elem())
		case *types.Slice:
			walk(t.Elem())
		case *types.Array:
			walk(t.Elem())
		case *types.Chan:
			walk(t.Elem())
		case *types.Map:
			walk(t.Key())
			walk(t.Elem())
		case *types.Signature:
			walkTuple(t.Params(), walk)
			walkTuple(t.Results(), walk)
		case *types.Interface:
			for i := range t.NumEmbeddeds() {
				walk(t.EmbeddedType(i))
			}
		case *types.Struct:
			for i := range t.NumFields() {
				walk(t.Field(i).Type())
			}
		case *types.Union:
			for i := range t.Len() {
				walk(t.Term(i).Type())
			}
		}
	}
	walk(t)
	return out
}

// walkTuple applies walk to every type in a tuple.
func walkTuple(tuple *types.Tuple, walk func(types.Type)) {
	if tuple == nil {
		return
	}
	for i := range tuple.Len() {
		walk(tuple.At(i).Type())
	}
}
