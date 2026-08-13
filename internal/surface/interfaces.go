package surface

import (
	"go/ast"
	"go/types"
	"iter"
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

	// typeSwitchClauses holds the case clauses that belong to a type switch, which
	// are the only ones whose expressions are types. An ordinary expression switch
	// has the same clause node holding values, and reading those as types recorded
	// an assertion nobody wrote: "switch f { case defaultFormat: }" would report
	// that something asserts on the interface defaultFormat happens to have. The
	// same pre-order guarantee applies, so a type switch is seen before its
	// clauses.
	typeSwitchClauses := map[*ast.CaseClause]bool{}

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
			case *ast.TypeSwitchStmt:
				if node.Body == nil {
					break
				}
				for _, stmt := range node.Body.List {
					if clause, ok := stmt.(*ast.CaseClause); ok {
						typeSwitchClauses[clause] = true
					}
				}
			case *ast.CaseClause:
				if !typeSwitchClauses[node] {
					// An expression switch. Its cases are values, so nothing here
					// asserts on a type.
					break
				}
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
			Doubts:   p.dyn.interfaceDoubts(c.name),
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

// typesIn yields every type a type expression mentions, descending through
// pointers, slices, arrays, maps, channels, function signatures, structs,
// unions, and generic type arguments. Recursion is bounded by a seen set so a
// recursive type cannot loop.
//
// A named type is yielded but not opened. Its definition belongs to its own
// declaration, and descending into it would credit a struct's field types to
// every signature that merely mentions the struct.
//
// Two callers share this walk because they want different nodes out of the same
// traversal, and a second copy of it is how one of them would quietly stop
// matching the other: [namedTypes] takes the declarations a type expression
// mentions, and [dynamic.addReferencedContracts] takes the interfaces, which
// include the anonymous ones that have no [types.TypeName] to be found by name.
func typesIn(root types.Type) iter.Seq[types.Type] {
	return func(yield func(types.Type) bool) {
		seen := map[types.Type]bool{}

		var walk func(types.Type) bool
		walk = func(t types.Type) bool {
			if t == nil || seen[t] {
				return true
			}
			seen[t] = true
			if !yield(t) {
				return false
			}
			switch t := t.(type) {
			case *types.Named:
				if args := t.TypeArgs(); args != nil {
					for i := range args.Len() {
						if !walk(args.At(i)) {
							return false
						}
					}
				}
			case *types.Alias:
				return walk(types.Unalias(t))
			case *types.Pointer:
				return walk(t.Elem())
			case *types.Slice:
				return walk(t.Elem())
			case *types.Array:
				return walk(t.Elem())
			case *types.Chan:
				return walk(t.Elem())
			case *types.Map:
				return walk(t.Key()) && walk(t.Elem())
			case *types.Signature:
				return walkTuple(t.Params(), walk) && walkTuple(t.Results(), walk)
			case *types.Interface:
				for i := range t.NumEmbeddeds() {
					if !walk(t.EmbeddedType(i)) {
						return false
					}
				}
			case *types.Struct:
				for i := range t.NumFields() {
					if !walk(t.Field(i).Type()) {
						return false
					}
				}
			case *types.Union:
				for i := range t.Len() {
					if !walk(t.Term(i).Type()) {
						return false
					}
				}
			}
			return true
		}
		walk(root)
	}
}

// namedTypes collects the named types a type expression mentions.
func namedTypes(t types.Type) []*types.TypeName {
	var out []*types.TypeName
	for mentioned := range typesIn(t) {
		switch mentioned := mentioned.(type) {
		case *types.Named:
			out = append(out, mentioned.Obj())
		case *types.Alias:
			out = append(out, mentioned.Obj())
		}
	}
	return out
}

// walkTuple applies walk to every type in a tuple, stopping early if walk does.
func walkTuple(tuple *types.Tuple, walk func(types.Type) bool) bool {
	if tuple == nil {
		return true
	}
	for i := range tuple.Len() {
		if !walk(tuple.At(i).Type()) {
			return false
		}
	}
	return true
}
