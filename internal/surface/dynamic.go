package surface

import (
	"context"
	"fmt"
	"go/ast"
	"go/token"
	"go/types"
	"io/fs"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"unicode"

	"golang.org/x/tools/go/packages"
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
	// tokens maps every identifier-shaped token found in a Go string literal or
	// an executable repository asset (templates, policies, configuration) to a
	// description of where it was found. A symbol whose name appears there may
	// be looked up by name rather than referenced, and naming the source lets a
	// reader judge that in one step: a name in a CEL policy is a reachability
	// path, and a name in a code fence is not.
	//
	// Documentation is deliberately not scanned. Prose that mentions a symbol
	// does not execute it, so treating docs as evidence would attach a doubt to
	// every well documented symbol and make the signal meaningless.
	tokens map[string]string

	// byMethod indexes the dispatch contracts of the whole program by method
	// name, so a method finding is checked only against the interfaces that
	// declare a method by that name.
	byMethod map[string][]contract

	// taggedTypes holds the package-qualified names ("pkg/path.Type") of the
	// package-level types with at least one encoding-tagged field. Such a type is
	// normally built by a decoder rather than by a caller naming it, so a decoder
	// can reach it without any reference.
	//
	// The key carries the package because a bare name is not an identity. A
	// common name such as Run or Stats would otherwise lend this doubt to every
	// object called that, in any package and of any kind, which is evidence the
	// audit does not have.
	//
	// The package is the declaring object's own path, not the variant's canonical
	// path, and the difference matters in one case: canonical folds an external
	// "…_test" package back onto the package it tests, so a tagged type declared
	// in a black-box test file would lend its doubt to an unrelated production
	// type of the same name.
	taggedTypes map[string]bool

	// unexamined records the assets this run did not read. Every one of them is a
	// place a reflectively consumed name could have been, so a finding is only as
	// certain as this list is short. Skipping a file is acceptable and saying
	// nothing about it is not: the audit would present a symbol as safe to
	// unexport while knowing it had passed over the evidence.
	unexamined []Unexamined

	// blankImported holds canonical paths imported for side effects only. This
	// answers check 1 and nothing else: such a package is reached, so it is not an
	// unreachable-package finding.
	//
	// It is deliberately not a doubt about the package's symbols. A blank import
	// runs init, and whatever init registers it registers from inside the package,
	// which is a reference the audit already counts as internal. So being
	// blank-imported is not evidence that an export is needed; it is evidence that
	// nobody outside can name one, since nobody imports the package by name. A
	// doubt here told a reader to keep exactly the identifiers that were safest to
	// unexport.
	blankImported map[string]bool
}

// contract is an interface a method can be reached through. Holding the
// interface itself, and not just its method names, lets the audit verify that
// the receiver actually satisfies it: a type with a String method that does not
// implement [fmt.Stringer] gains nothing from the coincidence.
type contract struct {
	// name is how the contract is described in a doubt, such as "fmt.Stringer".
	name string

	// anonymous marks a contract with no declared type behind it, whose name is
	// the type expression that spelled it out. Such a contract is worth reporting
	// only when no named one says the same thing, which
	// [dynamic.dispatchedThrough] decides.
	anonymous bool

	iface *types.Interface
}

// dispatchContracts is a floor under the derived contracts, not the source of
// them. [dynamic.addReferencedContracts] finds a foreign interface the moment
// any type in the module mentions it, which covers the ordinary case: a method
// returning [log/slog.Handler], a struct field holding an [io.Writer], a call to
// a function that takes one. This list names the classic contracts a type here
// can satisfy by signature alone while no type in the module mentions the
// interface at all, which is how [database/sql.Scanner] gets called by a driver
// reached through a dependency.
//
// A hand-maintained list must stay a floor rather than the mechanism, because a
// missing entry does not merely weaken the audit, it inverts it: the methods
// that contract reaches are then reported as certainly unused, and the tool
// recommends unexporting live code. Widen the derivation before adding a name
// here.
//
// Every name must resolve to an interface in the package it is filed under,
// which [dynamic.addForeignContracts] enforces at run time and
// TestDispatchContractsResolveToInterfaces enforces for the whole list.
var dispatchContracts = map[string][]string{
	"fmt":                 {"Stringer", "GoStringer", "Formatter"},
	"encoding":            {"TextMarshaler", "TextUnmarshaler", "BinaryMarshaler", "BinaryUnmarshaler"},
	"encoding/json":       {"Marshaler", "Unmarshaler"},
	"io":                  {"Reader", "Writer", "Closer", "ReaderAt", "WriterAt", "Seeker", "ReaderFrom", "WriterTo", "StringWriter"},
	"sort":                {"Interface"},
	"net/http":            {"Handler", "RoundTripper", "ResponseWriter", "Flusher"},
	"database/sql":        {"Scanner"},
	"database/sql/driver": {"Valuer"},
	protoreflectPath:      {"ProtoMessage", "Message"},
}

// protoreflectPath is the package declaring the interface that makes a type
// reachable through the protobuf registry. It is written once and used both to
// register the contract above and to look it up in [dynamic.protoLike], so the
// doubt cannot search for a contract the table never adds.
const protoreflectPath = "google.golang.org/protobuf/reflect/protoreflect"

// protoMessageContract is the registered name of protobuf's message contract.
const protoMessageContract = protoreflectPath + ".ProtoMessage"

// encodingTags are the struct tag keys that mean a field is read or written by
// a reflective codec in this module.
var encodingTags = []string{"json", "yaml", "toml", "protobuf", "cel", "xml", "mapstructure", "kong", "env"}

// assetExtensions are the non-Go files that can name a Go symbol in a way that
// reaches it: policy sources, templates, and configuration or fixture data a
// decoder binds to fields. Markdown and other prose are excluded on purpose;
// documentation names symbols without reaching them.
var assetExtensions = map[string]bool{
	".cel":       true,
	".tmpl":      true,
	".gotmpl":    true,
	".yaml":      true,
	".yml":       true,
	".json":      true,
	".toml":      true,
	".textproto": true,
}

// newDynamic gathers the dynamic-reachability evidence for the whole module. It
// fails if the dispatch contract list does not resolve: missing evidence makes
// findings look more certain than they are, so an audit that cannot gather it is
// not one to report. It fails the same way when ctx is canceled, since the
// caller asked for no report at all.
func newDynamic(ctx context.Context, p *program, roots []*packages.Package) (*dynamic, error) {
	d := &dynamic{
		tokens:        map[string]string{},
		byMethod:      map[string][]contract{},
		taggedTypes:   map[string]bool{},
		blankImported: map[string]bool{},
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
						d.addTokens(s, "a Go string literal")
					}
				}
			case *ast.TypeSpec:
				d.addTaggedTypes(v, node)
			}
			return true
		})
		return true
	})

	for _, v := range p.variants() {
		d.addDeclaredInterfaces(v.pkg)
	}
	d.addReferencedContracts(p)
	if err := d.addForeignContracts(roots, dispatchContracts); err != nil {
		return nil, err
	}
	if err := d.addAssets(ctx, p.root); err != nil {
		return nil, err
	}
	return d, nil
}

// addContract indexes one dispatch contract under each of its method names.
func (d *dynamic) addContract(name string, iface *types.Interface) {
	d.addNamedContract(name, iface, false)
}

// addNamedContract indexes a contract, recording whether its name is a type
// expression rather than a declared type's name.
func (d *dynamic) addNamedContract(name string, iface *types.Interface, anonymous bool) {
	if iface == nil || iface.NumMethods() == 0 {
		return
	}
	c := contract{name: name, anonymous: anonymous, iface: iface}
	for i := range iface.NumMethods() {
		method := iface.Method(i).Name()
		if !slices.ContainsFunc(d.byMethod[method], func(have contract) bool { return have.name == c.name }) {
			d.byMethod[method] = append(d.byMethod[method], c)
		}
	}
}

// addDeclaredInterfaces indexes the interfaces a package declares. A method
// whose receiver satisfies one of them can be called through it without the
// call site naming the method's own type.
func (d *dynamic) addDeclaredInterfaces(pkg *packages.Package) {
	scope := pkg.Types.Scope()
	for _, name := range scope.Names() {
		tn, ok := scope.Lookup(name).(*types.TypeName)
		if !ok {
			continue
		}
		if iface, ok := tn.Type().Underlying().(*types.Interface); ok {
			d.addContract(pkg.PkgPath+"."+name, iface)
		}
	}
}

// addReferencedContracts derives the dispatch contracts of foreign packages from
// the module's own type graph: every interface mentioned by the type of anything
// the module declares or references, named or anonymous.
//
// This is what keeps the audit from depending on a hand-maintained list of
// interfaces. A [log/slog.Handler] implementation is the case that motivated it:
// its Handle, WithAttrs and WithGroup are called by slog, so nothing in the
// module references them, and without the contract the audit reported four live
// methods as certainly unexportable. Nothing about slog made it special. Any
// interface a foreign package dispatches through would have gone the same way
// until someone noticed a wrong recommendation.
//
// Mentioning the interface is the signal because that is what puts a value of an
// implementing type somewhere a foreign package can dispatch on it. Declaring a
// method that returns slog.Handler, holding one in a field, or calling
// slog.New all mention it, and any of the three is enough for the handler to
// leave this module as an interface value.
//
// [types.Info.Defs] carries the module's own declarations, so a signature or
// field type reaches this even when nothing calls it; [types.Info.Uses] carries
// everything the module names, so a foreign function's parameters and a foreign
// struct's fields arrive through the objects the module refers to. Objects and
// types are both deduplicated, because a package's popular function appears in
// Uses once per call site.
//
// The doubt is still earned by [types.Implements] in [dynamic.dispatchedThrough]
// rather than by method name, so widening the contract set cannot make a method
// carry a doubt it does not satisfy.
func (d *dynamic) addReferencedContracts(p *program) {
	seenObj := map[types.Object]bool{}
	seenType := map[types.Type]bool{}
	register := func(root types.Type) {
		if root == nil {
			return
		}
		for mentioned := range typesIn(root) {
			switch mentioned := mentioned.(type) {
			case *types.Named:
				tn := mentioned.Obj()
				if tn.Pkg() == nil {
					continue
				}
				if iface, ok := mentioned.Underlying().(*types.Interface); ok {
					d.addContract(tn.Pkg().Path()+"."+tn.Name(), iface)
				}
			case *types.Interface:
				// An anonymous interface, spelled out in the signature or field
				// that uses it. Only these reach this branch, since typesIn does
				// not open a named type, and they are the contracts no lookup by
				// name could ever find: there is no TypeName to look up. A
				// parameter declared as interface{ Run() } dispatches to the Run
				// of whatever is passed, so the doubt is named by the type
				// expression itself.
				d.addNamedContract(types.TypeString(mentioned, nil), mentioned, true)
			}
		}
	}
	consider := func(obj types.Object) {
		if obj == nil || seenObj[obj] {
			return
		}
		seenObj[obj] = true
		t := obj.Type()
		if t == nil || seenType[t] {
			return
		}
		seenType[t] = true
		register(t)
		for _, constraint := range constraintsOf(t) {
			register(constraint)
		}
	}
	for _, v := range p.variants() {
		for _, obj := range v.pkg.TypesInfo.Defs {
			consider(obj)
		}
		for _, obj := range v.pkg.TypesInfo.Uses {
			consider(obj)
		}
	}
}

// constraintsOf returns the constraints on a generic declaration's type
// parameters. A constraint is a dispatch contract: calling F[T interface{ Run()
// }] with an internal type lets F reach that type's Run with nothing in this
// module naming the method, exactly as passing it to a parameter of interface
// type would.
//
// Constraints are collected here rather than inside [typesIn] because they are
// not part of the structure of a value's type. Folding them into that walk makes
// [namedTypes] report a constraint from every parameter declared as a type
// parameter, which the interface check would then read as an interface something
// accepts, erasing the distinction roleConstraint exists to draw.
func constraintsOf(t types.Type) []types.Type {
	var params *types.TypeParamList
	switch t := t.(type) {
	case *types.Signature:
		params = t.TypeParams()
	case *types.Named:
		params = t.TypeParams()
	}
	if params == nil {
		return nil
	}
	out := make([]types.Type, 0, params.Len())
	for i := range params.Len() {
		out = append(out, params.At(i).Constraint())
	}
	return out
}

// addForeignContracts indexes the interfaces from table that the load graph
// contains, plus the builtin error interface. Without these, a method reached
// only by the standard library (Marshaler dispatched from json.Marshal, Stringer
// from fmt) looks unreferenced with nothing to doubt.
//
// A name the table files under the wrong package is an error rather than a skip.
// Skipping it costs a whole dispatch contract, and the methods that contract
// reaches are then reported as certainly unused: the audit would invent evidence
// of deadness, which is worse than not running. A package the load graph does
// not contain is not an error, because the table names contracts a module may or
// may not depend on.
func (d *dynamic) addForeignContracts(roots []*packages.Package, table map[string][]string) error {
	if errType, ok := types.Universe.Lookup("error").Type().Underlying().(*types.Interface); ok {
		d.addContract("error", errType)
	}
	var unresolved []string
	packages.Visit(roots, nil, func(pkg *packages.Package) {
		names, wanted := table[pkg.PkgPath]
		if !wanted || pkg.Types == nil {
			// A wanted package with no type information would hide its contracts
			// as surely as a wrong name does. [Analyze] has already refused any
			// graph with load errors by this point, so reaching that state means
			// the load mode stopped asking for types, not that a lookup failed.
			return
		}
		for _, name := range names {
			qualified := pkg.PkgPath + "." + name
			obj := pkg.Types.Scope().Lookup(name)
			if obj == nil {
				unresolved = append(unresolved, qualified+" does not exist")
				continue
			}
			iface, ok := obj.Type().Underlying().(*types.Interface)
			if !ok {
				unresolved = append(unresolved, fmt.Sprintf("%s is %s, not an interface", qualified, obj.Type().Underlying()))
				continue
			}
			d.addContract(qualified, iface)
		}
	})
	if len(unresolved) > 0 {
		slices.Sort(unresolved)
		return fmt.Errorf("dispatch contracts do not resolve: %s", strings.Join(unresolved, "; "))
	}
	return nil
}

// dispatchedThrough returns the contracts a method can be reached through: those
// declaring a method of the same name that the receiver's type actually
// satisfies.
func (d *dynamic) dispatchedThrough(fn *types.Func) []string {
	candidates := d.byMethod[fn.Name()]
	if len(candidates) == 0 {
		return nil
	}
	sig, ok := fn.Type().(*types.Signature)
	if !ok || sig.Recv() == nil {
		return nil
	}
	recv := sig.Recv().Type()
	forms := []types.Type{recv}
	if _, isPtr := recv.(*types.Pointer); !isPtr {
		forms = append(forms, types.NewPointer(recv))
	}

	var matched []contract
	for _, c := range candidates {
		for _, form := range forms {
			if types.Implements(form, c.iface) {
				matched = append(matched, c)
				break
			}
		}
	}

	var out []string
	for _, c := range matched {
		// An anonymous contract identical to a named one in the same match is the
		// same fact spelled twice: "interface{String() string}" beside
		// "fmt.Stringer" lengthens the doubt without telling a reader anything, and
		// identical interfaces cannot differ in who implements them. Named contracts
		// are always kept, so the reason is never lost, only its duplicate.
		if c.anonymous && slices.ContainsFunc(matched, func(other contract) bool {
			return !other.anonymous && types.Identical(c.iface, other.iface)
		}) {
			continue
		}
		out = append(out, c.name)
	}
	slices.Sort(out)
	return slices.Compact(out)
}

// addTokens splits text into identifier-shaped tokens, recording source as
// where they came from. Splitting beats substring matching: it will not let
// "Expirable" match inside "NotExpirableAtAll", and it costs one pass.
//
// The first source to claim a token wins, so the description stays stable
// regardless of walk order.
func (d *dynamic) addTokens(text, source string) {
	add := func(tok string) {
		if _, seen := d.tokens[tok]; !seen {
			d.tokens[tok] = source
		}
	}
	start := -1
	for i, r := range text {
		if isIdentRune(r) {
			if start < 0 {
				start = i
			}
			continue
		}
		if start >= 0 {
			add(text[start:i])
			start = -1
		}
	}
	if start >= 0 {
		add(text[start:])
	}
}

// isIdentRune reports whether r can appear in a Go identifier.
func isIdentRune(r rune) bool {
	return r == '_' || unicode.IsLetter(r) || unicode.IsDigit(r)
}

// addTaggedTypes records the package-level named type declared by spec when its
// struct body carries an encoding tag. The type, not the field, is what the
// doubt is about: a decoder constructs the whole value, and struct fields are
// outside the audited surface anyway. Keying on the field name instead would
// attach a doubt to any unrelated symbol that happened to share a field's name.
//
// The record is package-qualified, and a type declared inside a function body is
// skipped. Such a type is nobody's surface and can never be the subject of a
// finding, so recording it could only lend its doubt to a package-level name it
// happens to collide with.
func (d *dynamic) addTaggedTypes(v *variant, spec *ast.TypeSpec) {
	st, ok := spec.Type.(*ast.StructType)
	if !ok {
		return
	}
	obj := v.pkg.TypesInfo.Defs[spec.Name]
	if obj == nil || obj.Pkg() == nil || obj.Parent() != v.pkg.Types.Scope() {
		return
	}
	for _, field := range st.Fields.List {
		if field.Tag == nil {
			continue
		}
		tag, err := strconv.Unquote(field.Tag.Value)
		if err != nil {
			continue
		}
		if hasEncodingTag(tag) {
			d.taggedTypes[obj.Pkg().Path()+"."+obj.Name()] = true
			return
		}
	}
}

// hasEncodingTag reports whether a struct tag names a reflective codec.
//
// The tag is parsed with [reflect.StructTag], the same reader every codec in this
// module uses, rather than searched for a substring. Substring matching cannot
// tell a key from the end of a longer key: a field tagged `notjson:"value"`
// contains `json:"` and would have lent its type an encoding doubt no decoder
// justifies, which makes a finding read as uncertain forever with nothing behind
// it.
func hasEncodingTag(tag string) bool {
	st := reflect.StructTag(tag)
	for _, key := range encodingTags {
		if _, ok := st.Lookup(key); ok {
			return true
		}
	}
	return false
}

// addAssets tokenizes the repository's executable non-Go files, so a field
// named only in a template, a CEL policy, or fixture data is not reported as
// unreferenced. Dot-prefixed and vendored trees are skipped; testdata is not,
// because fixtures do name the fields a decoder binds.
//
// This is the audit's one unbounded filesystem phase, and it runs after the
// package load, so it is where a Ctrl-C lands on a large repository. The walk
// therefore checks ctx on every entry and returns the cancellation, which fails
// the audit rather than letting a report print for a run the user stopped. The
// check comes before the tolerance for unreadable entries below, so an
// unreadable tree cannot swallow a cancellation.
//
// Every other way of not reading something is recorded rather than tolerated. A
// directory the walk cannot enter is the largest of them, because it costs the
// whole subtree and not one file, and it is the case where continuing quietly
// would let the report claim a coverage it does not have.
func (d *dynamic) addAssets(ctx context.Context, root string) error {
	if root == "" {
		return nil
	}
	walkErr := filepath.WalkDir(root, func(path string, entry fs.DirEntry, err error) error {
		if ctxErr := ctx.Err(); ctxErr != nil {
			return ctxErr
		}
		if err != nil {
			// WalkDir does not descend into a directory it could not read, so
			// nothing under this path was scanned. Keep walking the rest of the
			// tree, but on the record.
			d.skipAsset(path, root, fmt.Sprintf("could not be walked (%v), so nothing under it was scanned for names", err))
			return nil //nolint:nilerr // recorded above; one unreadable tree must not end the scan
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
		if statErr != nil {
			d.skipAsset(path, root, fmt.Sprintf("could not be measured (%v), so the names it contains were not collected", statErr))
			return nil
		}
		if info.Size() > maxAssetBytes {
			d.skipAsset(path, root, fmt.Sprintf("is %d bytes, over the %d byte asset limit, so the names it contains were not collected", info.Size(), maxAssetBytes))
			return nil
		}
		data, readErr := os.ReadFile(path)
		if readErr != nil {
			d.skipAsset(path, root, fmt.Sprintf("could not be read (%v), so the names it contains were not collected", readErr))
			return nil
		}
		d.addTokens(string(data), filepath.ToSlash(trimRoot(path, root)))
		return nil
	})
	if walkErr != nil {
		return fmt.Errorf("scan assets under %s: %w", root, walkErr)
	}
	return nil
}

// maxAssetBytes caps the asset files scanned for identifier tokens, so a large
// generated fixture cannot dominate the audit's runtime. Exceeding it is recorded
// rather than ignored, because the limit is a bound on the audit's evidence and a
// reader cannot weigh a finding without knowing one applied.
const maxAssetBytes = 4 << 20

// skipAsset records that an asset was not read. The path is made relative to the
// module root so the caveat reads the same way finding positions do.
func (d *dynamic) skipAsset(path, root, reason string) {
	d.unexamined = append(d.unexamined, Unexamined{
		Path:   filepath.ToSlash(trimRoot(path, root)),
		Reason: reason,
	})
}

// symbolDoubts returns the reasons a symbol finding might be wrong.
func (d *dynamic) symbolDoubts(obj types.Object, kind SymbolKind, pkgPath string) []string {
	var doubts []string
	if fn, ok := obj.(*types.Func); ok && kind == KindMethod {
		if through := d.dispatchedThrough(fn); len(through) > 0 {
			doubts = append(doubts, "receiver satisfies "+strings.Join(through, ", ")+", so calls reach this method through dispatch")
		}
	}
	if src, ok := d.tokens[obj.Name()]; ok {
		doubts = append(doubts, "name appears in "+src+", so it may be looked up by name")
	}
	if tn, ok := obj.(*types.TypeName); ok {
		if d.protoLike(tn) {
			doubts = append(doubts, "type is a protobuf message, reachable through the proto registry")
		}
		if d.taggedType(tn) {
			doubts = append(doubts, "type has encoding-tagged fields, so a codec may construct it reflectively")
		}
	}
	return doubts
}

// taggedType reports whether tn is a type recorded as carrying encoding tags.
// The lookup is package-qualified for the same reason the record is: the doubt
// describes one type, not every object that shares its name.
func (d *dynamic) taggedType(tn *types.TypeName) bool {
	if tn.Pkg() == nil {
		return false
	}
	return d.taggedTypes[tn.Pkg().Path()+"."+tn.Name()]
}

// protoLike reports whether a type implements protoreflect's message contract,
// which makes it reachable through the protobuf registry regardless of what
// references it.
//
// Membership is decided by [types.Implements] against the registered contract,
// not by finding a method called ProtoReflect. A type declaring ProtoReflect()
// string satisfies nothing and is not in any registry, and labelling it a
// protobuf message invents the evidence, which is the same mistake this file
// refuses to make for [fmt.Stringer] and every other contract.
//
// A module that does not depend on protobuf has no such contract registered and
// gets false, which is the right answer: with no protobuf in the graph there is
// no registry to be reachable through.
func (d *dynamic) protoLike(tn *types.TypeName) bool {
	forms := []types.Type{tn.Type(), types.NewPointer(tn.Type())}
	for _, c := range d.byMethod["ProtoReflect"] {
		if c.name != protoMessageContract {
			continue
		}
		for _, form := range forms {
			if types.Implements(form, c.iface) {
				return true
			}
		}
	}
	return false
}

// interfaceDoubts returns the reasons an interface finding might be wrong.
func (d *dynamic) interfaceDoubts(obj types.Object) []string {
	var doubts []string
	if src, ok := d.tokens[obj.Name()]; ok {
		doubts = append(doubts, "name appears in "+src)
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
