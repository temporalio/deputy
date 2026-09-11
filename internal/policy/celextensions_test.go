package policy

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"slices"
	"strconv"
	"strings"
	"testing"

	"github.com/google/cel-go/cel"
	celenv "github.com/google/cel-go/common/env"
	"github.com/google/cel-go/ext"
)

// celLatestVersion is the version cel-go assumes when a library is enabled
// without a version option, which is what these tests compare the pins against.
const celLatestVersion = uint32(math.MaxUint32)

// optionalLibrary is the singleton name of cel-go's optional type library. It
// lives in the cel package rather than the ext package, so cel-go's own
// extension config plumbing special-cases it and so do these tests.
const optionalLibrary = "cel.lib.optional"

// TestCELExtensionsMatchLibraryNames checks that every pin names a library
// cel-go actually registers, so a typo in celExtensions cannot leave an entry
// that no other test can match back to the environment.
func TestCELExtensionsMatchLibraryNames(t *testing.T) {
	for _, extension := range celExtensions {
		t.Run(extension.library, func(t *testing.T) {
			env, err := cel.NewCustomEnv(append(celExtensionScaffold(extension), extension.enable(extension.version))...)
			if err != nil {
				t.Fatalf("build env for %s: %v", extension.library, err)
			}
			if !env.HasLibrary(extension.library) {
				t.Fatalf("library %q is not registered by its own enable func; env registered %v",
					extension.library, slices.Sorted(slices.Values(env.Libraries())))
			}
		})
	}
}

// TestCELExtensionsArePinned checks that every versioned cel-go library the
// policy environment enables is pinned through celExtensions, and that every
// pin is actually reached. The enabled set is read back from the environment
// and the "does cel-go version this library" question is answered by cel-go's
// own extension registry, so a library enabled outside the table fails this
// test without anyone having to extend a list of extensions here.
//
// This works on library names, which is all cel-go reports about a registered
// library, so it catches a library that is not pinned at all. Re-registering a
// library the table already pins is invisible here and is caught by
// TestCELExtensionsBuiltInOnePlace instead.
func TestCELExtensionsArePinned(t *testing.T) {
	env, err := envWithNames(nil)
	if err != nil {
		t.Fatalf("envWithNames() error = %v", err)
	}

	pinned := make(map[string]bool, len(celExtensions))
	for _, extension := range celExtensions {
		pinned[extension.library] = true
	}

	enabled := make(map[string]bool)
	for _, library := range env.Libraries() {
		enabled[library] = true
		if !celVersionedLibrary(library) {
			// cel-go offers no version knob for this library, so there is
			// nothing to pin. The standard library is the usual case.
			continue
		}
		if !pinned[library] {
			t.Errorf("cel-go library %q is enabled in the policy environment but not pinned in celExtensions; "+
				"enable it through celExtensions at an explicit version so a cel-go upgrade cannot change what shipped policies mean",
				library)
		}
	}

	for _, extension := range celExtensions {
		if !enabled[extension.library] {
			t.Errorf("celExtensions pins %q but the policy environment does not enable it; "+
				"envWithNames must apply celExtensionOptions", extension.library)
		}
	}
}

// TestCELExtensionVersionsAreApplied checks that each pin reaches cel-go rather
// than being decoration: a library built at version 0 must expose a smaller
// surface than the same library built at its pinned version. Libraries pinned
// at 0 are exempt, since there is no lower version to differ from.
func TestCELExtensionVersionsAreApplied(t *testing.T) {
	for _, extension := range celExtensions {
		t.Run(extension.library, func(t *testing.T) {
			if extension.version == 0 {
				t.Skipf("%s is pinned at version 0, its first version, so there is no lower version to compare against",
					extension.library)
			}
			first := measureCELLibrary(t, extension, 0)
			pinned := measureCELLibrary(t, extension, extension.version)
			if first.equal(pinned) {
				t.Fatalf("%s exposes the same surface at version 0 and at pinned version %d, "+
					"so the version argument is not reaching cel-go and the library is effectively unpinned",
					extension.library, extension.version)
			}
		})
	}
}

// TestCELExtensionVersionsAreCurrent compares each pin against the surface the
// linked cel-go release exposes when the same library is enabled unpinned.
// Equality is the evidence that the pinned numbers are the versions today's
// policies were written against. A failure means cel-go moved past the pin,
// which is a semantics change to review and adopt deliberately instead of
// inheriting it from a dependency bump.
//
// Limit: this compares what an environment observably gains from the library
// (declarations, macros, validator names, cost and program option counts). A
// cel-go version that only swaps an implementation behind an unchanged
// declaration, as the strings library did when it rewrote format at version 4,
// is invisible here. The pin still holds the old behavior in that case; only
// the notice that a newer version exists is best effort.
func TestCELExtensionVersionsAreCurrent(t *testing.T) {
	for _, extension := range celExtensions {
		t.Run(extension.library, func(t *testing.T) {
			pinned := measureCELLibrary(t, extension, extension.version)
			latest := measureCELLibrary(t, extension, celLatestVersion)
			if pinned.equal(latest) {
				return
			}
			t.Fatalf("%s is pinned at version %d but the linked cel-go release exposes a different surface unpinned; "+
				"review what changed, then raise the pin in celExtensions as a deliberate change\n%s",
				extension.library, extension.version, pinned.describeDifference(latest))
		})
	}
}

// celVersionedLibrary reports whether cel-go exposes a version option for the
// named library. It asks cel-go's extension registry rather than keeping a copy
// of the extension list here, so a library added upstream is classified without
// any change to this test.
func celVersionedLibrary(library string) bool {
	if library == optionalLibrary {
		// cel.OptionalTypes takes cel.OptionalTypesVersion but is not part of
		// the ext registry, exactly as cel-go's own config loader treats it.
		return true
	}
	_, versioned := ext.ExtensionOptionFactory(celenv.NewExtension(library, celLatestVersion))
	return versioned
}

// celExtensionScaffold returns the options an extension needs before it can be
// registered on its own. cel-go rejects the regex library unless the optional
// library is enabled, so the optional library scaffolds every other extension.
// Whatever the scaffold contributes is subtracted from every measurement, so
// the version it runs at does not matter.
func celExtensionScaffold(extension celExtension) []cel.EnvOption {
	if extension.library == optionalLibrary {
		return nil
	}
	return []cel.EnvOption{cel.OptionalTypes()}
}

// celLibrarySurface is everything an environment observably gains from enabling
// one cel-go library at one version. Declarations alone are not enough: some
// versions add only cost support (the strings library at version 5, the lists
// library at version 3), which shows up as registered cost and program options.
type celLibrarySurface struct {
	// declarations lists the function overload signatures, macros, and AST
	// validator names the library contributes.
	declarations []string

	// costOptions counts the cost estimators the library registers.
	costOptions int

	// programOptions counts the program options the library registers, which is
	// how cost trackers and planners reach evaluation.
	programOptions int
}

// equal reports whether two library surfaces are indistinguishable.
func (s celLibrarySurface) equal(other celLibrarySurface) bool {
	return s.costOptions == other.costOptions &&
		s.programOptions == other.programOptions &&
		slices.Equal(s.declarations, other.declarations)
}

// describeDifference reports how other differs from s, for test failure output.
func (s celLibrarySurface) describeDifference(other celLibrarySurface) string {
	var lines []string
	if s.costOptions != other.costOptions || s.programOptions != other.programOptions {
		lines = append(lines, fmt.Sprintf("  option counts: costOptions %d -> %d, programOptions %d -> %d",
			s.costOptions, other.costOptions, s.programOptions, other.programOptions))
	}
	for _, declaration := range celMissingDeclarations(other.declarations, s.declarations) {
		lines = append(lines, "  added: "+declaration)
	}
	for _, declaration := range celMissingDeclarations(s.declarations, other.declarations) {
		lines = append(lines, "  dropped: "+declaration)
	}
	return strings.Join(lines, "\n")
}

// measureCELLibrary measures what an extension contributes at the given
// version. The measurement of an environment built without the extension is
// subtracted, so the result describes only the library under test.
func measureCELLibrary(t *testing.T, extension celExtension, version uint32) celLibrarySurface {
	t.Helper()

	scaffold := celExtensionScaffold(extension)
	baseline := measureCELEnv(t, scaffold...)
	withExtension := measureCELEnv(t, append(scaffold, extension.enable(version))...)

	return celLibrarySurface{
		declarations:   celMissingDeclarations(withExtension.declarations, baseline.declarations),
		costOptions:    withExtension.costOptions - baseline.costOptions,
		programOptions: withExtension.programOptions - baseline.programOptions,
	}
}

// measureCELEnv measures an environment built from the given options.
func measureCELEnv(t *testing.T, opts ...cel.EnvOption) celLibrarySurface {
	t.Helper()

	env, err := cel.NewCustomEnv(opts...)
	if err != nil {
		t.Fatalf("build custom env: %v", err)
	}

	var declarations []string
	for name, fn := range env.Functions() {
		for _, overload := range fn.OverloadDecls() {
			args := make([]string, 0, len(overload.ArgTypes()))
			for _, arg := range overload.ArgTypes() {
				args = append(args, arg.String())
			}
			declarations = append(declarations, fmt.Sprintf("func %s/%s(%s) -> %s",
				name, overload.ID(), strings.Join(args, ", "), overload.ResultType()))
		}
	}
	for _, macro := range env.Macros() {
		declarations = append(declarations, "macro "+macro.MacroKey())
	}
	for _, validator := range env.Validators() {
		declarations = append(declarations, "validator "+validator.Name())
	}
	slices.Sort(declarations)

	return celLibrarySurface{
		declarations:   slices.Compact(declarations),
		costOptions:    celEnvFieldLen(t, env, "costOptions"),
		programOptions: celEnvFieldLen(t, env, "progOpts"),
	}
}

// celEnvFieldLen returns the length of an unexported slice field of cel.Env.
// cel-go exposes no accessor for the cost estimators and program options a
// library registers, and those are the only evidence that a version which adds
// cost support was applied, so the test reads the fields reflectively. A rename
// upstream fails loudly here rather than quietly dropping the comparison.
func celEnvFieldLen(t *testing.T, env *cel.Env, field string) int {
	t.Helper()

	value := reflect.ValueOf(env).Elem().FieldByName(field)
	if !value.IsValid() || value.Kind() != reflect.Slice {
		t.Fatalf("cel.Env no longer has a slice field %q; find the current name so version comparisons keep covering cost and program options", field)
	}
	return value.Len()
}

// celMissingDeclarations returns the declarations in have that are absent from
// want, preserving sort order.
func celMissingDeclarations(have, want []string) []string {
	missing := make([]string, 0, len(have))
	for _, declaration := range have {
		if !slices.Contains(want, declaration) {
			missing = append(missing, declaration)
		}
	}
	return missing
}

// TestCELExtensionFunctionsEvaluate evaluates one expression per pinned
// library, from the version that introduced the newest functions the pin
// admits. The surface comparisons above work on declarations, so this is what
// catches a pin that declares a function the runtime cannot execute, and it
// fails readably if a pin is ever lowered under the language Deputy documents.
func TestCELExtensionFunctionsEvaluate(t *testing.T) {
	tests := []struct {
		name string
		expr string
	}{
		{name: "strings quote", expr: `strings.quote("a") == "\"a\""`},
		{name: "strings join", expr: `["a", "b"].join("-") == "a-b"`},
		{name: "strings format", expr: `"%d".format([2]) == "2"`},
		{name: "strings reverse", expr: `"ab".reverse() == "ba"`},
		{name: "lists flatten", expr: `[[1], [2]].flatten() == [1, 2]`},
		{name: "lists sort", expr: `[3, 1, 2].sort() == [1, 2, 3]`},
		{name: "lists distinct", expr: `[1, 1, 2].distinct() == [1, 2]`},
		{name: "lists range", expr: `lists.range(3) == [0, 1, 2]`},
		{name: "sets contains", expr: `sets.contains([1, 2], [1])`},
		{name: "regex extract", expr: `regex.extract("id:1", "id:(\\d+)") == optional.of("1")`},
		{name: "bindings bind", expr: `cel.bind(x, 2, x + 1) == 3`},
		{name: "encoders base64", expr: `base64.encode(b"hi") == "aGk="`},
		{name: "encoders json", expr: `json.encode(1) == "1"`},
		{name: "math abs", expr: `math.abs(-1) == 1`},
		{name: "math sqrt", expr: `math.sqrt(4.0) == 2.0`},
		{name: "optional access", expr: `{"a": 1}.?a.orValue(0) == 1`},
		{name: "optional first", expr: `[1, 2].first() == optional.of(1)`},
		{name: "optional last", expr: `[1, 2].last() == optional.of(2)`},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			out, err := Evaluate(t.Context(), test.expr, nil)
			if err != nil {
				t.Fatalf("Evaluate(%q) error = %v", test.expr, err)
			}
			if out != true {
				t.Fatalf("Evaluate(%q) = %v, want true", test.expr, out)
			}
		})
	}
}

// celExtensionSourceFile is the only file in this package allowed to construct
// cel-go extension libraries.
const celExtensionSourceFile = "celextensions.go"

// TestCELExtensionsBuiltInOnePlace checks the package source for extension
// libraries constructed outside celExtensions, and for constructor calls there
// that omit a version option.
//
// The surface comparisons cannot see this class of mistake. cel-go registers a
// singleton library once and the first registration wins, so a second, unpinned
// ext.Strings() placed ahead of the table would take over the strings library
// while every library still reports as pinned and, with the pins at latest,
// every measured surface still matches. Reading the source is the only way to
// catch it.
func TestCELExtensionsBuiltInOnePlace(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatalf("read package directory: %v", err)
	}

	fset := token.NewFileSet()
	inspected := 0
	for _, entry := range entries {
		name := entry.Name()
		if entry.IsDir() || !strings.HasSuffix(name, ".go") || strings.HasSuffix(name, "_test.go") {
			continue
		}
		file, err := parser.ParseFile(fset, name, nil, 0)
		if err != nil {
			t.Fatalf("parse %s: %v", name, err)
		}
		extName, celName := celImportNames(file)
		if extName == "" && celName == "" {
			continue
		}
		inspected++
		for _, call := range celLibraryConstructorCalls(file, extName, celName) {
			called := call.Fun.(*ast.SelectorExpr).Sel.Name
			position := fset.Position(call.Pos())
			switch {
			case name != celExtensionSourceFile:
				t.Errorf("%s: %s constructs a cel-go library outside %s; enable it through celExtensions so it carries an explicit version, "+
					"because cel-go keeps only the first registration of a library and an unpinned one here would win",
					position, called, celExtensionSourceFile)
			case !celCallHasVersionArg(call):
				t.Errorf("%s: %s is called without a version option; pass its %sVersion option so a cel-go upgrade cannot change what shipped policies mean",
					position, called, called)
			}
		}
	}
	if inspected == 0 {
		t.Fatal("no package source imported cel-go, so this check inspected nothing")
	}
}

// celImportNames returns the local names the file uses for the cel-go ext and
// cel packages, empty when the file does not import them.
func celImportNames(file *ast.File) (extName, celName string) {
	for _, spec := range file.Imports {
		path, err := strconv.Unquote(spec.Path.Value)
		if err != nil {
			continue
		}
		name := filepath.Base(path)
		if spec.Name != nil {
			name = spec.Name.Name
		}
		switch path {
		case "github.com/google/cel-go/ext":
			extName = name
		case "github.com/google/cel-go/cel":
			celName = name
		}
	}
	return extName, celName
}

// celLibraryConstructorCalls returns the calls in the file that build a
// versioned cel-go library: any call into the ext package other than a version
// option, plus cel.OptionalTypes, which takes a version option of its own even
// though it lives in the cel package.
//
// Arguments of a matched call are not searched again, because the ext package
// also exports helpers that only make sense as arguments to a constructor
// (ext.StringsVersion, but also tuning options such as ext.StringsMaxPrecision
// and ext.ListsMaxRangeSize). Only the outermost call constructs a library.
func celLibraryConstructorCalls(file *ast.File, extName, celName string) []*ast.CallExpr {
	var calls []*ast.CallExpr
	ast.Inspect(file, func(node ast.Node) bool {
		call, isCall := node.(*ast.CallExpr)
		if !isCall {
			return true
		}
		selector, isSelector := call.Fun.(*ast.SelectorExpr)
		if !isSelector {
			return true
		}
		pkg, isIdent := selector.X.(*ast.Ident)
		if !isIdent {
			return true
		}
		switch {
		case extName != "" && pkg.Name == extName && !strings.HasSuffix(selector.Sel.Name, "Version"):
			calls = append(calls, call)
		case celName != "" && pkg.Name == celName && selector.Sel.Name == "OptionalTypes":
			calls = append(calls, call)
		default:
			return true
		}
		return false
	})
	return calls
}

// celCallHasVersionArg reports whether the call passes one of cel-go's version
// options, such as ext.StringsVersion or cel.OptionalTypesVersion.
func celCallHasVersionArg(call *ast.CallExpr) bool {
	for _, arg := range call.Args {
		argCall, isCall := arg.(*ast.CallExpr)
		if !isCall {
			continue
		}
		selector, isSelector := argCall.Fun.(*ast.SelectorExpr)
		if isSelector && strings.HasSuffix(selector.Sel.Name, "Version") {
			return true
		}
	}
	return false
}
