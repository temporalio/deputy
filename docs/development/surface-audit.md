# Auditing the internal API surface

Deputy keeps almost everything under `internal/`, which bounds the surface to
this module but does not stop it from growing. `internal/surface` measures that
surface with `go/types`, so what it reports is what the compiler sees rather
than what a text search guesses.

## Running it

```bash
# Summary of all four checks
go run ./internal/surface/cmd

# Per-symbol detail before unexporting anything in a package
go run ./internal/surface/cmd -pkg vulnerability/weakness/cwe

# Dump the report for filtering with jq
go run ./internal/surface/cmd -json

# Rewrite the unreachable-package baseline after wiring up or deleting a package
go run ./internal/surface/cmd -baseline
```

`-json` dumps the in-process `surface.Report` keyed by Go field name. It is a reading aid, not an interface: nothing versions it, and renaming a field renames a key. That is deliberate rather than an oversight. Deputy defines its cross-surface output in proto because those consumers are versioned separately from the producer, and this one is not: the only readers are this repository's developers, running the tool from the same commit it lives in. The output that is pinned is the text baseline (`internal/surface/testdata/unreachable.txt`), which a test compares against. If something ever needs to consume the audit rather than read it (a CI gate that fails on a count, another tool ingesting findings), that consumer is what makes this a contract, and the contract belongs in proto with everything else.

## What it checks

**1. Packages no other package imports.** A package with no importers can still
be exercised by its own tests, so its code genuinely is used, by its own test,
and an unused-symbol analyzer is right not to flag it. Test-only reachability is
invisible to dead-code analysis, which is why this check exists separately. The
result is pinned by a baseline (`internal/surface/testdata/unreachable.txt`) and
a test: a newly orphaned package fails CI, and a package that gains an importer
fails until the baseline shrinks.

**2. Exported symbols nothing outside the declaring package references.** Each
finding is graded by how far its references travel:

| Reach | Meaning |
|-------|---------|
| `unreferenced` | Nothing outside the package names it. Unexporting is mechanical. |
| `own-test-only` | Only the package's own `_test` package names it. Unexporting means moving that test in-package first. |
| `foreign-test-only` | Only other packages' test files name it. The export exists for tests alone. |

A reference from a test file in another package counts as a reference; a
reference from the declaring package's own in-package test does not, because it
sits inside the boundary an unexport would draw.

**3. Exported interfaces nothing accepts as a parameter and nothing holds as a
field.** An interface no signature mentions is not an abstraction any caller was
written against. Findings list the positions the interface does appear in
(result, var, assertion, embedded, constraint), so the reason is visible: a
compile-time assertion such as `var _ Expirable = (*TokenCredential)(nil)` is
not a dependency.

**4. Dynamic reachability.** Reflection, encoding, interface dispatch, protobuf
registration, and lookup by name all reach code that looks unreferenced. The
audit does not guess: findings carry the reasons they might be wrong, and each
reason names its own evidence.

- **Dispatch.** A method whose receiver satisfies an interface can be called
  without the call site naming it. Contracts are derived from the module's own
  type graph: any interface mentioned by the type of anything the module declares
  or references, named or anonymous, including a generic type parameter's
  constraint. A short floor list adds the classic standard-library contracts a
  type can satisfy by signature alone while nothing here mentions the interface,
  such as `database/sql.Scanner` on a value handed to a driver. Membership is
  always checked with `types.Implements`, never by method name: `Read()` with no
  arguments does not implement `io.Reader`, and `ProtoReflect() string` is not a
  protobuf message.
- **Lookup by name.** The audit tokenizes Go string literals and the repository's
  executable assets (CEL policies, templates, configuration, fixtures) and
  reports which one named the symbol. Documentation is deliberately not scanned:
  prose that mentions a symbol does not execute it, and treating docs as evidence
  would attach a doubt to everything well documented.
- **Encoding.** A type with encoding-tagged fields is normally built by a decoder
  rather than by a caller naming it. Tags are read with `reflect.StructTag`, so a
  key that merely ends in a codec name (`notjson:"..."`) earns nothing.

A finding with no such reason is one you can act on mechanically.

A blank import is deliberately *not* one of these reasons. It proves the package
is reached, so the package is not an unreachable-package finding, but it says
nothing about the package's exports: the registration it triggers runs in that
package's own `init`, and nobody who blank-imports a package can name an export
at all. Treating it as a doubt argued for keeping precisely the identifiers that
were safest to unexport.

## What the run did not look at

The report ends with a caveat listing every path the run skipped and why: files
this platform's build constraints excluded from the load, and assets too large or
too unreadable to tokenize. Each entry bounds every finding above it, because
evidence that was never read cannot contradict one. A skipped 4 MiB policy file
could be the only place a reflectively consumed symbol is named.

The audit is allowed to be bounded. It is not allowed to present bounded results
as exhaustive, which is why the limits report themselves instead of applying
quietly.

## Interpreting a finding

Findings are evidence, not instructions. Some exports exist for reasons the type
checker cannot see, and the tool says so rather than asserting. The reliable
part is the negative: if the audit finds no reference and no reason to doubt one,
the compiler will confirm it the moment you unexport the symbol.

Unexporting is worth doing beyond tidiness: an unused exported symbol is
invisible to `staticcheck -checks=U1000`, because an export is assumed to have
callers elsewhere. Unexporting it makes any remaining deadness visible to
ordinary linting.

## Scope

Findings are reported for `internal/` only. Generated code, `examples/`, and the
public `sdk/` are excluded, since the SDK's exports serve consumers outside this
module. Excluded trees still count as usage: a symbol the SDK references is
referenced.
