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

# Machine-readable, for filtering with jq
go run ./internal/surface/cmd -json

# Rewrite the unreachable-package baseline after wiring up or deleting a package
go run ./internal/surface/cmd -baseline
```

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
audit does not guess: findings carry the reasons they might be wrong (a name
appearing in a string literal or a template, a method name in some interface's
method set, a protobuf message type, an encoding struct tag, a package imported
only for its side effects). A finding with no such reason is one you can act on
mechanically.

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
