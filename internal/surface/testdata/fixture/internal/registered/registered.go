// Package registered is imported for its side effects only, which is the case
// that shows why a blank import is not a reason to keep an export. The
// registration below happens inside this package, so unexporting BlankImportedOnly would
// not disturb it, and nobody who blank-imports the package can name BlankImportedOnly at
// all.
package registered

func init() { register(&BlankImportedOnly{}) }

var registry []any

func register(v any) { registry = append(registry, v) }

// BlankImportedOnly is exported from a package nothing imports by name.
type BlankImportedOnly struct{}
