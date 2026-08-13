// Package awkward lives at an import path ending in _test, which is legal and is
// not the same thing as being another package's external test package. The audit
// has to tell those apart from the test binary a variant was compiled for, not
// from the shape of the path.
package awkward

// Awkward is reached only by this package's own in-package test, so this package
// is unreachable in the same way internal/orphan is.
func Awkward() int { return 1 }
