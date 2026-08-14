// Package initonly declares nothing in package scope: go/types puts neither an
// init function nor a blank-named declaration there. It is still the kind of
// orphan that matters most, because its whole purpose is to run and nothing
// imports it, so it never does.
package initonly

func init() {}
