package ifaces

// Accepted is taken as a parameter, so it is a dependency and not a finding.
type Accepted interface{ A() }

// Held is held as a struct field, so it is not a finding either.
type Held interface{ H() }

// Behind is only ever mentioned inside a slice in a parameter list, which
// still counts as being accepted.
type Behind interface{ B() }

// Returned is only ever a result type: nothing is written against it.
type Returned interface{ R() }

// Bare is only ever a type assertion target.
type Bare interface{ Ba() }

// SelfAccepting is accepted only by its own method, which is not a caller
// depending on the abstraction.
type SelfAccepting interface{ Merge(SelfAccepting) }

type holder struct {
	field Held
}

// Run accepts Accepted and Behind.
func Run(a Accepted, b []Behind) *holder { return &holder{} }

// Make returns Returned.
func Make() Returned { return nil }

func assert(v any) bool {
	_, ok := v.(Bare)
	return ok
}

var _ = assert
