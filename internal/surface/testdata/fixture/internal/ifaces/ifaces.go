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

// Shared has the name of an encoding-tagged type in another package and no tags
// of its own, so nothing reflective can reach it and it carries no doubt.
type Shared struct {
	Name string
}

type holder struct {
	field Held
}

// Run accepts Accepted and Behind.
func Run(a Accepted, b []Behind) *holder { return &holder{} }

// Make returns Returned.
func Make() Returned { return nil }

// RunAnon accepts an anonymous interface, which is the one dispatch contract no
// lookup by name can find: there is no declared type to file it under. It stands
// in for a foreign API declared the same way, since the audit reads such a
// signature out of the type graph either way.
func RunAnon(v interface{ Anon() }) { v.Anon() }

// RunConstrained reaches its argument's method through a type constraint rather
// than through a parameter of interface type. Nothing names the concrete method,
// and the constraint is where the contract lives, so a walk that visits only
// parameter and result types finds no reason to doubt a finding about it.
func RunConstrained[T interface{ Constrained() }](v T) { v.Constrained() }

// RunStringish accepts an anonymous interface identical to [fmt.Stringer]. A
// doubt must not name both spellings: identical interfaces cannot differ in who
// implements them, so the anonymous one would lengthen every Stringer doubt in
// the report without adding a reason.
func RunStringish(v interface{ String() string }) string { return v.String() }

func assert(v any) bool {
	_, ok := v.(Bare)
	return ok
}

var _ = assert
