package used

import (
	// Blank on purpose: the audit can only check implementations against an
	// interface the load graph contains, and a real module gets sql.Scanner
	// that way, through a dependency, with no file of its own naming it. An
	// import that named the interface would prove less.
	_ "database/sql"
)

// Used is referenced by package main, so it is not a finding.
func Used() string { return "used" }

// Local is referenced only by this package's own in-package test. It must be
// reported: an in-package test lives inside the boundary an unexport draws.
func Local() string { return "local" }

// NamedInString is referenced nowhere, but its name appears in a string
// literal below, which is a reason to doubt the finding.
func NamedInString() string { return "named" }

func selfReference() string { return "NamedInString" }

// localTagged declares an encoding-tagged type inside a function body, where it
// is nobody's surface and no finding can be about it. It deliberately shadows the
// name of the package-level Never, which must stay free of the encoding doubt.
func localTagged() any {
	type Never struct {
		Name string `json:"name"`
	}
	return Never{}
}

var _ = localTagged

// Never is referenced nowhere at all and carries no doubt.
type Never struct{}

// Method is an exported method nothing outside this package calls.
func (Never) Method() {}

// Stringish is referenced nowhere, but its String method satisfies
// [fmt.Stringer], so any %v verb anywhere can reach it.
type Stringish struct{}

// String implements [fmt.Stringer].
func (Stringish) String() string { return "stringish" }

// Decoy names a method like an interface method without satisfying the
// interface: this Read takes no arguments, so io.Reader is not implemented and
// the audit must not claim dispatch reaches it.
type Decoy struct{}

// Read is not io.Reader's Read.
func (Decoy) Read() {}

// Scannable satisfies [database/sql.Scanner] by signature alone. Nothing in
// this module calls Scan; a database driver does, through the interface, so the
// audit has to find the contract in the standard library to doubt the finding.
type Scannable struct{}

// Scan implements [database/sql.Scanner].
func (*Scannable) Scan(src any) error { return nil }

// Tagged carries an encoding tag, so a decoder can construct it without any
// caller naming the type.
type Tagged struct {
	Name string `json:"name"`
}
