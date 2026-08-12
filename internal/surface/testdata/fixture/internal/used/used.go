package used

// Used is referenced by package main, so it is not a finding.
func Used() string { return "used" }

// Local is referenced only by this package's own in-package test. It must be
// reported: an in-package test lives inside the boundary an unexport draws.
func Local() string { return "local" }

// NamedInString is referenced nowhere, but its name appears in a string
// literal below, which is a reason to doubt the finding.
func NamedInString() string { return "named" }

func selfReference() string { return "NamedInString" }

// Never is referenced nowhere at all and carries no doubt.
type Never struct{}

// Method is an exported method nothing outside this package calls.
func (Never) Method() {}
