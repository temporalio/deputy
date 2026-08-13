package used

import (
	// Blank on purpose: the audit can only check implementations against an
	// interface the load graph contains, and a real module gets sql.Scanner
	// that way, through a dependency, with no file of its own naming it. An
	// import that named the interface would prove less.
	"context"
	_ "database/sql"
	"log/slog"
)

// Used is referenced by package main, so it is not a finding.
func Used() string { return "used" }

// Local is referenced only by this package's own in-package test. It must be
// reported: an in-package test lives inside the boundary an unexport draws.
func Local() string { return "local" }

// ForSDKOnly is referenced from the module-root sdk/ tree and from nowhere else.
// It carries the invariant that an excluded tree still contributes references:
// the exclusion decides whose surface is audited, not which references count, so
// this must not be reported. A case written against a symbol main also uses
// would pass whether or not sdk/ was scanned at all.
func ForSDKOnly() string { return "sdk" }

// ForExampleOnly is the same invariant for examples/, the other module-root tree
// the audit excludes from findings.
func ForExampleOnly() string { return "example" }

// NamedInString is referenced nowhere, but its name appears in a string
// literal below, which is a reason to doubt the finding.
func NamedInString() string { return "named" }

func selfReference() string { return "NamedInString" }

// NamedInAssetAndLiteral is named in the Go string literal below and also in the
// fixture's CEL policy. Go literals are tokenized before assets, so reporting
// whichever source arrived first would name the literal and hide the policy that
// actually looks the symbol up.
func NamedInAssetAndLiteral() string { return "both" }

func selfReferenceBoth() string { return "NamedInAssetAndLiteral" }

var _ = selfReferenceBoth

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

// NotAProto declares a method named ProtoReflect that returns a string, so it
// satisfies protobuf's message contract in name only. Nothing registers it and
// nothing can reach it through the proto registry, so it must not be called a
// protobuf message.
type NotAProto struct{}

// ProtoReflect has protobuf's method name and none of its signature.
func (NotAProto) ProtoReflect() string { return "not a message" }

// ConstraintReached satisfies the constraint on ifaces.RunConstrained. No named
// interface in the fixture declares a Constrained method, so the doubt on its
// method can only come from the constraint.
type ConstraintReached struct{}

// Constrained is reached only through a generic type constraint.
func (ConstraintReached) Constrained() {}

// AnonReached satisfies the anonymous interface ifaces.RunAnon accepts. No named
// interface anywhere in the fixture declares an Anon method, so the doubt on its
// method can only come from the anonymous interface in that signature.
type AnonReached struct{}

// Anon is reached only through an anonymous interface.
func (AnonReached) Anon() {}

// Handled satisfies [log/slog.Handler], which is the shape that showed a
// hand-maintained contract list cannot carry this check. Nothing here calls its
// methods; slog does, once a handler is installed. The audit's supplemental list
// does not name slog.Handler, so the only way these methods earn their doubt is
// by deriving the contract from the WithAttrs and WithGroup results below, which
// are the one place this module mentions the interface.
type Handled struct{}

// Enabled implements [log/slog.Handler].
func (Handled) Enabled(context.Context, slog.Level) bool { return true }

// Handle implements [log/slog.Handler].
func (Handled) Handle(context.Context, slog.Record) error { return nil }

// WithAttrs implements [log/slog.Handler].
func (Handled) WithAttrs([]slog.Attr) slog.Handler { return Handled{} }

// WithGroup implements [log/slog.Handler].
func (Handled) WithGroup(string) slog.Handler { return Handled{} }
