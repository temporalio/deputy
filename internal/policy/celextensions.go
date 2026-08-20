package policy

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/ext"
)

// celExtension is a versioned cel-go library enabled in the policy CEL
// environment, paired with the version Deputy pins it to.
type celExtension struct {
	// library is the cel-go singleton library name, which is the name
	// (*cel.Env).Libraries reports once the library is registered. It lets a
	// test map an enabled library back to its pin.
	library string

	// version is the pinned library version. cel-go includes only the
	// functions, macros, and validators introduced at or below this version.
	version uint32

	// enable builds the environment option that registers the library at the
	// given version. It takes the version as an argument instead of closing
	// over the pin so that a test can build the same library at neighboring
	// versions and compare what each declares.
	enable func(version uint32) cel.EnvOption
}

// celExtensions lists the cel-go libraries the policy CEL environment enables,
// each at an explicit version, in the order they are applied.
//
// cel-go versions every library it ships so that adding a function, rewriting
// an overload, or changing a default cannot alter the meaning of an expression
// written against an earlier version. Enabling a library without a version
// (plain ext.Strings(), for example) opts into whatever the linked cel-go
// release treats as latest, so a routine dependency bump can change what an
// already committed policy evaluates to with no diff in the policy. Deputy
// decides whether a dependency is allowed, so each library version is part of
// the policy language contract: raising a pin is a deliberate change to that
// contract rather than a side effect of an upgrade.
//
// The pins here are the highest version each library implements in the cel-go
// release named in go.mod, because that is the behavior every policy and
// example in this repository was written and tested against. Pinning below
// latest would drop functions policies already use, and pinning above latest
// would be indistinguishable from not pinning at all, since cel-go gates
// features with "version >= n" and a too-high pin silently picks up whatever a
// later release adds. Every entry records what its pinned version covers so
// the numbers can be reviewed without reading cel-go's source, and
// celextensions_test.go keeps both claims honest: it fails when a library is
// enabled outside this table and when cel-go grows a version beyond a pin.
//
// CEL's own standard library, which cel.NewEnv enables implicitly, exposes no
// version option, so it cannot be pinned here.
//
// Order is load bearing. cel-go registers a singleton library once and the
// first registration wins, so these options are applied ahead of the rest of
// the environment, which makes a stray unpinned call added later a no-op
// rather than a silent unpinning.
var celExtensions = []celExtension{
	{
		// Optional types: ?. and ?[] access, optional.of/none/ofNonZeroValue.
		// Version 1 added the optFlatMap macro; version 2 added first, last,
		// optional.unwrap, and unwrapOpt. Required by ext.Regex, which
		// declares optional-typed results.
		library: "cel.lib.optional",
		version: 2,
		enable: func(version uint32) cel.EnvOption {
			return cel.OptionalTypes(cel.OptionalTypesVersion(version))
		},
	},
	{
		// Strings: charAt, indexOf, split, substring, trim, and friends.
		// Version 1 added format and strings.quote, version 2 join, version 3
		// reverse, version 4 the rewritten format implementation and its AST
		// validator, version 5 cost estimators plus the default limit of 100
		// on format precision.
		library: "cel.lib.ext.strings",
		version: 5,
		enable: func(version uint32) cel.EnvOption {
			return ext.Strings(ext.StringsVersion(version))
		},
	},
	{
		// Lists: slice at version 0, flatten at version 1, distinct, range,
		// reverse, sort, and sortBy at version 2, cost estimators at version
		// 3.
		library: "cel.lib.ext.lists",
		version: 3,
		enable: func(version uint32) cel.EnvOption {
			return ext.Lists(ext.ListsVersion(version))
		},
	},
	{
		// Sets: sets.contains, sets.equivalent, sets.intersects. cel-go has
		// only ever shipped version 0 of this library, so 0 is both the first
		// and the current version.
		library: "cel.lib.ext.sets",
		version: 0,
		enable: func(version uint32) cel.EnvOption {
			return ext.Sets(ext.SetsVersion(version))
		},
	},
	{
		// Regex: regex.replace, regex.extract, regex.extractAll. Introduced
		// whole at version 0, with no later versions yet.
		library: "cel.lib.ext.regex",
		version: 0,
		enable: func(version uint32) cel.EnvOption {
			return ext.Regex(ext.RegexVersion(version))
		},
	},
	{
		// Bindings: the cel.bind macro for local variables at version 0, the
		// cel.@block form used by the optimizer at version 1.
		library: "cel.lib.ext.cel.bindings",
		version: 1,
		enable: func(version uint32) cel.EnvOption {
			return ext.Bindings(ext.BindingsVersion(version))
		},
	},
	{
		// Encoders: base64.encode and base64.decode at version 0, json.encode
		// at version 1.
		library: "cel.lib.ext.encoders",
		version: 1,
		enable: func(version uint32) cel.EnvOption {
			return ext.Encoders(ext.EncodersVersion(version))
		},
	},
	{
		// Math: math.greatest and math.least at version 0, the rounding,
		// sign, bitwise, and float classification functions at version 1,
		// math.sqrt at version 2.
		library: "cel.lib.ext.math",
		version: 2,
		enable: func(version uint32) cel.EnvOption {
			return ext.Math(ext.MathVersion(version))
		},
	},
}

// celExtensionOptions returns the environment options that enable every pinned
// cel-go library, in celExtensions order. It is the only way the policy
// environment should enable an extension library.
func celExtensionOptions() []cel.EnvOption {
	opts := make([]cel.EnvOption, 0, len(celExtensions))
	for _, extension := range celExtensions {
		opts = append(opts, extension.enable(extension.version))
	}
	return opts
}
