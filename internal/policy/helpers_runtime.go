package policy

import (
	"time"

	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// levenshteinMaxInputLen is the maximum string length accepted by the levenshtein
// functions. Inputs exceeding this limit return -1 to prevent excessive computation.
const levenshteinMaxInputLen = 128

// customHelperFunctions returns cel.EnvOption entries that register custom
// helper functions declared in helperFunctions. This keeps the runtime and
// catalog aligned.
func customHelperFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		// String distance functions
		cel.Function("levenshtein",
			cel.Overload("levenshtein_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(a, b ref.Val) ref.Val {
					return types.Int(levenshtein(toString(a), toString(b), levenshteinMaxInputLen, -1))
				}),
			),
		),
		cel.Function("levenshteinWithin",
			cel.Overload("levenshteinWithin_string",
				[]*cel.Type{cel.StringType, cel.StringType, cel.IntType},
				cel.BoolType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					if len(args) != 3 {
						return types.Bool(false)
					}
					a, b, limit := toString(args[0]), toString(args[1]), toInt64(args[2])
					dist := levenshtein(a, b, levenshteinMaxInputLen, limit)
					if dist < 0 {
						return types.Bool(false)
					}
					return types.Bool(dist <= limit)
				}),
			),
		),

		// Time functions for JWT/time-based policies
		// Note: CEL natively provides timestamp(int) and timestamp(string) constructors,
		// as well as duration(string). We only need to add now() since it's not built-in.
		cel.Function("now",
			cel.Overload("now_timestamp",
				[]*cel.Type{},
				cel.TimestampType,
				cel.FunctionBinding(func(args ...ref.Val) ref.Val {
					return types.Timestamp{Time: time.Now()}
				}),
			),
		),
		// age() is a convenience function for computing time since a Unix timestamp.
		// While you can use `now() - timestamp(jwt.iat)`, `age(jwt.iat)` is more readable.
		cel.Function("age",
			cel.Overload("age_timestamp",
				[]*cel.Type{cel.TimestampType},
				cel.DurationType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					ts, ok := val.(types.Timestamp)
					if !ok {
						return types.Duration{Duration: 0}
					}
					return types.Duration{Duration: time.Since(ts.Time)}
				}),
			),
			cel.Overload("age_int",
				[]*cel.Type{cel.IntType},
				cel.DurationType,
				cel.UnaryBinding(func(val ref.Val) ref.Val {
					secs := toInt64(val)
					t := time.Unix(secs, 0)
					return types.Duration{Duration: time.Since(t)}
				}),
			),
		),
	}
}
