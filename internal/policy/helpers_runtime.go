package policy

import (
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
)

// customHelperFunctions returns cel.EnvOption entries that register custom
// helper functions declared in helperFunctions. This keeps the runtime and
// catalog aligned.
func customHelperFunctions() []cel.EnvOption {
	return []cel.EnvOption{
		cel.Function("levenshtein",
			cel.Overload("levenshtein_string",
				[]*cel.Type{cel.StringType, cel.StringType},
				cel.IntType,
				cel.BinaryBinding(func(a, b ref.Val) ref.Val {
					return types.Int(levenshtein(toString(a), toString(b), 128, -1))
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
					dist := levenshtein(a, b, 128, limit)
					if dist < 0 {
						return types.Bool(false)
					}
					return types.Bool(dist <= limit)
				}),
			),
		),
	}
}
