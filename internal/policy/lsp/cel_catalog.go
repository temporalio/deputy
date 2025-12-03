package lsp

import "github.com/picatz/deputy/internal/policy"

// celFunction describes a helper available in the CEL environment.
type celFunction struct {
	Name      string
	Signature string
	Doc       string
}

// celFunctionCatalog reads helper definitions from the policy runtime to stay in sync.
func celFunctionCatalog() []celFunction {
	helpers := policy.HelperCatalog()
	out := make([]celFunction, 0, len(helpers))
	for _, h := range helpers {
		out = append(out, celFunction{Name: h.Name, Signature: h.Signature, Doc: h.Doc})
	}
	return out
}
