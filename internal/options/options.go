package options

// Validator is implemented by Options types that support validation.
// The Validate method should return an error if the options are invalid,
// or nil if they are valid.
type Validator interface {
	Validate() error
}

// Validate checks if v implements Validator and calls its Validate method.
// Returns nil if v is nil or does not implement Validator.
func Validate(v any) error {
	if v == nil {
		return nil
	}
	if validator, ok := v.(Validator); ok {
		return validator.Validate()
	}
	return nil
}

// MustValidate calls Validate and panics if validation fails.
// Use this in initialization code where invalid options are programming errors.
func MustValidate(v any) {
	if err := Validate(v); err != nil {
		panic("options validation failed: " + err.Error())
	}
}
