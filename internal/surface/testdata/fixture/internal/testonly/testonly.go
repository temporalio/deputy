package testonly

// ForForeignTests is referenced only from another package's test file.
func ForForeignTests() string { return "foreign" }

// Shared carries an encoding tag, so a decoder can construct it. Two other
// declarations share its name and must not inherit its doubt: the method below,
// and the untagged ifaces.Shared.
type Shared struct {
	Name string `json:"name"`
}

// Holder declares a method named after the tagged type above.
type Holder struct{}

// Shared is a method, not the type of the same name in this same package. A
// method has no fields for a tag to be on.
func (Holder) Shared() {}
