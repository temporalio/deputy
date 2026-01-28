package targets

// TestRegistry is the registry type exposed for testing.
type TestRegistry = registry

// NewTestRegistry creates a new empty registry for testing.
func NewTestRegistry() *TestRegistry {
	return newRegistry()
}
