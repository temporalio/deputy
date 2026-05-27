package proxy

import (
	"github.com/temporalio/deputy/internal/ecosystem"
)

// testableHandler provides access to internal handler fields for testing.
// It wraps a genericHandler to expose the baseHandler for test manipulation.
type testableHandler struct {
	*genericHandler
}

// newTestableHandler creates a handler that exposes internal fields for testing.
// This is intended only for use in tests.
func newTestableHandler(eco ecosystem.Ecosystem, upstream string, policies PolicyEvaluator) (*testableHandler, error) {
	h, err := DefaultFactory.CreateHandler(eco, upstream, policies)
	if err != nil {
		return nil, err
	}
	gh, ok := h.(*genericHandler)
	if !ok {
		// This should never happen if using DefaultFactory
		panic("unexpected handler type from factory")
	}
	return &testableHandler{genericHandler: gh}, nil
}

// newGoModuleHandler is a test helper that creates a Go module handler with
// exposed internal fields for test manipulation.
// Deprecated: Use newTestableHandler(ecosystem.Go, ...) instead.
func newGoModuleHandler(upstream string, policies PolicyEvaluator) (*testableHandler, error) {
	return newTestableHandler(ecosystem.Go, upstream, policies)
}

// newNPMHandler is a test helper that creates an npm handler with
// exposed internal fields for test manipulation.
// Deprecated: Use newTestableHandler(ecosystem.NPM, ...) instead.
func newNPMHandler(upstream string, policies PolicyEvaluator) (*testableHandler, error) {
	return newTestableHandler(ecosystem.NPM, upstream, policies)
}

// newPyPIHandler is a test helper that creates a PyPI handler with
// exposed internal fields for test manipulation.
// Deprecated: Use newTestableHandler(ecosystem.PyPI, ...) instead.
func newPyPIHandler(upstream string, policies PolicyEvaluator) (*testableHandler, error) {
	return newTestableHandler(ecosystem.PyPI, upstream, policies)
}

// newRubyGemsHandler is a test helper that creates a RubyGems handler with
// exposed internal fields for test manipulation.
// Deprecated: Use newTestableHandler(ecosystem.RubyGems, ...) instead.
func newRubyGemsHandler(upstream string, policies PolicyEvaluator) (*testableHandler, error) {
	return newTestableHandler(ecosystem.RubyGems, upstream, policies)
}
