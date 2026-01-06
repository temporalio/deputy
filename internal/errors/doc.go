// Package errors provides domain-specific error types for Deputy.
//
// This package enables robust error handling using [errors.Is] and [errors.As],
// allowing callers to distinguish between different failure modes and handle
// them appropriately.
//
// # Sentinel Errors
//
// Common failure modes are represented as sentinel errors:
//
//	if errors.Is(err, deperrors.ErrNotFound) {
//	    // Handle missing resource
//	}
//	if errors.Is(err, deperrors.ErrNetwork) {
//	    // Handle network failure
//	}
//
// # Typed Errors
//
// Domain-specific errors carry additional context:
//
//	var policyErr *PolicyError
//	if errors.As(err, &policyErr) {
//	    fmt.Printf("Policy %s failed at line %d\n", policyErr.PolicyName, policyErr.Line)
//	}
//
// # Error Suggestions
//
// Errors can carry remediation suggestions for display to users:
//
//	err := deperrors.Suggest(
//	    errors.New("ANTHROPIC_API_KEY is not set"),
//	    "Set the ANTHROPIC_API_KEY environment variable",
//	)
//
//	// Later, when displaying the error:
//	if suggestion := deperrors.GetSuggestion(err); suggestion != "" {
//	    fmt.Printf("Suggestion: %s\n", suggestion)
//	}
//
// Common suggestions are available via [CommonSuggestions]:
//
//	deperrors.SuggestFor("network")  // Returns network troubleshooting hint
//
// # Silent Errors
//
// For errors that should exit non-zero but not print (because the command
// already explained the issue):
//
//	return deperrors.Silent(err)  // CLI framework won't print this
//
// # Error Types
//
// Available error types:
//   - [PolicyError] - Policy evaluation or compilation failures
//   - [ValidationError] - Input validation failures
//   - [NetworkError] - Network operation failures with retry context
//   - [ConfigError] - Configuration-related failures
//   - [ScanError] - Dependency scanning failures
//   - [TargetError] - Target resolution failures (repos, images)
//   - [PluginError] - Plugin execution failures
package errors
