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
// # Credential Sanitization
//
// The package provides systematic sanitization of sensitive data from error
// messages. Use this at RPC boundaries and when logging errors that might
// contain credentials:
//
//	// Sanitize an error before returning to client
//	return deperrors.Sanitize(err)
//
//	// Wrap with context while sanitizing
//	return deperrors.WrapSanitized(err, "failed to authenticate")
//
//	// Get fields safe for structured logging
//	slog.Error("operation failed", deperrors.SanitizeFields(err)...)
//
// The [DefaultSanitizer] detects common credential patterns:
//   - AWS credentials (access key ID, secret key, session token)
//   - GitHub tokens (fine-grained and classic PATs)
//   - Bearer tokens and JWTs
//   - Basic auth in URLs
//   - Private keys (PEM format)
//   - Database connection strings
//   - Azure and GCP credentials
//
// For authentication-specific errors, use [AuthenticationError] which
// guarantees safe error messages:
//
//	return deperrors.NewAuthenticationError(
//	    "AWS ECR",                    // service
//	    "GetAuthorizationToken",       // operation
//	    underlyingErr,                 // cause (may contain secrets)
//	    "run 'aws configure'",         // user-friendly hint
//	)
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
//   - [SanitizedError] - Error with sensitive data redacted
//   - [AuthenticationError] - Authentication failures (safe by design)
package errors
