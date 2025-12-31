// Package version provides build version information for Deputy.
//
// Set at build time via ldflags:
//
//	go build -ldflags "-X github.com/picatz/deputy/internal/version.Value=1.0.0"
package version

// Value is the semantic version of Deputy.
//
// Set at build time via ldflags. Defaults to "0.0.0-dev" for local builds.
// Must start with a digit for SARIF compliance (SARIF2005).
var Value = "0.0.0-dev"
