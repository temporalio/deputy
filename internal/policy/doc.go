// Package policy provides the CEL-based policy evaluation engine for Deputy.
//
// Policies are defined in YAML with CEL expressions that evaluate against
// typed proto inputs like vulnerabilities, packages, and container images.
//
// The package provides:
//   - Parsing and compiling policy bundles (YAML + CEL)
//   - Pre-compiled policy execution via Engine
//   - Entrypoint-based routing for different evaluation contexts
//   - Custom CEL helper functions for security analysis
//
// Example usage:
//
//	engine, err := policy.NewEngineFromPaths([]string{"policy.yaml"})
//	actions, err := engine.EvaluateAll(ctx, payload, "scan", "scan_vulnerability")
package policy
