// Package remediation generates actionable steps to resolve security vulnerabilities.
// It analyzes vulnerability reports and suggests specific commands (e.g., `go get`, `npm install`)
// or manual actions to upgrade affected dependencies.
//
// The package handles:
//   - Consolidating multiple vulnerabilities for the same package.
//   - Determining the minimal version upgrade required to fix issues.
//   - Generating ecosystem-specific commands (Go, npm, etc.).
//   - Suggesting Go toolchain upgrades when standard library vulnerabilities are found.
package remediation
