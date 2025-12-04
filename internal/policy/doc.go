// Package policy provides the core engine for evaluating Deputy policies.
// It leverages the Common Expression Language (CEL) to define and execute
// rules against various inputs, such as package metadata, vulnerabilities,
// and system configurations.
//
// The package handles:
//   - Parsing and compiling policy bundles (YAML + CEL).
//   - Managing policy metadata and entrypoints.
//   - executing policies against specific targets.
//   - Aggregating and reporting evaluation results.
//
// The central component is the Engine, which pre-compiles policies for
// efficient, repeated execution.
package policy
