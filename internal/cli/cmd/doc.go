// Package cmd implements Deputy's CLI commands using the Cobra framework.
//
// This package contains all subcommand implementations (scan, fix, diff, sbom,
// list, policy, proxy, triage) and their supporting helpers. Commands are
// registered via [RegisterCommands] which attaches them to a root Cobra command.
//
// # Command Structure
//
// Each command follows a consistent pattern:
//   - Add{Command}Command function to register with a parent command
//   - Command-specific flags and configuration
//   - Execution logic that delegates to internal packages
//
// # Dependencies
//
// Commands receive shared services through the [Dependencies] struct, enabling
// dependency injection for testing and composition. The primary dependency is
// [scan.Service] which orchestrates vulnerability scanning workflows.
//
// # Output Formats
//
// Most commands support multiple output formats (table, json, sarif, github)
// configured via the --format flag. Format-specific rendering is handled by
// the [report/render] package.
package cmd
