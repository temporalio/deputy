// Package cli wires together the root Cobra command, its subcommands, and
// shared runtime concerns (logging, contextual execution) for the deputy tool.
// It focuses on composition: subcommand registration is delegated to the cmd
// subpackage (see internal/cli/cmd) so that new behavior can be added or legacy
// entry points retired without disturbing the public surface.
//
// The exported Run function constructs a root command configured with
// descriptive long help text, attaches subcommands, and executes within a
// provided context. Subcommands avoid global state to keep invocation
// deterministic and testable.
package cli
