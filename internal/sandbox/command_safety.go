package sandbox

import (
	"path/filepath"
	"regexp"
	"slices"
	"strings"
)

// CommandSafety represents the safety classification of a command.
type CommandSafety int

const (
	// CommandSafe means the command is read-only or benign.
	// No confirmation needed.
	CommandSafe CommandSafety = iota

	// CommandNormal means the command may modify files but is not inherently dangerous.
	// Confirmation based on sandbox mode.
	CommandNormal

	// CommandDangerous means the command is potentially destructive.
	// Always requires confirmation unless explicitly skipped.
	CommandDangerous
)

// String returns a human-readable safety level.
func (s CommandSafety) String() string {
	switch s {
	case CommandSafe:
		return "safe"
	case CommandNormal:
		return "normal"
	case CommandDangerous:
		return "dangerous"
	default:
		return "unknown"
	}
}

// safeCommands are read-only commands that never modify state.
// Based on Codex's safe command list with additions for common dev tools.
var safeCommands = map[string]bool{
	// Core Unix read-only commands
	"cat":     true,
	"head":    true,
	"tail":    true,
	"less":    true,
	"more":    true,
	"grep":    true,
	"egrep":   true,
	"fgrep":   true,
	"rg":      true, // ripgrep
	"ag":      true, // silver searcher
	"ack":     true,
	"ls":      true,
	"ll":      true,
	"la":      true,
	"dir":     true,
	"tree":    true,
	"find":    true, // Conditionally safe (see below)
	"which":   true,
	"whereis": true,
	"whatis":  true,
	"type":    true,
	"file":    true,
	"stat":    true,
	"wc":      true,
	"nl":      true,
	"sort":    true, // Safe unless -o
	"uniq":    true,
	"diff":    true,
	"cmp":     true,
	"comm":    true,
	"cut":     true,
	"paste":   true,
	"join":    true,
	"tr":      true,
	"rev":     true,
	"tac":     true,
	"fold":    true,
	"fmt":     true,
	"column":  true,
	"seq":     true,
	"expr":    true,
	"bc":      true,
	"dc":      true,

	// System info (read-only)
	"pwd":      true,
	"id":       true,
	"whoami":   true,
	"who":      true,
	"w":        true,
	"groups":   true,
	"hostname": true,
	"uname":    true,
	"arch":     true,
	"nproc":    true,
	"uptime":   true,
	"date":     true,
	"cal":      true,
	"env":      true,
	"printenv": true,
	"locale":   true,
	"df":       true,
	"du":       true,
	"free":     true,
	"vmstat":   true,
	"iostat":   true,
	"top":      true, // Interactive but read-only
	"htop":     true, // Interactive but read-only
	"ps":       true,
	"pgrep":    true,
	"lsof":     true,
	"netstat":  true,
	"ss":       true,

	// Developer tools (read-only operations)
	"echo":   true,
	"printf": true,
	"true":   true,
	"false":  true,
	"test":   true,
	"[":      true,
	"man":    true,
	"info":   true,
	"help":   true,
	"yes":    true, // Can be dangerous in pipes but itself is benign

	// Version/help queries
	"go":      true, // Conditionally safe
	"node":    true, // Conditionally safe
	"python":  true, // Conditionally safe
	"python3": true,
	"ruby":    true,
	"perl":    true,
	"java":    true,
	"javac":   true,
	"rustc":   true,
	"cargo":   true, // Conditionally safe
	"npm":     true, // Conditionally safe
	"yarn":    true, // Conditionally safe
	"pnpm":    true, // Conditionally safe
	"pip":     true, // Conditionally safe
	"pip3":    true,

	// macOS specific
	"pbcopy":  true, // Clipboard (technically writes clipboard)
	"pbpaste": true,
	"open":    true, // Opens files/URLs
	"mdfind":  true,
	"mdls":    true,

	// Linux specific
	"numfmt": true,
	"getent": true,
}

// normalCommands are known state-changing commands that are not inherently destructive.
var normalCommands = map[string]bool{
	"touch": true,
	"mkdir": true,
	"cp":    true,
	"mv":    true,
}

// dangerousPatterns are regex patterns that indicate dangerous commands.
var dangerousPatterns = []*regexp.Regexp{
	// Destructive file operations
	regexp.MustCompile(`\brm\s+.*-[rRf]`), // rm with -r or -f
	regexp.MustCompile(`\brm\s+-[rRf]`),   // rm -rf, rm -r, rm -f
	regexp.MustCompile(`\brmdir\b`),       // Remove directories
	regexp.MustCompile(`\bshred\b`),       // Secure delete
	regexp.MustCompile(`\bdd\b`),          // Disk destroyer
	regexp.MustCompile(`\bmkfs\b`),        // Filesystem creation
	regexp.MustCompile(`\bfdisk\b`),       // Partition editing
	regexp.MustCompile(`\bparted\b`),      // Partition editing

	// Privilege escalation
	regexp.MustCompile(`\bsudo\b`),
	regexp.MustCompile(`\bsu\b`),
	regexp.MustCompile(`\bdoas\b`),
	regexp.MustCompile(`\bpkexec\b`),

	// System modification
	regexp.MustCompile(`\bchmod\s+[0-7]*7`), // World-writable permissions
	regexp.MustCompile(`\bchown\b`),         // Change ownership
	regexp.MustCompile(`\bchgrp\b`),         // Change group
	regexp.MustCompile(`\bsystemctl\b`),     // Service management
	regexp.MustCompile(`\bservice\b`),       // Service management
	regexp.MustCompile(`\blaunchctl\b`),     // macOS service management

	// Network exfiltration patterns
	regexp.MustCompile(`curl.*\|.*sh`), // Pipe to shell
	regexp.MustCompile(`wget.*\|.*sh`), // Pipe to shell
	regexp.MustCompile(`curl.*-o\s*/`), // Download to absolute path
	regexp.MustCompile(`wget.*-O\s*/`), // Download to absolute path

	// Git dangerous operations
	regexp.MustCompile(`\bgit\s+push\s+.*--force`),
	regexp.MustCompile(`\bgit\s+push\s+-f\b`),
	regexp.MustCompile(`\bgit\s+reset\s+--hard`),
	regexp.MustCompile(`\bgit\s+clean\s+-[fdx]`),

	// Package publishing (supply chain risk)
	regexp.MustCompile(`\bnpm\s+publish\b`),
	regexp.MustCompile(`\byarn\s+publish\b`),
	regexp.MustCompile(`\bpnpm\s+publish\b`),
	regexp.MustCompile(`\bcargo\s+publish\b`),
	regexp.MustCompile(`\bgem\s+push\b`),
	regexp.MustCompile(`\bpip\s+.*upload\b`),
	regexp.MustCompile(`\btwine\s+upload\b`),
	regexp.MustCompile(`\bgo\s+.*-mod=mod\b`), // Modifying go.mod in unexpected ways

	// Container escape vectors
	regexp.MustCompile(`\bdocker\s+run\s+.*--privileged`),
	regexp.MustCompile(`\bdocker\s+run\s+.*--pid=host`),
	regexp.MustCompile(`\bdocker\s+run\s+.*--network=host`),
}

// conditionalSafetyRules define commands that are safe only with certain arguments.
type conditionalRule struct {
	Command     string
	SafeArgs    []string // Subcommands/args that make it safe
	DangerArgs  []string // Subcommands/args that make it dangerous
	SafePattern *regexp.Regexp
}

var conditionalRules = []conditionalRule{
	// git: only certain subcommands are safe
	{
		Command:    "git",
		SafeArgs:   []string{"status", "log", "diff", "show", "branch", "tag", "remote", "config", "describe", "rev-parse", "ls-files", "ls-tree", "blame", "shortlog", "stash", "list"},
		DangerArgs: []string{"push", "reset", "clean", "rm", "rebase", "merge", "cherry-pick"},
	},
	// cargo: only check/clippy/doc are safe
	{
		Command:    "cargo",
		SafeArgs:   []string{"check", "clippy", "doc", "tree", "metadata", "version", "search", "info"},
		DangerArgs: []string{"publish", "install", "uninstall"},
	},
	// go: most read operations are safe
	{
		Command:    "go",
		SafeArgs:   []string{"version", "env", "list", "doc", "vet", "fmt", "mod", "help"},
		DangerArgs: []string{"install"},
	},
	// npm/yarn/pnpm: limited safe operations
	{
		Command:    "npm",
		SafeArgs:   []string{"list", "ls", "view", "info", "search", "outdated", "audit", "config", "help", "version"},
		DangerArgs: []string{"publish", "unpublish", "deprecate"},
	},
	{
		Command:    "yarn",
		SafeArgs:   []string{"list", "info", "outdated", "audit", "config", "help", "version", "why"},
		DangerArgs: []string{"publish"},
	},
	{
		Command:    "pnpm",
		SafeArgs:   []string{"list", "ls", "view", "outdated", "audit", "config", "help", "version", "why"},
		DangerArgs: []string{"publish"},
	},
	// pip: only query operations are safe
	{
		Command:    "pip",
		SafeArgs:   []string{"list", "show", "search", "check", "config", "help", "freeze"},
		DangerArgs: []string{"install", "uninstall"},
	},
	{
		Command:    "pip3",
		SafeArgs:   []string{"list", "show", "search", "check", "config", "help", "freeze"},
		DangerArgs: []string{"install", "uninstall"},
	},
	// find: dangerous with -exec, -delete
	{
		Command:    "find",
		DangerArgs: []string{"-exec", "-execdir", "-delete", "-ok", "-okdir"},
	},
	// sed: only safe for printing (sed -n '1,10p')
	{
		Command:     "sed",
		SafePattern: regexp.MustCompile(`^sed\s+-n\s+['"]?\d+(,\d+)?p`),
	},
	// base64: dangerous with output redirect
	{
		Command:    "base64",
		DangerArgs: []string{"-o", "--output"},
	},
}

// ClassifyCommand determines the safety level of a command.
func ClassifyCommand(cmd []string) CommandSafety {
	if len(cmd) == 0 {
		return CommandDangerous
	}

	// Get the base command name (without path)
	executable := filepath.Base(cmd[0])
	cmdStr := strings.Join(cmd, " ")

	// Check dangerous patterns first (highest priority)
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(cmdStr) {
			return CommandDangerous
		}
	}

	// Check conditional rules
	for _, rule := range conditionalRules {
		if executable == rule.Command || filepath.Base(executable) == rule.Command {
			return classifyConditional(cmd, rule)
		}
	}

	// Check if it's a known safe command
	if safeCommands[executable] {
		return CommandSafe
	}

	if normalCommands[executable] {
		return CommandNormal
	}

	// Default to dangerous for unknown commands
	return CommandDangerous
}

// classifyConditional applies conditional safety rules.
func classifyConditional(cmd []string, rule conditionalRule) CommandSafety {
	if len(cmd) < 2 {
		// Just the command name with no args - treat as querying help/version
		return CommandSafe
	}

	// Check safe pattern if defined
	if rule.SafePattern != nil {
		cmdStr := strings.Join(cmd, " ")
		if rule.SafePattern.MatchString(cmdStr) {
			return CommandSafe
		}
	}

	// Get the subcommand (first non-flag argument)
	subcommand := ""
	for _, arg := range cmd[1:] {
		if !strings.HasPrefix(arg, "-") {
			subcommand = arg
			break
		}
	}

	// Check if subcommand is explicitly dangerous
	for _, dangerous := range rule.DangerArgs {
		if subcommand == dangerous {
			return CommandDangerous
		}
		// Also check if any arg matches (for flags like -exec)
		if slices.Contains(cmd[1:], dangerous) {
			return CommandDangerous
		}
	}

	// Check if subcommand is explicitly safe
	if slices.Contains(rule.SafeArgs, subcommand) {
		return CommandSafe
	}

	// If we have safe args defined but didn't match, be conservative
	if len(rule.SafeArgs) > 0 {
		return CommandNormal
	}

	return CommandNormal
}

// IsSafeCommand is a convenience function that returns true if the command is classified as safe.
func IsSafeCommand(cmd []string) bool {
	return ClassifyCommand(cmd) == CommandSafe
}

// IsDangerousCommand is a convenience function that returns true if the command is classified as dangerous.
func IsDangerousCommand(cmd []string) bool {
	return ClassifyCommand(cmd) == CommandDangerous
}

// CommandSafetyReason returns a human-readable explanation for why a command was classified.
func CommandSafetyReason(cmd []string) string {
	if len(cmd) == 0 {
		return "empty command"
	}

	cmdStr := strings.Join(cmd, " ")
	executable := filepath.Base(cmd[0])

	// Check dangerous patterns
	for _, pattern := range dangerousPatterns {
		if pattern.MatchString(cmdStr) {
			return "matches dangerous pattern: " + pattern.String()
		}
	}

	// Check conditional rules
	for _, rule := range conditionalRules {
		if executable == rule.Command {
			safety := classifyConditional(cmd, rule)
			switch safety {
			case CommandSafe:
				return "safe subcommand for " + rule.Command
			case CommandDangerous:
				return "dangerous subcommand for " + rule.Command
			default:
				return "unrecognized subcommand for " + rule.Command
			}
		}
	}

	if safeCommands[executable] {
		return "known safe command"
	}
	if normalCommands[executable] {
		return "known normal command"
	}

	return "unknown command, treated as dangerous"
}
