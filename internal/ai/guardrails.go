package ai

import (
	"fmt"
	"path/filepath"
	"regexp"
	"strings"
)

// Guardrails defines safety constraints for AI agent operations.
// Guardrails are evaluated before approval checks and can block operations
// outright or flag them as high-risk (requiring explicit approval).
//
// The evaluation order is:
//  1. Deny rules (if matched, operation is blocked immediately)
//  2. Allow rules (if matched, operation proceeds to approval check)
//  3. High-risk rules (if matched, operation is flagged as high-risk)
//  4. Default action (allow or deny based on configuration)
//
// This design follows the principle of deny-by-default for maximum safety.
type Guardrails struct {
	// Commands contains rules for shell command execution.
	Commands CommandGuardrails `yaml:"commands" json:"commands"`

	// Files contains rules for file system operations.
	Files FileGuardrails `yaml:"files" json:"files"`

	// Network contains rules for network operations (future).
	Network NetworkGuardrails `yaml:"network" json:"network"`

	// Custom allows user-defined rules evaluated via a callback.
	// This enables integration with external policy engines.
	Custom CustomGuardrails `yaml:"-" json:"-"`
}

// CommandGuardrails controls what shell commands an agent can execute.
type CommandGuardrails struct {
	// DenyPatterns blocks commands matching these regex patterns.
	// These are evaluated first - a match means immediate denial.
	DenyPatterns []string `yaml:"deny_patterns" json:"deny_patterns"`

	// AllowPatterns permits only commands matching these patterns.
	// If non-empty, commands not matching any pattern are denied.
	AllowPatterns []string `yaml:"allow_patterns" json:"allow_patterns"`

	// HighRiskPatterns flags commands as high-risk (requiring approval).
	// These are checked after deny/allow, before the operation proceeds.
	HighRiskPatterns []string `yaml:"high_risk_patterns" json:"high_risk_patterns"`

	// DenyCommands blocks specific command names (e.g., "rm", "sudo").
	DenyCommands []string `yaml:"deny_commands" json:"deny_commands"`

	// AllowCommands permits only these command names.
	// If non-empty, commands not in this list are denied.
	AllowCommands []string `yaml:"allow_commands" json:"allow_commands"`

	// compiled holds pre-compiled regex patterns for performance.
	compiled *compiledCommandRules
}

// FileGuardrails controls what file operations an agent can perform.
type FileGuardrails struct {
	// DenyPaths blocks operations on paths matching these patterns.
	// Supports glob syntax (e.g., "/etc/**", "~/.ssh/*").
	DenyPaths []string `yaml:"deny_paths" json:"deny_paths"`

	// AllowPaths permits only operations on paths matching these patterns.
	// If non-empty, operations on non-matching paths are denied.
	AllowPaths []string `yaml:"allow_paths" json:"allow_paths"`

	// HighRiskPaths flags operations on these paths as high-risk.
	HighRiskPaths []string `yaml:"high_risk_paths" json:"high_risk_paths"`

	// DenyExtensions blocks operations on files with these extensions.
	DenyExtensions []string `yaml:"deny_extensions" json:"deny_extensions"`

	// AllowExtensions permits only operations on files with these extensions.
	AllowExtensions []string `yaml:"allow_extensions" json:"allow_extensions"`

	// DenyActions blocks specific actions (e.g., "delete", "execute").
	// Valid actions: "read", "create", "modify", "delete", "execute"
	DenyActions []string `yaml:"deny_actions" json:"deny_actions"`

	// WorkspaceOnly restricts all file operations to the workspace directory.
	// This is the recommended setting for most use cases.
	WorkspaceOnly bool `yaml:"workspace_only" json:"workspace_only"`

	// compiled holds pre-compiled patterns for performance.
	compiled *compiledFileRules
}

// NetworkGuardrails controls network operations (for future use).
type NetworkGuardrails struct {
	// DenyHosts blocks connections to these hosts/patterns.
	DenyHosts []string `yaml:"deny_hosts" json:"deny_hosts"`

	// AllowHosts permits only connections to these hosts.
	AllowHosts []string `yaml:"allow_hosts" json:"allow_hosts"`

	// DenyPorts blocks connections on these ports.
	DenyPorts []int `yaml:"deny_ports" json:"deny_ports"`

	// AllowPorts permits only connections on these ports.
	AllowPorts []int `yaml:"allow_ports" json:"allow_ports"`
}

// CustomGuardrails allows pluggable guardrail evaluation.
type CustomGuardrails struct {
	// EvalCommand is called to evaluate command execution.
	// Return (false, nil) to allow, (true, nil) to flag as high-risk,
	// or (_, error) to deny with the given reason.
	EvalCommand func(cmd string) (highRisk bool, err error)

	// EvalFile is called to evaluate file operations.
	EvalFile func(path, action string) (highRisk bool, err error)
}

// GuardrailResult contains the outcome of a guardrail evaluation.
type GuardrailResult struct {
	// Allowed indicates whether the operation is permitted.
	Allowed bool

	// HighRisk indicates the operation requires explicit approval.
	HighRisk bool

	// Reason explains why the operation was blocked or flagged.
	Reason string

	// Rule identifies which rule triggered the result.
	Rule string
}

// DefaultGuardrails returns sensible default guardrails that block
// dangerous operations while allowing typical development workflows.
func DefaultGuardrails() *Guardrails {
	return &Guardrails{
		Commands: CommandGuardrails{
			DenyPatterns: []string{
				// Destructive file operations with dangerous paths
				`(?i)\brm\s+(-[rf]+\s+)*(/|~|\$HOME|\.\.)`,
				// Privilege escalation
				`(?i)\bsudo\b`,
				`(?i)\bsu\s+-`,
				`(?i)\bdoas\b`,
				// Remote code execution patterns
				`(?i)\bcurl\b.*\|\s*(ba)?sh`,
				`(?i)\bwget\b.*\|\s*(ba)?sh`,
				`(?i)\beval\s*\(`,
				// System modification
				`(?i)>\s*/etc/`,
				`(?i)\bdd\s+.*of=/dev/`,
				`(?i)\bmkfs\b`,
				`(?i)\bfdisk\b`,
				`(?i)\bparted\b`,
				// Fork bombs and resource exhaustion
				`(?i):(){.*};:`,
				`(?i)\bfork\s*\(.*\)\s*while`,
				// Credential/secret exfiltration
				`(?i)\bcat\s+.*\.(pem|key|crt|p12|pfx)`,
				`(?i)\bbase64\s+.*\.(pem|key|crt)`,
				// Network reconnaissance (often used in attacks)
				`(?i)\bnmap\b`,
				`(?i)\bnetcat\b|\bnc\s+-`,
			},
			HighRiskPatterns: []string{
				// Git operations that rewrite history
				`(?i)\bgit\s+push\s+.*--force`,
				`(?i)\bgit\s+push\s+-f\b`,
				`(?i)\bgit\s+reset\s+--hard`,
				`(?i)\bgit\s+rebase\s+-i`,
				`(?i)\bgit\s+filter-branch`,
				// Package publishing (irreversible)
				`(?i)\bnpm\s+publish`,
				`(?i)\bgo\s+mod\s+.*publish`,
				`(?i)\bcargo\s+publish`,
				`(?i)\bgem\s+push`,
				`(?i)\btwine\s+upload`,
				// Permission changes
				`(?i)\bchmod\s+[0-7]*7[0-7]*`, // world-writable
				`(?i)\bchown\b`,
				`(?i)\bchgrp\b`,
				// Service management
				`(?i)\bsystemctl\s+(start|stop|restart|enable|disable)`,
				`(?i)\bservice\s+\w+\s+(start|stop|restart)`,
				// Container operations
				`(?i)\bdocker\s+(rm|rmi|stop|kill)`,
				`(?i)\bkubectl\s+delete`,
				// Database operations
				`(?i)\bdrop\s+(table|database|schema)`,
				`(?i)\btruncate\s+table`,
			},
			DenyCommands: []string{
				// Extremely dangerous commands that should never run
				"shutdown", "reboot", "poweroff", "halt", "init",
				"mkfs", "fdisk", "parted", "dd",
				"iptables", "ufw", "firewall-cmd",
			},
		},
		Files: FileGuardrails{
			DenyPaths: []string{
				// System files
				"/etc/passwd", "/etc/shadow", "/etc/sudoers", "/etc/sudoers.d/*",
				"/etc/ssh/*", "/etc/ssl/*",
				// User credentials
				"~/.ssh/*", "~/.gnupg/*", "~/.aws/*", "~/.azure/*", "~/.gcp/*",
				"~/.config/gcloud/*", "~/.kube/*",
				// Application secrets
				"**/.env", "**/.env.*",
				"**/credentials.json", "**/credentials.yaml",
				"**/secrets.json", "**/secrets.yaml",
				"**/*.pem", "**/*.key", "**/*.p12", "**/*.pfx",
				"**/id_rsa", "**/id_ed25519", "**/id_ecdsa",
				// Package lock files (often should not be manually edited)
				// Note: These are high-risk, not denied, to allow legitimate updates
			},
			HighRiskPaths: []string{
				// Package manifests and lock files
				"**/package-lock.json", "**/yarn.lock", "**/pnpm-lock.yaml",
				"**/go.sum", "**/Cargo.lock", "**/Gemfile.lock",
				"**/poetry.lock", "**/composer.lock",
				// CI/CD configuration
				"**/.github/workflows/*", "**/.gitlab-ci.yml",
				"**/Jenkinsfile", "**/.circleci/*",
				// Docker and container files
				"**/Dockerfile*", "**/docker-compose*.yml",
				"**/*.dockerfile",
				// Infrastructure as code
				"**/*.tf", "**/*.tfvars",
				"**/ansible/*", "**/playbook*.yml",
			},
			WorkspaceOnly: true,
		},
	}
}

// StrictGuardrails returns highly restrictive guardrails suitable for
// untrusted or production environments.
func StrictGuardrails() *Guardrails {
	g := DefaultGuardrails()

	// Only allow a small set of safe commands
	g.Commands.AllowCommands = []string{
		"ls", "cat", "head", "tail", "less", "more",
		"grep", "find", "wc", "sort", "uniq", "diff",
		"echo", "printf", "date", "pwd", "whoami",
		"go", "npm", "yarn", "pip", "cargo", "bundle",
		"git", "make", "cmake",
	}

	// Only allow a small set of safe file extensions
	g.Files.AllowExtensions = []string{
		".go", ".js", ".ts", ".jsx", ".tsx", ".py", ".rb", ".rs",
		".java", ".kt", ".scala", ".c", ".cpp", ".h", ".hpp",
		".json", ".yaml", ".yml", ".toml", ".xml",
		".md", ".txt", ".html", ".css", ".scss",
		".sh", ".bash", ".zsh",
		".sql", ".graphql",
	}

	// Deny delete operations
	g.Files.DenyActions = []string{"delete", "execute"}

	return g
}

// PermissiveGuardrails returns minimal guardrails for trusted environments.
// Use with caution - this allows most operations.
func PermissiveGuardrails() *Guardrails {
	return &Guardrails{
		Commands: CommandGuardrails{
			DenyPatterns: []string{
				// Still block the most dangerous patterns
				`(?i)\brm\s+-rf\s+/\s*$`, // rm -rf / specifically
				`(?i):(){.*};:`,          // fork bombs
			},
			DenyCommands: []string{
				"shutdown", "reboot", "poweroff", "halt",
			},
		},
		Files: FileGuardrails{
			DenyPaths: []string{
				"/etc/shadow", "/etc/sudoers",
				"~/.ssh/id_*", "~/.gnupg/private-keys*",
			},
			WorkspaceOnly: false,
		},
	}
}

// Compile pre-compiles regex patterns for better performance.
// Call this after loading configuration and before using the guardrails.
func (g *Guardrails) Compile() error {
	if err := g.Commands.compile(); err != nil {
		return fmt.Errorf("compile command guardrails: %w", err)
	}
	if err := g.Files.compile(); err != nil {
		return fmt.Errorf("compile file guardrails: %w", err)
	}
	return nil
}

// EvalCommand evaluates whether a shell command is allowed.
func (g *Guardrails) EvalCommand(cmd string) GuardrailResult {
	// Ensure patterns are compiled
	if g.Commands.compiled == nil {
		_ = g.Commands.compile()
	}

	// Custom evaluation first (if configured)
	if g.Custom.EvalCommand != nil {
		highRisk, err := g.Custom.EvalCommand(cmd)
		if err != nil {
			return GuardrailResult{
				Allowed:  false,
				Reason:   err.Error(),
				Rule:     "custom",
				HighRisk: false,
			}
		}
		if highRisk {
			return GuardrailResult{
				Allowed:  true,
				HighRisk: true,
				Reason:   "flagged by custom rule",
				Rule:     "custom",
			}
		}
	}

	// Check deny patterns
	for i, re := range g.Commands.compiled.denyPatterns {
		if re.MatchString(cmd) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("matches deny pattern: %s", g.Commands.DenyPatterns[i]),
				Rule:    fmt.Sprintf("deny_pattern[%d]", i),
			}
		}
	}

	// Check deny commands (extract first word)
	cmdName := extractCommandName(cmd)
	for _, denied := range g.Commands.DenyCommands {
		if strings.EqualFold(cmdName, denied) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("command %q is not allowed", cmdName),
				Rule:    "deny_commands",
			}
		}
	}

	// Check allow commands (if configured)
	if len(g.Commands.AllowCommands) > 0 {
		allowed := false
		for _, a := range g.Commands.AllowCommands {
			if strings.EqualFold(cmdName, a) {
				allowed = true
				break
			}
		}
		if !allowed {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("command %q is not in allow list", cmdName),
				Rule:    "allow_commands",
			}
		}
	}

	// Check allow patterns (if configured)
	if len(g.Commands.compiled.allowPatterns) > 0 {
		matched := false
		for _, re := range g.Commands.compiled.allowPatterns {
			if re.MatchString(cmd) {
				matched = true
				break
			}
		}
		if !matched {
			return GuardrailResult{
				Allowed: false,
				Reason:  "command does not match any allow pattern",
				Rule:    "allow_patterns",
			}
		}
	}

	// Check high-risk patterns
	for i, re := range g.Commands.compiled.highRiskPatterns {
		if re.MatchString(cmd) {
			return GuardrailResult{
				Allowed:  true,
				HighRisk: true,
				Reason:   fmt.Sprintf("matches high-risk pattern: %s", g.Commands.HighRiskPatterns[i]),
				Rule:     fmt.Sprintf("high_risk_pattern[%d]", i),
			}
		}
	}

	return GuardrailResult{Allowed: true}
}

// EvalFile evaluates whether a file operation is allowed.
func (g *Guardrails) EvalFile(path, action, workDir string) GuardrailResult {
	// Ensure patterns are compiled
	if g.Files.compiled == nil {
		_ = g.Files.compile()
	}

	// Normalize path for consistent matching
	normalizedPath := normalizePath(path)

	// Custom evaluation first
	if g.Custom.EvalFile != nil {
		highRisk, err := g.Custom.EvalFile(path, action)
		if err != nil {
			return GuardrailResult{
				Allowed: false,
				Reason:  err.Error(),
				Rule:    "custom",
			}
		}
		if highRisk {
			return GuardrailResult{
				Allowed:  true,
				HighRisk: true,
				Reason:   "flagged by custom rule",
				Rule:     "custom",
			}
		}
	}

	// Check workspace restriction
	if g.Files.WorkspaceOnly && workDir != "" {
		if !isInsideWorkspace(path, workDir) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("path %q is outside workspace %q", path, workDir),
				Rule:    "workspace_only",
			}
		}
	}

	// Check deny actions
	for _, denied := range g.Files.DenyActions {
		if strings.EqualFold(action, denied) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("action %q is not allowed", action),
				Rule:    "deny_actions",
			}
		}
	}

	// Check deny paths
	for _, pattern := range g.Files.DenyPaths {
		if matchPath(normalizedPath, pattern) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("path matches deny pattern: %s", pattern),
				Rule:    "deny_paths",
			}
		}
	}

	// Check deny extensions
	ext := strings.ToLower(filepath.Ext(path))
	for _, denied := range g.Files.DenyExtensions {
		if strings.EqualFold(ext, denied) || strings.EqualFold(ext, "."+denied) {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("extension %q is not allowed", ext),
				Rule:    "deny_extensions",
			}
		}
	}

	// Check allow extensions (if configured)
	if len(g.Files.AllowExtensions) > 0 {
		allowed := false
		for _, a := range g.Files.AllowExtensions {
			if strings.EqualFold(ext, a) || strings.EqualFold(ext, "."+a) {
				allowed = true
				break
			}
		}
		if !allowed && ext != "" {
			return GuardrailResult{
				Allowed: false,
				Reason:  fmt.Sprintf("extension %q is not in allow list", ext),
				Rule:    "allow_extensions",
			}
		}
	}

	// Check allow paths (if configured)
	if len(g.Files.AllowPaths) > 0 {
		matched := false
		for _, pattern := range g.Files.AllowPaths {
			if matchPath(normalizedPath, pattern) {
				matched = true
				break
			}
		}
		if !matched {
			return GuardrailResult{
				Allowed: false,
				Reason:  "path does not match any allow pattern",
				Rule:    "allow_paths",
			}
		}
	}

	// Check high-risk paths
	for _, pattern := range g.Files.HighRiskPaths {
		if matchPath(normalizedPath, pattern) {
			return GuardrailResult{
				Allowed:  true,
				HighRisk: true,
				Reason:   fmt.Sprintf("path matches high-risk pattern: %s", pattern),
				Rule:     "high_risk_paths",
			}
		}
	}

	return GuardrailResult{Allowed: true}
}

// compiledCommandRules holds pre-compiled regex patterns.
type compiledCommandRules struct {
	denyPatterns     []*regexp.Regexp
	allowPatterns    []*regexp.Regexp
	highRiskPatterns []*regexp.Regexp
}

// compiledFileRules holds pre-compiled patterns (future use).
type compiledFileRules struct {
	// Reserved for compiled glob patterns if needed
}

func (c *CommandGuardrails) compile() error {
	c.compiled = &compiledCommandRules{}

	var err error
	c.compiled.denyPatterns, err = compilePatterns(c.DenyPatterns)
	if err != nil {
		return fmt.Errorf("deny patterns: %w", err)
	}

	c.compiled.allowPatterns, err = compilePatterns(c.AllowPatterns)
	if err != nil {
		return fmt.Errorf("allow patterns: %w", err)
	}

	c.compiled.highRiskPatterns, err = compilePatterns(c.HighRiskPatterns)
	if err != nil {
		return fmt.Errorf("high-risk patterns: %w", err)
	}

	return nil
}

func (f *FileGuardrails) compile() error {
	f.compiled = &compiledFileRules{}
	// File patterns use glob matching, not regex, so no compilation needed
	return nil
}

func compilePatterns(patterns []string) ([]*regexp.Regexp, error) {
	result := make([]*regexp.Regexp, 0, len(patterns))
	for _, p := range patterns {
		re, err := regexp.Compile(p)
		if err != nil {
			return nil, fmt.Errorf("invalid pattern %q: %w", p, err)
		}
		result = append(result, re)
	}
	return result, nil
}

// extractCommandName extracts the command name from a shell command string.
func extractCommandName(cmd string) string {
	cmd = strings.TrimSpace(cmd)

	// Skip environment variable assignments
	for strings.Contains(cmd, "=") && !strings.HasPrefix(cmd, "=") {
		parts := strings.SplitN(cmd, " ", 2)
		if len(parts) < 2 {
			break
		}
		if !strings.Contains(parts[0], "=") {
			break
		}
		cmd = strings.TrimSpace(parts[1])
	}

	// Handle common shell constructs that prefix commands
	// These need to skip their own arguments too
	prefixes := []string{"exec", "time", "nohup"}
	for _, prefix := range prefixes {
		if after, ok := strings.CutPrefix(cmd, prefix+" "); ok {
			cmd = strings.TrimSpace(after)
		}
	}

	// Handle nice with its arguments (nice [-n N] command)
	if after, ok := strings.CutPrefix(cmd, "nice "); ok {
		cmd = strings.TrimSpace(after)
		parts := strings.Fields(cmd)
		i := 0
		for i < len(parts) {
			if parts[i] == "-n" && i+1 < len(parts) {
				i += 2 // Skip -n and its argument
			} else if strings.HasPrefix(parts[i], "-") {
				i++ // Skip other nice flags
			} else {
				break
			}
		}
		if i < len(parts) {
			cmd = strings.Join(parts[i:], " ")
		}
	}

	// Get first word
	parts := strings.Fields(cmd)
	if len(parts) == 0 {
		return ""
	}

	// Handle path prefixes
	name := parts[0]
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		name = name[idx+1:]
	}

	return name
}

// normalizePath normalizes a file path for consistent matching.
func normalizePath(path string) string {
	// Expand ~ to indicate home directory pattern
	if strings.HasPrefix(path, "~/") || path == "~" {
		// Keep ~ for pattern matching, but note it
		return path
	}

	// Clean the path
	return filepath.Clean(path)
}

// matchPath checks if a path matches a glob-like pattern.
func matchPath(path, pattern string) bool {
	// Handle home directory patterns
	if strings.HasPrefix(pattern, "~/") {
		if !strings.HasPrefix(path, "~/") && !strings.Contains(path, "/.") {
			// Try to match against common home directory patterns
			pattern = strings.Replace(pattern, "~/", "**/", 1)
		}
	}

	// Handle ** glob patterns (recursive)
	if strings.Contains(pattern, "**") {
		return matchDoubleStarGlob(path, pattern)
	}

	// Standard glob matching
	matched, err := filepath.Match(pattern, path)
	if err != nil {
		return false
	}
	if matched {
		return true
	}

	// Also try matching just the filename
	base := filepath.Base(path)
	matched, _ = filepath.Match(pattern, base)
	return matched
}

// matchDoubleStarGlob handles ** glob patterns.
// ** matches any sequence of directories (including zero).
func matchDoubleStarGlob(path, pattern string) bool {
	// Split pattern by **
	parts := strings.Split(pattern, "**")
	if len(parts) == 1 {
		// No **, use standard matching
		matched, _ := filepath.Match(pattern, path)
		return matched
	}

	// Check prefix (part before **)
	prefix := strings.TrimSuffix(parts[0], "/")
	if prefix != "" {
		if !strings.HasPrefix(path, prefix) {
			return false
		}
		// Remove prefix from path for suffix matching
		path = strings.TrimPrefix(path, prefix)
		path = strings.TrimPrefix(path, "/")
	}

	// Check suffix (part after **)
	if len(parts) > 1 && parts[len(parts)-1] != "" {
		suffix := strings.TrimPrefix(parts[len(parts)-1], "/")

		// For patterns like **/.github/workflows/*, we need to check if path contains the suffix pattern
		if strings.Contains(suffix, "*") {
			// Split suffix into directory parts and glob pattern
			suffixParts := strings.Split(suffix, "/")
			globPart := suffixParts[len(suffixParts)-1]
			dirPart := strings.Join(suffixParts[:len(suffixParts)-1], "/")

			if dirPart != "" {
				// Path must contain the directory part
				if !strings.Contains(path, dirPart) {
					return false
				}
				// Get the part after dirPart for glob matching
				idx := strings.Index(path, dirPart)
				remainingPath := path[idx+len(dirPart):]
				remainingPath = strings.TrimPrefix(remainingPath, "/")

				// Match the glob against the remaining filename
				if remainingPath != "" {
					matched, _ := filepath.Match(globPart, remainingPath)
					if !matched {
						// Also try matching just the base name
						matched, _ = filepath.Match(globPart, filepath.Base(path))
					}
					return matched
				}
			} else {
				// Just a glob pattern like **/*.go
				matched, _ := filepath.Match(globPart, filepath.Base(path))
				return matched
			}
		} else {
			// No glob in suffix, check exact match
			if !strings.HasSuffix(path, suffix) && !strings.Contains(path, suffix) {
				return false
			}
		}
	}

	return true
}

// Merge combines two Guardrails configurations, with the overlay taking precedence.
// This is useful for layering project-specific rules on top of defaults.
func (g *Guardrails) Merge(overlay *Guardrails) *Guardrails {
	if overlay == nil {
		return g
	}

	result := &Guardrails{
		Commands: CommandGuardrails{
			DenyPatterns:     append(g.Commands.DenyPatterns, overlay.Commands.DenyPatterns...),
			AllowPatterns:    mergeStringSlice(g.Commands.AllowPatterns, overlay.Commands.AllowPatterns),
			HighRiskPatterns: append(g.Commands.HighRiskPatterns, overlay.Commands.HighRiskPatterns...),
			DenyCommands:     append(g.Commands.DenyCommands, overlay.Commands.DenyCommands...),
			AllowCommands:    mergeStringSlice(g.Commands.AllowCommands, overlay.Commands.AllowCommands),
		},
		Files: FileGuardrails{
			DenyPaths:       append(g.Files.DenyPaths, overlay.Files.DenyPaths...),
			AllowPaths:      mergeStringSlice(g.Files.AllowPaths, overlay.Files.AllowPaths),
			HighRiskPaths:   append(g.Files.HighRiskPaths, overlay.Files.HighRiskPaths...),
			DenyExtensions:  append(g.Files.DenyExtensions, overlay.Files.DenyExtensions...),
			AllowExtensions: mergeStringSlice(g.Files.AllowExtensions, overlay.Files.AllowExtensions),
			DenyActions:     append(g.Files.DenyActions, overlay.Files.DenyActions...),
			WorkspaceOnly:   g.Files.WorkspaceOnly || overlay.Files.WorkspaceOnly,
		},
		Network: NetworkGuardrails{
			DenyHosts:  append(g.Network.DenyHosts, overlay.Network.DenyHosts...),
			AllowHosts: mergeStringSlice(g.Network.AllowHosts, overlay.Network.AllowHosts),
			DenyPorts:  append(g.Network.DenyPorts, overlay.Network.DenyPorts...),
			AllowPorts: mergeIntSlice(g.Network.AllowPorts, overlay.Network.AllowPorts),
		},
		Custom: overlay.Custom, // Custom rules from overlay take precedence
	}

	return result
}

func mergeStringSlice(base, overlay []string) []string {
	if len(overlay) > 0 {
		return overlay // Overlay replaces base for allow lists
	}
	return base
}

func mergeIntSlice(base, overlay []int) []int {
	if len(overlay) > 0 {
		return overlay
	}
	return base
}

// GuardrailsFromConfig creates a Guardrails instance from configuration values.
// This function allows creating guardrails from config without circular imports.
//
// The preset parameter selects a base configuration:
//   - "default": sensible defaults blocking dangerous operations
//   - "strict": highly restrictive for untrusted environments
//   - "permissive": minimal restrictions for trusted environments
//
// Additional rules are merged on top of the preset.
func GuardrailsFromConfig(preset string, commands CommandGuardrails, files FileGuardrails) *Guardrails {
	var base *Guardrails

	switch strings.ToLower(preset) {
	case "strict":
		base = StrictGuardrails()
	case "permissive":
		base = PermissiveGuardrails()
	default:
		base = DefaultGuardrails()
	}

	// Merge additional rules from config
	overlay := &Guardrails{
		Commands: commands,
		Files:    files,
	}

	result := base.Merge(overlay)
	_ = result.Compile()

	return result
}

// isInsideWorkspace checks if a path is inside the workspace directory.
// It handles both absolute and relative paths correctly.
func isInsideWorkspace(path, workDir string) bool {
	// Handle empty workspace (allow all)
	if workDir == "" {
		return true
	}

	// Handle home directory references (never inside workspace)
	if strings.HasPrefix(path, "~/") || strings.HasPrefix(path, "~\\") {
		return false
	}

	// Handle absolute paths
	if filepath.IsAbs(path) {
		absWorkDir, err := filepath.Abs(workDir)
		if err != nil {
			return false
		}
		// Check if path starts with workspace
		rel, err := filepath.Rel(absWorkDir, path)
		if err != nil {
			return false
		}
		return !strings.HasPrefix(rel, "..") && rel != ".."
	}

	// For relative paths, check for parent directory traversal
	cleanPath := filepath.Clean(path)
	if strings.HasPrefix(cleanPath, "..") {
		return false
	}

	// Relative paths without .. are inside the workspace
	return true
}
