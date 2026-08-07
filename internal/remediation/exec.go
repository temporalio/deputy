package remediation

import (
	"fmt"
	"path/filepath"
	"slices"
	"strings"
)

// ExecArgs returns the executable args for a remediation command.
// It validates the executable against the manager allowlist before returning.
func ExecArgs(cmd Command) ([]string, error) {
	if !cmd.Executable {
		return nil, fmt.Errorf("command is not executable")
	}
	if IsDeputyInternalCommand(cmd.Command) {
		return nil, fmt.Errorf("deputy internal command must be handled separately")
	}

	args := cmd.Args
	if len(args) == 0 {
		parsed, err := ParseCommandArgs(cmd.Command)
		if err != nil {
			return nil, err
		}
		args = parsed
	}

	if err := ValidateExecutable(cmd.Manager, args); err != nil {
		return nil, err
	}

	return args, nil
}

// ParseCommandArgs splits a command string into args without invoking a shell.
// It supports basic quoting with single/double quotes and backslash escaping.
func ParseCommandArgs(command string) ([]string, error) {
	trimmed := strings.TrimSpace(command)
	if trimmed == "" {
		return nil, fmt.Errorf("empty command")
	}
	if strings.ContainsAny(trimmed, "\x00\r\n") {
		return nil, fmt.Errorf("command contains invalid control characters")
	}

	var (
		args     []string
		current  strings.Builder
		inSingle bool
		inDouble bool
		escaped  bool
	)

	flush := func() {
		if current.Len() > 0 {
			args = append(args, current.String())
			current.Reset()
		}
	}

	for i := 0; i < len(trimmed); i++ {
		ch := trimmed[i]

		if escaped {
			current.WriteByte(ch)
			escaped = false
			continue
		}

		if ch == '\\' && !inSingle {
			escaped = true
			continue
		}

		if ch == '\'' && !inDouble {
			inSingle = !inSingle
			continue
		}
		if ch == '"' && !inSingle {
			inDouble = !inDouble
			continue
		}

		if (ch == ' ' || ch == '\t') && !inSingle && !inDouble {
			flush()
			continue
		}

		current.WriteByte(ch)
	}

	if escaped {
		return nil, fmt.Errorf("unfinished escape sequence")
	}
	if inSingle || inDouble {
		return nil, fmt.Errorf("unterminated quoted string")
	}

	flush()

	if len(args) == 0 {
		return nil, fmt.Errorf("empty command")
	}
	return args, nil
}

// ValidateExecutable enforces manager-specific command allowlists.
func ValidateExecutable(manager string, args []string) error {
	if len(args) == 0 {
		return fmt.Errorf("missing executable")
	}

	manager = strings.ToLower(strings.TrimSpace(manager))
	if manager == "" {
		return fmt.Errorf("missing manager for executable command")
	}

	executable := strings.ToLower(filepath.Base(args[0]))
	allowed := managerExecutables[manager]
	if len(allowed) == 0 {
		return fmt.Errorf("unknown manager %q for executable %q", manager, executable)
	}

	if slices.Contains(allowed, executable) {
		return nil
	}

	return fmt.Errorf("executable %q not allowed for manager %q", executable, manager)
}

// managerExecutables is the execution allowlist: for each manager string the
// remediation generator can emit, the executables its commands (and follow-ups)
// are permitted to invoke. A manager that generates executable commands but has
// no entry here produces fixes deputy can never apply, so keep this in sync
// with recommendCommand (TestManagerExecutablesCoverGeneratedCommands enforces
// the pairing).
var managerExecutables = map[string][]string{
	"go":        {"go"},
	"mise":      {"mise"},
	"npm":       {"npm"},
	"yarn":      {"yarn"},
	"pnpm":      {"pnpm"},
	"pip":       {"pip"},
	"pipenv":    {"pipenv"},
	"poetry":    {"poetry"},
	"uv":        {"uv"},
	"pdm":       {"pdm"},
	"conda":     {"conda"},
	"gem":       {"bundle", "gem"},
	"bundler":   {"bundle"},
	"composer":  {"composer"},
	"cargo":     {"cargo"},
	"maven":     {"mvn"},
	"gradle":    {"gradlew", "gradle"},
	"nuget":     {"dotnet"},
	"dotnet":    {"dotnet"},
	"hex":       {"mix"},
	"mix":       {"mix"},
	"pub":       {"dart"},
	"dart":      {"dart"},
	"flutter":   {"dart"},
	"cocoapods": {"pod"},
	"pod":       {"pod"},
	"renv":      {"rscript"},
	"conan":     {"conan"},
}
