package cmd

import (
	"bufio"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/charmbracelet/lipgloss"
	sandboxv1 "github.com/temporalio/deputy/gen/deputy/sandbox/v1"
	"github.com/temporalio/deputy/internal/sandbox"
	"github.com/temporalio/deputy/internal/ui"
	"golang.org/x/term"
)

// Exec confirmation styles - uses shared styles from internal/ui/style.go where possible.
// Only defines styles that are specific to the confirmation box rendering.
var (
	// execBoxBorder uses the dim color for subtle box borders
	execBoxBorder = ui.StyleDim

	// execWarningIcon uses amber for warning indicators (matches StyleStatusWarning)
	execWarningIcon = ui.StyleStatusWarning.Bold(true)

	// execWarningTitle uses neutral bold white for warning text
	execWarningTitle = ui.StyleNeutral
)

// Unicode box drawing characters (no emojis, per Deputy style)
const (
	boxTopLeft     = "╭"
	boxTopRight    = "╮"
	boxBottomLeft  = "╰"
	boxBottomRight = "╯"
	boxHorizontal  = "─"
	boxVertical    = "│"
	boxTeeLeft     = "├"
	boxTeeRight    = "┤"
	boxBullet      = "•"
)

// execConfirmationRequired returns true if the given configuration requires
// user confirmation before proceeding.
func execConfirmationRequired(mode sandboxv1.Mode, network sandboxv1.NetworkMode, command []string) bool {
	// Safe commands (read-only like ls, cat, head) never require confirmation
	// even in permissive modes - they can't cause harm
	if sandbox.IsSafeCommand(command) {
		return false
	}
	// Full filesystem access is dangerous
	if mode == sandboxv1.Mode_MODE_FULL_ACCESS {
		return true
	}
	// Host network access is dangerous
	if network == sandboxv1.NetworkMode_NETWORK_MODE_HOST {
		return true
	}
	// Dangerous commands require confirmation even in safe modes
	if sandbox.IsDangerousCommand(command) {
		return true
	}
	return false
}

// execConfirmationInfo holds information for building a confirmation prompt.
type execConfirmationInfo struct {
	Mode        sandboxv1.Mode
	NetworkMode sandboxv1.NetworkMode
	Command     []string
	Workspace   string
}

// confirmExecDangerousMode prompts the user to confirm a dangerous sandbox configuration.
// Returns true if the user confirms, false otherwise.
// If stdin is not a terminal, returns false (non-interactive mode should use --dangerously-skip-prompt).
func confirmExecDangerousMode(info execConfirmationInfo, stdin io.Reader, stdout, stderr io.Writer) bool {
	// Check if stdin is a terminal
	if f, ok := stdin.(*os.File); ok {
		if !term.IsTerminal(int(f.Fd())) {
			fmt.Fprintln(stderr, "Error: dangerous mode requires confirmation but stdin is not a terminal")
			fmt.Fprintln(stderr, "Use --dangerously-skip-prompt to skip confirmation in non-interactive mode")
			return false
		}
	}

	// Render the confirmation box
	renderExecConfirmationBox(info, stdout)

	// Prompt for confirmation
	fmt.Fprint(stdout, "Continue? [y/N]: ")

	reader := bufio.NewReader(stdin)
	response, err := reader.ReadString('\n')
	if err != nil {
		return false
	}

	response = strings.TrimSpace(strings.ToLower(response))
	return response == "y" || response == "yes"
}

// renderExecConfirmationBox renders a styled confirmation box to stdout.
func renderExecConfirmationBox(info execConfirmationInfo, w io.Writer) {
	boxWidth := 61 // Inner width of the box

	// Helper to create a horizontal line
	hline := func(left, right string) string {
		return execBoxBorder.Render(left + strings.Repeat(boxHorizontal, boxWidth) + right)
	}

	// Helper to create a padded content line
	line := func(content string) string {
		// Calculate visible width (accounting for ANSI codes)
		plainLen := lipgloss.Width(content)
		padding := max(0, boxWidth-plainLen-2) // -2 for spaces on each side
		return execBoxBorder.Render(boxVertical) + " " + content + strings.Repeat(" ", padding) + " " + execBoxBorder.Render(boxVertical)
	}

	// Determine the warning message based on mode and command safety
	var warningTitle string
	var warningPoints []string
	var alternatives []string

	// Check command safety first (may override mode-based warnings)
	cmdSafety := sandbox.ClassifyCommand(info.Command)
	cmdReason := sandbox.CommandSafetyReason(info.Command)

	if info.Mode == sandboxv1.Mode_MODE_FULL_ACCESS {
		warningTitle = "Warning: Full filesystem access requested"
		warningPoints = []string{
			"Read and write ANY file on your system",
			"Access files outside the workspace",
			"Modify system configuration",
		}
		alternatives = []string{
			"--mode workspace-write (access workspace only)",
			"Copy needed files into workspace first",
		}
	} else if info.NetworkMode == sandboxv1.NetworkMode_NETWORK_MODE_HOST {
		warningTitle = "Warning: Host network access requested"
		warningPoints = []string{
			"Connect to any network host",
			"Access local network services",
			"Potentially exfiltrate data",
		}
		alternatives = []string{
			"--network allowlist --network-allow <host:port>",
			"--network none (no network access)",
		}
	} else if cmdSafety == sandbox.CommandDangerous {
		warningTitle = "Warning: Dangerous command detected"
		warningPoints = []string{
			"This command may cause irreversible changes",
			"Reason: " + cmdReason,
		}
		alternatives = []string{
			"Review the command carefully before proceeding",
			"Consider using a safer alternative",
		}
	}

	// Build command display (truncate if too long)
	commandStr := strings.Join(info.Command, " ")
	maxCmdLen := boxWidth - 12 // "Command: " + some padding
	if len(commandStr) > maxCmdLen {
		commandStr = commandStr[:maxCmdLen-3] + "..."
	}

	// Build workspace display (truncate if too long)
	workspaceStr := info.Workspace
	if workspaceStr == "" {
		workspaceStr = "(none)"
	}
	maxWsLen := boxWidth - 14 // "Workspace: " + some padding
	if len(workspaceStr) > maxWsLen {
		workspaceStr = "..." + workspaceStr[len(workspaceStr)-maxWsLen+3:]
	}

	// Print the box
	fmt.Fprintln(w)
	fmt.Fprintln(w, hline(boxTopLeft, boxTopRight))
	fmt.Fprintln(w, line(execWarningIcon.Render("!")+" "+execWarningTitle.Render(warningTitle)))
	fmt.Fprintln(w, hline(boxTeeLeft, boxTeeRight))
	fmt.Fprintln(w, line(""))
	fmt.Fprintln(w, line("This mode allows the command to:"))

	for _, point := range warningPoints {
		fmt.Fprintln(w, line("  "+ui.StyleDim.Render(boxBullet)+" "+point))
	}

	fmt.Fprintln(w, line(""))
	fmt.Fprintln(w, line("Command: "+ui.StylePolicyFile.Render(commandStr)))
	fmt.Fprintln(w, line("Workspace: "+ui.StylePath.Render(workspaceStr)))
	fmt.Fprintln(w, line(""))
	fmt.Fprintln(w, line(ui.StyleMeta.Render("Consider safer alternatives:")))

	for _, alt := range alternatives {
		fmt.Fprintln(w, line("  "+ui.StyleDim.Render(boxBullet)+" "+ui.StyleManager.Render(alt)))
	}

	fmt.Fprintln(w, line(""))
	fmt.Fprintln(w, hline(boxBottomLeft, boxBottomRight))
	fmt.Fprintln(w)
}
