//go:build unix

package server

import (
	"errors"
	"fmt"
	"os/exec"
	"syscall"
)

// processTreeTerminationSupported reports whether cancelling a command on
// this platform terminates every process it spawned, not just the direct
// child. Unix gets this from process groups (see configureProcessGroup),
// which is what makes an execution timeout a real upper bound on how long
// plan steps can mutate the workspace.
const processTreeTerminationSupported = true

// configureProcessGroup puts the command in its own process group so that
// cancellation can reach the whole tree it spawns. Without this, a command
// that forks (a package manager invoking a compiler or a download helper)
// leaves descendants running after the parent is killed, and those
// descendants keep writing to the workspace past the deadline.
func configureProcessGroup(cmd *exec.Cmd) {
	if cmd.SysProcAttr == nil {
		cmd.SysProcAttr = &syscall.SysProcAttr{}
	}
	cmd.SysProcAttr.Setpgid = true
}

// terminateProcessGroup kills the command's entire process group, which is
// what configureProcessGroup set up. Killing the group (negative pid) rather
// than the process is the point: the direct child is often a launcher whose
// real work happens in a grandchild. A group that is already gone is not an
// error. If the group kill fails for any other reason, the direct child is
// killed as a fallback so cancellation is never silently a no-op.
func terminateProcessGroup(cmd *exec.Cmd) error {
	proc := cmd.Process
	if proc == nil {
		return nil
	}

	err := syscall.Kill(-proc.Pid, syscall.SIGKILL)
	switch {
	case err == nil, errors.Is(err, syscall.ESRCH):
		return nil
	default:
		if killErr := proc.Kill(); killErr != nil {
			return fmt.Errorf("killing process group %d: %w (direct kill also failed: %v)", proc.Pid, err, killErr)
		}
		return fmt.Errorf("killing process group %d, killed direct child instead: %w", proc.Pid, err)
	}
}
