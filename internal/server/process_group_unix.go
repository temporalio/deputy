//go:build unix

package server

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"syscall"
)

// processTreeTerminationSupported reports whether cancelling a command on
// this platform terminates the processes it spawned, not just the direct
// child. Unix gets this from process groups (see configureProcessGroup),
// which is what makes an execution timeout a real upper bound on how long
// plan steps can mutate the workspace.
//
// The guarantee covers every descendant that remains in the command's process
// group, which is every descendant a package manager normally produces. It is
// not absolute: a descendant that leaves the group on purpose, by calling
// setsid or otherwise changing its process group, is no longer reachable by
// the group kill and survives it. Tracking those is a separate problem
// (cgroups, a subreaper, or a job-style container) and is not attempted here.
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
// real work happens in a grandchild. If the group kill fails for any reason
// other than the group being gone, the direct child is killed as a fallback so
// cancellation is never silently a no-op.
//
// A group that is already gone reports os.ErrProcessDone rather than success,
// because this runs as [exec.Cmd.Cancel] and os/exec reads the two differently.
// Success there means the command was interrupted, so os/exec replaces a
// successful exit status with the context's error; ErrProcessDone means the
// command had already finished and os/exec keeps the status it earned. A kill
// racing a command that completed on its own returns ESRCH once the child has
// been reaped, and calling that an interruption reported a step that ran to
// completion and mutated the workspace as timed out, which skips every step
// depending on it.
//
// ESRCH also covers a direct child that left the group on purpose, which is
// outside the guarantee processTreeTerminationSupported states. Reporting the
// command as already finished is still the safer reading: [exec.Cmd.WaitDelay]
// is set on these commands, so os/exec kills the child itself once the delay
// elapses, and a child killed that way exits unsuccessfully rather than being
// mistaken for a step that completed.
func terminateProcessGroup(cmd *exec.Cmd) error {
	proc := cmd.Process
	if proc == nil {
		return nil
	}

	err := syscall.Kill(-proc.Pid, syscall.SIGKILL)
	switch {
	case err == nil:
		return nil
	case errors.Is(err, syscall.ESRCH):
		return os.ErrProcessDone
	default:
		if killErr := proc.Kill(); killErr != nil {
			return fmt.Errorf("killing process group %d: %w (direct kill also failed: %v)", proc.Pid, err, killErr)
		}
		return fmt.Errorf("killing process group %d, killed direct child instead: %w", proc.Pid, err)
	}
}
