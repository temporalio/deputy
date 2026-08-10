//go:build !unix

package server

import "os/exec"

// configureProcessGroup is a no-op outside unix.
//
// PLATFORM CAVEAT: process group semantics are unix specific. Windows would
// need a job object to get the equivalent tree-wide termination, which is not
// implemented here, so on non-unix platforms an execution timeout bounds only
// the direct child process: descendants it spawned may outlive the deadline.
func configureProcessGroup(*exec.Cmd) {}

// terminateProcessGroup kills the direct child, the only termination
// guarantee available without the platform-specific job control described in
// configureProcessGroup.
func terminateProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
