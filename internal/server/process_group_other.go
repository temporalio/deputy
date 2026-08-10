//go:build !unix

package server

import "os/exec"

// processTreeTerminationSupported reports whether cancelling a command on
// this platform terminates every process it spawned. It is false outside
// unix: process groups are a unix concept, and the Windows equivalent (a job
// object with JOB_OBJECT_LIMIT_KILL_ON_JOB_CLOSE, created suspended and
// assigned before the main thread resumes) cannot be built on os/exec, which
// does not expose the child's thread handle needed to resume it.
//
// ExecutePlan refuses to spawn external commands when this is false rather
// than running them under a weaker guarantee. An execution timeout that
// bounds only the direct child is not a timeout: descendants keep mutating
// the workspace after the deadline, which is precisely the failure the
// timeout exists to prevent. Deputy-internal commands still run on these
// platforms, since they apply file edits in process and are bounded by the
// context directly.
const processTreeTerminationSupported = false

// configureProcessGroup is a no-op outside unix. Commands are not spawned on
// these platforms (see processTreeTerminationSupported), so there is no
// process group to establish.
func configureProcessGroup(*exec.Cmd) {}

// terminateProcessGroup kills the direct child. It exists to keep the
// platform API symmetric and is unreachable while external command execution
// is refused on these platforms.
func terminateProcessGroup(cmd *exec.Cmd) error {
	if cmd.Process == nil {
		return nil
	}
	return cmd.Process.Kill()
}
