//go:build unix

package server

import (
	"context"
	"errors"
	"io"
	"os"
	"os/exec"
	"syscall"
	"testing"
	"time"
)

// TestTerminateProcessGroupOutcomes pins what the cancel hook reports for each
// state a command can be in when cancellation reaches it. The distinction that
// matters is between a group this call interrupted and one that was already
// gone: os/exec reads the first as a reason to replace a successful exit status
// with the context's error, and only os.ErrProcessDone keeps the status a
// command earned on its own.
func TestTerminateProcessGroupOutcomes(t *testing.T) {
	tests := []struct {
		name string
		// command prepares the command in the state under test, returning it
		// and a function to run once the row's assertion is done.
		command func(t *testing.T) (*exec.Cmd, func())
		// wantErr is the error the cancel hook must report, or nil.
		wantErr error
	}{
		{
			name: "command that was never started",
			command: func(t *testing.T) (*exec.Cmd, func()) {
				t.Helper()
				return exec.Command(shellPath(t), "-c", "exit 0"), func() {}
			},
		},
		{
			// The group is gone because the command completed and was reaped,
			// which is what a cancellation racing a successful exit finds.
			name: "command that already completed",
			command: func(t *testing.T) (*exec.Cmd, func()) {
				t.Helper()
				cmd := exec.Command(shellPath(t), "-c", "exit 0")
				configureProcessGroup(cmd)
				if err := cmd.Run(); err != nil {
					t.Fatalf("Run: %v", err)
				}
				return cmd, func() {}
			},
			wantErr: os.ErrProcessDone,
		},
		{
			// A group that is still there is interrupted, which is the case
			// os/exec must read as a real cancellation.
			name: "command that is still running",
			command: func(t *testing.T) (*exec.Cmd, func()) {
				t.Helper()
				cmd := exec.Command(shellPath(t), "-c", "sleep 30")
				configureProcessGroup(cmd)
				if err := cmd.Start(); err != nil {
					t.Fatalf("Start: %v", err)
				}
				return cmd, func() {
					if err := cmd.Wait(); err == nil {
						t.Error("the killed command reported success")
					}
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cmd, cleanup := tt.command(t)
			err := terminateProcessGroup(cmd)
			if tt.wantErr == nil {
				if err != nil {
					t.Fatalf("terminateProcessGroup = %v, want nil", err)
				}
			} else if !errors.Is(err, tt.wantErr) {
				t.Fatalf("terminateProcessGroup = %v, want %v", err, tt.wantErr)
			}
			cleanup()
		})
	}
}

// TestCancelErrorDecidesASuccessfulExit pins the os/exec contract the cancel
// hook is written against, since the hook's return value is only meaningful
// through it: for a command that exits successfully after cancellation, a nil
// error from Cancel makes Wait report the context's error instead of the
// success, and os.ErrProcessDone leaves the success alone. A step that ran to
// completion and mutated the workspace must not come back as timed out.
//
// The stub Cancel does not kill anything, so the ordering is fixed rather than
// raced: Cancel runs first, and only then is the command allowed to exit.
func TestCancelErrorDecidesASuccessfulExit(t *testing.T) {
	tests := []struct {
		name string
		// cancelErr is what the command's Cancel hook reports.
		cancelErr error
		// wantErr is what Wait must then report for a command that exited 0.
		wantErr error
	}{
		{
			name:    "cancel reports an interruption",
			wantErr: context.Canceled,
		},
		{
			name:      "cancel reports a process that had already finished",
			cancelErr: os.ErrProcessDone,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx, cancel := context.WithCancel(t.Context())
			defer cancel()

			// cat exits 0 as soon as its stdin is closed, which is what gives
			// the row a successful exit it controls the timing of.
			catPath, err := exec.LookPath("cat")
			if err != nil {
				t.Skipf("cat is not on PATH: %v", err)
			}
			cmd := exec.CommandContext(ctx, catPath)
			stdin, err := cmd.StdinPipe()
			if err != nil {
				t.Fatalf("StdinPipe: %v", err)
			}
			cancelled := make(chan struct{})
			cmd.Cancel = func() error {
				close(cancelled)
				return tt.cancelErr
			}
			if err := cmd.Start(); err != nil {
				t.Fatalf("Start: %v", err)
			}

			cancel()
			select {
			case <-cancelled:
			case <-time.After(10 * time.Second):
				t.Fatal("the cancel hook was never called")
			}
			if err := stdin.(io.Closer).Close(); err != nil {
				t.Fatalf("closing stdin: %v", err)
			}

			waitErr := cmd.Wait()
			if !cmd.ProcessState.Success() {
				t.Fatalf("the command did not exit successfully: %v", cmd.ProcessState)
			}
			if tt.wantErr == nil {
				if waitErr != nil {
					t.Fatalf("Wait = %v, want nil for a successful exit", waitErr)
				}
				return
			}
			if !errors.Is(waitErr, tt.wantErr) {
				t.Fatalf("Wait = %v, want %v", waitErr, tt.wantErr)
			}
		})
	}
}

// shellPath returns a shell to run test commands with, skipping the test when
// the host has none.
func shellPath(t *testing.T) string {
	t.Helper()
	path, err := exec.LookPath("sh")
	if err != nil {
		t.Skipf("sh is not on PATH: %v", err)
	}
	return path
}

// TestKillReportsESRCHForAReapedGroup pins the kernel behaviour the cancel
// hook's mapping rests on: signalling the process group of a command that
// completed and was reaped fails with ESRCH rather than succeeding. Without
// this, the mapping to os.ErrProcessDone would be asserting something the
// platform never reports.
func TestKillReportsESRCHForAReapedGroup(t *testing.T) {
	cmd := exec.Command(shellPath(t), "-c", "exit 0")
	configureProcessGroup(cmd)
	if err := cmd.Run(); err != nil {
		t.Fatalf("Run: %v", err)
	}
	// The pid was reaped by Run, so the only way this signal reaches anything
	// is a pid reused between those two statements.
	if err := syscall.Kill(-cmd.Process.Pid, syscall.SIGKILL); !errors.Is(err, syscall.ESRCH) {
		t.Fatalf("Kill on a reaped group = %v, want ESRCH", err)
	}
}
