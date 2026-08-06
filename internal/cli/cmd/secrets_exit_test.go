package cmd

import (
	"errors"
	"fmt"
	"testing"

	deputyerrors "github.com/temporalio/deputy/internal/errors"
)

// TestSecretsExit pins the documented CI contract for `deputy secrets`:
// finding a secret must exit non-zero so a pipeline gate fails, a clean scan
// must exit 0, and scan errors must surface unchanged rather than being
// flattened into the findings signal.
func TestSecretsExit(t *testing.T) {
	scanErr := errors.New("scanning target: boom")

	tests := []struct {
		name           string
		found          int
		err            error
		alwaysExitZero bool
		wantCode       int
		wantErr        error // non-nil means the exact error must pass through
		// wantSilent asserts the CLI suppresses printing, because the
		// findings were already rendered to the user.
		wantSilent bool
	}{
		{
			name:     "clean scan exits zero",
			found:    0,
			wantCode: 0,
		},
		{
			name:       "findings exit one silently",
			found:      1,
			wantCode:   1,
			wantSilent: true,
		},
		{
			name:       "many findings still exit one",
			found:      42,
			wantCode:   1,
			wantSilent: true,
		},
		{
			name:           "always-exit-zero suppresses the findings exit",
			found:          7,
			alwaysExitZero: true,
			wantCode:       0,
		},
		{
			name:     "scan error propagates unchanged",
			found:    0,
			err:      scanErr,
			wantCode: 1,
			wantErr:  scanErr,
		},
		{
			name: "scan error wins over findings",
			// A partial scan that both found secrets and failed must report
			// the failure: exiting on the findings alone would imply the scan
			// completed.
			found:    3,
			err:      scanErr,
			wantCode: 1,
			wantErr:  scanErr,
		},
		{
			name:           "scan error is not suppressed by always-exit-zero",
			found:          0,
			err:            scanErr,
			alwaysExitZero: true,
			wantCode:       1,
			wantErr:        scanErr,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := secretsExit(tt.found, tt.err, tt.alwaysExitZero)

			if code := deputyerrors.ExitCode(got); code != tt.wantCode {
				t.Errorf("ExitCode = %d, want %d (err %v)", code, tt.wantCode, got)
			}

			if tt.wantErr != nil {
				if !errors.Is(got, tt.wantErr) {
					t.Errorf("error = %v, want it to wrap %v", got, tt.wantErr)
				}
				return
			}

			if tt.wantCode == 0 && got != nil {
				t.Errorf("expected nil error for a zero exit, got %v", got)
			}

			if tt.wantSilent {
				var silent *deputyerrors.SilentError
				if !errors.As(got, &silent) {
					t.Errorf("findings exit must be silent so the CLI does not print over the report, got %#v", got)
				}
			}
		})
	}
}

// TestSecretsExit_FindingsExitCarriesNoCause guards the user-visible result of
// a findings exit: the process fails, but nothing extra is printed after the
// rendered report. The CLI suppresses printing for SilentError, and the exit
// wraps no underlying failure, so there is no diagnostic to lose.
func TestSecretsExit_FindingsExitCarriesNoCause(t *testing.T) {
	err := secretsExit(1, nil, false)
	if err == nil {
		t.Fatal("expected a non-nil error to carry the exit code")
	}

	var silent *deputyerrors.SilentError
	if !errors.As(err, &silent) {
		t.Fatalf("findings exit must be silent, got %#v", err)
	}

	var exit *deputyerrors.ExitError
	if !errors.As(err, &exit) {
		t.Fatalf("findings exit must carry an exit code, got %#v", err)
	}
	if exit.Cause != nil {
		t.Errorf("findings exit should signal only, wrapping no error; got cause %v", exit.Cause)
	}
}

// TestSecretsExit_WrappedErrorKeepsCustomExitCode verifies the helper does not
// clobber an exit code a scan path already chose.
func TestSecretsExit_WrappedErrorKeepsCustomExitCode(t *testing.T) {
	custom := deputyerrors.WithExitCode(fmt.Errorf("interrupted"), 130)
	got := secretsExit(5, custom, false)
	if code := deputyerrors.ExitCode(got); code != 130 {
		t.Errorf("ExitCode = %d, want 130 (the scan's own code must win)", code)
	}
}
