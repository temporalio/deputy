package cli

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"sync"
	"testing"
)

// recordingServer starts an httptest server that records the path and
// Authorization header of every request and fails each RPC with a 500 so
// commands return quickly. The returned func snapshots the recorded requests.
func recordingServer(t *testing.T) (*httptest.Server, func() []recordedRequest) {
	t.Helper()
	var mu sync.Mutex
	var got []recordedRequest
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		got = append(got, recordedRequest{path: r.URL.Path, auth: r.Header.Get("Authorization")})
		mu.Unlock()
		http.Error(w, "recording test server: no handler", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	return srv, func() []recordedRequest {
		mu.Lock()
		defer mu.Unlock()
		out := make([]recordedRequest, len(got))
		copy(out, got)
		return out
	}
}

// recordedRequest captures the parts of an inbound RPC the root flag tests
// assert on.
type recordedRequest struct {
	path string
	auth string
}

// chdirToGoModFixture moves the test into a temp dir containing a minimal Go
// module so the list command has a real local target to enumerate when the
// in-process path is (wrongly) taken.
func chdirToGoModFixture(t *testing.T) {
	t.Helper()
	dir := t.TempDir()
	gomod := "module example.com/fixture\n\ngo 1.22\n"
	if err := os.WriteFile(filepath.Join(dir, "go.mod"), []byte(gomod), 0o644); err != nil {
		t.Fatalf("write go.mod fixture: %v", err)
	}
	t.Chdir(dir)
}

// executeRoot builds the root command and runs it with args, discarding
// output. The returned error is the command error, which the routing tests
// ignore: they assert on where the RPC landed, not on the RPC succeeding.
func executeRoot(t *testing.T, args ...string) error {
	t.Helper()
	root := newRoot()
	root.SetArgs(args)
	root.SetOut(io.Discard)
	root.SetErr(io.Discard)
	return root.ExecuteContext(context.Background())
}

// TestRootServerFlagRoutesRemote proves the --server and --auth-token
// persistent flags reach client construction: the command must take the
// remote path and send its RPC, with the bearer token attached, to the
// flag-provided address instead of running in-process against the local
// filesystem.
func TestRootServerFlagRoutesRemote(t *testing.T) {
	t.Setenv("DEPUTY_SERVER", "")
	t.Setenv("DEPUTY_AUTH_TOKEN", "")

	srv, requests := recordingServer(t)
	chdirToGoModFixture(t)

	// The RPC fails by design (the recording server returns 500); only the
	// routing matters here.
	_ = executeRoot(t, "--server", srv.URL, "--auth-token", "test-token", "list")

	got := requests()
	if len(got) == 0 {
		t.Fatal("no request reached the --server address; the flag was ignored and the command ran in-process")
	}
	if want := "Bearer test-token"; got[0].auth != want {
		t.Errorf("Authorization = %q, want %q; the --auth-token flag did not reach the client", got[0].auth, want)
	}
}

// TestRootAuthTokenFlagClearsEnvToken pins the explicit-empty contract for
// credentials: --auth-token= (set to an empty value) must clear a token
// coming from DEPUTY_AUTH_TOKEN, so no Authorization header leaks to the
// selected server.
func TestRootAuthTokenFlagClearsEnvToken(t *testing.T) {
	t.Setenv("DEPUTY_SERVER", "")
	t.Setenv("DEPUTY_AUTH_TOKEN", "env-secret")

	srv, requests := recordingServer(t)
	chdirToGoModFixture(t)

	_ = executeRoot(t, "--server", srv.URL, "--auth-token=", "list")

	got := requests()
	if len(got) == 0 {
		t.Fatal("no request reached the --server address")
	}
	if got[0].auth != "" {
		t.Errorf("Authorization = %q, want empty; explicit --auth-token= must clear the env token", got[0].auth)
	}
}

// TestRootServerFlagEmptyForcesInProcess pins the explicit-empty contract for
// the server address: --server= (set to an empty value) beats DEPUTY_SERVER
// by the same flag-first rule and selects the in-process default, so nothing
// is sent to the env-configured server.
func TestRootServerFlagEmptyForcesInProcess(t *testing.T) {
	t.Setenv("DEPUTY_AUTH_TOKEN", "")

	envSrv, envRequests := recordingServer(t)
	t.Setenv("DEPUTY_SERVER", envSrv.URL)
	chdirToGoModFixture(t)

	if err := executeRoot(t, "--server=", "list"); err != nil {
		t.Errorf("in-process list failed: %v", err)
	}
	if got := envRequests(); len(got) != 0 {
		t.Errorf("DEPUTY_SERVER address received %d request(s); explicit --server= must force in-process mode", len(got))
	}
}

// TestRootServerFlagBeatsEnv pins the precedence contract: an explicit
// --server flag wins over the DEPUTY_SERVER environment variable.
func TestRootServerFlagBeatsEnv(t *testing.T) {
	t.Setenv("DEPUTY_AUTH_TOKEN", "")

	flagSrv, flagRequests := recordingServer(t)
	envSrv, envRequests := recordingServer(t)
	t.Setenv("DEPUTY_SERVER", envSrv.URL)
	chdirToGoModFixture(t)

	_ = executeRoot(t, "--server", flagSrv.URL, "list")

	if got := flagRequests(); len(got) == 0 {
		t.Error("no request reached the --server address; the flag lost to DEPUTY_SERVER")
	}
	if got := envRequests(); len(got) != 0 {
		t.Errorf("DEPUTY_SERVER address received %d request(s); the env var should lose to the --server flag", len(got))
	}
}
