package cmd

import (
	"context"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"

	"connectrpc.com/connect"
	"github.com/spf13/cobra"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/internal/services"
)

// connectionProbe is a recording server standing in for a Deputy endpoint. It
// fails every RPC so calls return immediately: the tests assert on whether a
// request arrived and what it carried, never on a successful response.
type connectionProbe struct {
	url string

	mu    sync.Mutex
	calls int
	auth  string
}

// newConnectionProbe starts a probe server bound to the test lifetime.
func newConnectionProbe(t *testing.T) *connectionProbe {
	t.Helper()
	p := &connectionProbe{}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p.mu.Lock()
		p.calls++
		p.auth = r.Header.Get("Authorization")
		p.mu.Unlock()
		http.Error(w, "probe: no handler", http.StatusInternalServerError)
	}))
	t.Cleanup(srv.Close)
	p.url = srv.URL
	return p
}

// observed reports how many requests reached the probe and the Authorization
// header of the most recent one.
func (p *connectionProbe) observed() (int, string) {
	p.mu.Lock()
	defer p.mu.Unlock()
	return p.calls, p.auth
}

// callThrough issues the cheapest available RPC through the given clients so
// the test can see which endpoint the captured pointer is wired to. The error
// is intentionally ignored: the probe always fails the call.
func callThrough(t *testing.T, clients *services.Clients) {
	t.Helper()
	_, _ = clients.Packages.ListEcosystems(context.Background(), connect.NewRequest(&listv1.ListEcosystemsRequest{}))
}

// TestApplyConnectionKeepsClientsPointer pins the pointer-identity contract
// that makes the root --server and --auth-token flags work.
//
// RegisterCommands passes deps.Clients into every AddXCommand, so each command
// closure captures that pointer while flags are still unparsed. ApplyConnection
// then runs from PersistentPreRunE, after parsing. If it rebound the field
// (d.Clients = clients) instead of copying through it, the already-registered
// commands would keep talking to the pre-flag endpoint and the flags would be
// silently ignored. This test captures the pointer the way a command does and
// asserts it observes the post-parse configuration.
func TestApplyConnectionKeepsClientsPointer(t *testing.T) {
	tests := []struct {
		name string
		// apply mutates the connection settings the way PersistentPreRunE
		// does once the flags are known.
		apply    func(d *Dependencies, next *connectionProbe)
		wantAuth string
	}{
		{
			name: "server address change reaches captured clients",
			apply: func(d *Dependencies, next *connectionProbe) {
				d.ServerAddress = next.url
			},
			// AuthToken is untouched here, so the registration-time token
			// rides along to the new address.
			wantAuth: "Bearer registration-token",
		},
		{
			name: "auth token added after registration reaches captured clients",
			apply: func(d *Dependencies, next *connectionProbe) {
				d.ServerAddress = next.url
				d.AuthToken = "flag-token"
			},
			wantAuth: "Bearer flag-token",
		},
		{
			name: "auth token cleared after registration reaches captured clients",
			apply: func(d *Dependencies, next *connectionProbe) {
				d.ServerAddress = next.url
				d.AuthToken = ""
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			initial := newConnectionProbe(t)
			next := newConnectionProbe(t)

			// Registration-time state: clients already built from the
			// pre-flag settings, exactly as RegisterCommands leaves them.
			deps := &Dependencies{ServerAddress: initial.url, AuthToken: "registration-token"}
			if err := deps.ApplyConnection(); err != nil {
				t.Fatalf("build registration-time clients: %v", err)
			}
			RegisterCommands(&cobra.Command{Use: "root"}, deps)

			// What every command closure holds from here on.
			captured := deps.Clients

			test.apply(deps, next)
			if err := deps.ApplyConnection(); err != nil {
				t.Fatalf("re-apply connection: %v", err)
			}

			if deps.Clients != captured {
				t.Fatalf("ApplyConnection rebound Dependencies.Clients to a new pointer; " +
					"commands registered before flag parsing still hold the old one, so " +
					"--server and --auth-token would be silently ignored")
			}

			callThrough(t, captured)

			if calls, _ := initial.observed(); calls != 0 {
				t.Errorf("registration-time endpoint received %d request(s); the captured clients did not observe the new configuration", calls)
			}
			calls, auth := next.observed()
			if calls == 0 {
				t.Fatal("post-parse endpoint received no request; the captured clients did not observe the new configuration")
			}
			if auth != test.wantAuth {
				t.Errorf("Authorization = %q, want %q", auth, test.wantAuth)
			}
		})
	}
}
