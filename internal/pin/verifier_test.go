package pin

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestVerifier_SignedOnBranch(t *testing.T) {
	sha := "11bd71901bbe5b1630ceea73d27597364c9af683"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    sha,
			"author": map[string]any{"name": "GitHub"},
			"verification": map[string]any{
				"verified":  true,
				"reason":    "valid",
				"signature": "-----BEGIN PGP SIGNATURE-----",
			},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "behind", "ahead_by": 0, "behind_by": 5,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	verifier := NewVerifier(client)

	v, err := verifier.Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}
	if !v.SignatureValid {
		t.Error("expected SignatureValid=true")
	}
	if !v.OnBranch {
		t.Error("expected OnBranch=true")
	}
	if v.IsForkCommit {
		t.Error("expected IsForkCommit=false")
	}
	if len(v.Warnings) > 0 {
		t.Errorf("expected no warnings, got %v", v.Warnings)
	}
}

func TestVerifier_UnsignedNotOnBranch(t *testing.T) {
	sha := "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    sha,
			"author": map[string]any{"name": "attacker"},
			"verification": map[string]any{
				"verified": false, "reason": "unsigned", "signature": "",
			},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "diverged", "ahead_by": 1, "behind_by": 100,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	verifier := NewVerifier(client)

	v, err := verifier.Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}
	if v.SignatureValid {
		t.Error("expected SignatureValid=false")
	}
	if v.OnBranch {
		t.Error("expected OnBranch=false")
	}
	if !v.IsForkCommit {
		t.Error("expected IsForkCommit=true (unsigned + not on branch)")
	}
	if len(v.Warnings) == 0 {
		t.Error("expected warnings")
	}
}

func TestVerifier_CommitNotFound(t *testing.T) {
	sha := "deadbeefdeadbeefdeadbeefdeadbeefdeadbeef"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprint(w, `{"message":"Not Found"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	verifier := NewVerifier(client)

	v, err := verifier.Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsForkCommit {
		t.Error("expected IsForkCommit=true for not-found commit")
	}
}

func TestVerifier_CompareNotFound(t *testing.T) {
	sha := "abcdef1234567890abcdef1234567890abcdef12"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"author":       map[string]any{"name": "unknown"},
			"verification": map[string]any{"verified": false, "reason": "unsigned"},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, r *http.Request) {
		// Return 404 if the path contains our test SHA (simulating unreachable commit)
		if strings.Contains(r.URL.Path, sha[:12]) {
			w.WriteHeader(http.StatusNotFound)
			fmt.Fprint(w, `{"message":"Not Found"}`)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"status": "behind"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	verifier := NewVerifier(client)

	v, err := verifier.Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}
	if !v.IsForkCommit {
		t.Error("expected IsForkCommit=true when compare returns 404")
	}
}

func TestVerifier_AheadOfBranch(t *testing.T) {
	sha := "aabbccddaabbccddaabbccddaabbccddaabbccdd"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    sha,
			"author": map[string]any{"name": "maintainer"},
			"verification": map[string]any{
				"verified":  true,
				"reason":    "valid",
				"signature": "-----BEGIN PGP SIGNATURE-----",
			},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ahead", "ahead_by": 3, "behind_by": 0,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v, err := NewVerifier(client).Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}
	// Ahead + signed = not fork, but has warnings
	if v.IsForkCommit {
		t.Error("signed commit ahead of branch should not be flagged as fork")
	}
	if v.OnBranch {
		t.Error("ahead commit should not be marked as on-branch")
	}
	if len(v.Warnings) == 0 {
		t.Error("expected warning about being ahead")
	}
}

func TestVerifier_ImposterHeuristic(t *testing.T) {
	// The exact pattern of TeamPCP imposter commits:
	// unsigned + not on default branch = flagged as possible imposter
	sha := "70379aad1a8b40919ce8b382d3cd7d0315cde1d0"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"author":       map[string]any{"name": "attacker-spoofed-name"},
			"verification": map[string]any{"verified": false, "reason": "unsigned"},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ahead", "ahead_by": 1, "behind_by": 50,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v, err := NewVerifier(client).Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}

	if !v.IsForkCommit {
		t.Error("unsigned commit not on default branch should be flagged as possible imposter")
	}
	if v.SignatureValid {
		t.Error("expected SignatureValid=false")
	}

	// Should have specific warning about imposter
	found := false
	for _, w := range v.Warnings {
		if strings.Contains(w, "imposter") {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("expected imposter warning, got warnings: %v", v.Warnings)
	}
}

func TestVerifier_SignedButAhead_NotFlagged(t *testing.T) {
	// A signed commit ahead of the default branch is NOT suspicious —
	// this is normal for release tags on feature branches.
	sha := "1122334455667788990011223344556677889900"

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/git/commits/"+sha, func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    sha,
			"author": map[string]any{"name": "maintainer"},
			"verification": map[string]any{
				"verified":  true,
				"reason":    "valid",
				"signature": "-----BEGIN PGP SIGNATURE-----",
			},
		})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("GET /api/v3/repos/actions/checkout/compare/", func(w http.ResponseWriter, _ *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "ahead", "ahead_by": 5, "behind_by": 0,
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v, err := NewVerifier(client).Verify(context.Background(), "actions", "checkout", sha)
	if err != nil {
		t.Fatal(err)
	}

	if v.IsForkCommit {
		t.Error("signed commit ahead of branch should NOT be flagged as fork — this differentiates from the imposter heuristic")
	}
}
