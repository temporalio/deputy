package githubactions

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"testing"
)

func TestVerifier_SignedCommit(t *testing.T) {
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha": sha,
			"verification": map[string]any{
				"verified":  true,
				"signature": "-----BEGIN PGP SIGNATURE-----",
				"reason":    "valid",
			},
			"author": map[string]any{
				"name": "Test Author",
			},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"default_branch": "main",
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/compare/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"status": "behind",
		})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(context.Background(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	if !result.Signed {
		t.Error("expected signed")
	}
	if !result.SignatureValid {
		t.Error("expected valid signature")
	}
	if !result.OnBranch {
		t.Error("expected on branch")
	}
	if result.IsForkCommit {
		t.Error("expected not fork commit")
	}
}

func TestVerifier_UnsignedCommit(t *testing.T) {
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"verification": map[string]any{"verified": false},
			"author":       map[string]any{"name": "Unknown"},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/compare/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "behind"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(context.Background(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	if result.Signed {
		t.Error("expected unsigned")
	}
}

func TestVerifier_NotFound(t *testing.T) {
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"message":"Not Found"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(context.Background(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	if !result.IsForkCommit {
		t.Error("expected fork commit for 404")
	}
}

func TestVerifier_BranchNotReachable(t *testing.T) {
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"verification": map[string]any{"verified": false},
			"author":       map[string]any{"name": "Suspicious"},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/compare/", func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"message":"Not Found"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(context.Background(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	if !result.IsForkCommit {
		t.Error("expected fork commit")
	}
}

func TestVerifier_ImposterHeuristic(t *testing.T) {
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "11bd71901bbe5b1630ceea73d27597364c9af683"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"verification": map[string]any{"verified": false},
			"author":       map[string]any{"name": "Attacker"},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"default_branch": "main"})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/compare/", func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"status": "ahead"})
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(context.Background(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned + not on default branch → imposter heuristic triggers
	if !result.IsForkCommit {
		t.Error("expected imposter heuristic to flag as fork commit")
	}
}
