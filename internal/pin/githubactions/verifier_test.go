package githubactions

import (
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

	result, err := v.Verify(t.Context(), owner, repo, sha)
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

	result, err := v.Verify(t.Context(), owner, repo, sha)
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

	result, err := v.Verify(t.Context(), owner, repo, sha)
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

	result, err := v.Verify(t.Context(), owner, repo, sha)
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

	result, err := v.Verify(t.Context(), owner, repo, sha)
	if err != nil {
		t.Fatal(err)
	}

	// Unsigned + not on default branch → imposter heuristic triggers
	if !result.IsForkCommit {
		t.Error("expected imposter heuristic to flag as fork commit")
	}
}

func TestVerifier_AnnotatedTagObject(t *testing.T) {
	// When the resolver returns a tag object SHA instead of a commit SHA,
	// the verifier should dereference the tag and verify the commit.
	const (
		owner     = "sigstore"
		repo      = "cosign-installer"
		tagObjSHA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" // tag object
		commitSHA = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb" // underlying commit
	)

	mux := http.NewServeMux()

	// GetCommit for tag object SHA → 404
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+tagObjSHA, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"message":"Not Found"}`)
	})

	// GetTag for tag object SHA → returns tag pointing to commit
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/tags/"+tagObjSHA, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha": tagObjSHA,
			"object": map[string]any{
				"type": "commit",
				"sha":  commitSHA,
			},
		})
	})

	// GetCommit for actual commit SHA → success
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+commitSHA, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha": commitSHA,
			"verification": map[string]any{
				"verified":  true,
				"signature": "-----BEGIN SSH SIGNATURE-----",
				"reason":    "valid",
			},
			"author": map[string]any{"name": "Sigstore Bot"},
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

	result, err := v.Verify(t.Context(), owner, repo, tagObjSHA)
	if err != nil {
		t.Fatal(err)
	}

	if result.IsForkCommit {
		t.Error("expected annotated tag to NOT be flagged as fork commit")
	}
	if !result.Signed {
		t.Error("expected signed after tag dereference")
	}
	if !result.OnBranch {
		t.Error("expected on branch after tag dereference")
	}
}

func TestVerifier_RenamedRepoGraceful(t *testing.T) {
	// When a repository has been renamed, Repositories.Get returns 404.
	// The verifier should degrade gracefully instead of returning an error.
	const (
		owner = "picatz"
		repo  = "deputy"
		sha   = "cccccccccccccccccccccccccccccccccccccccc"
	)

	mux := http.NewServeMux()
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+sha, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          sha,
			"verification": map[string]any{"verified": true, "signature": "sig", "reason": "valid"},
			"author":       map[string]any{"name": "Author"},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		fmt.Fprintln(w, `{"message":"Not Found"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(t.Context(), owner, repo, sha)
	if err != nil {
		t.Fatalf("expected graceful degradation, got error: %v", err)
	}

	if result.IsForkCommit {
		t.Error("should not mark as fork commit when repo is simply inaccessible (404)")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected a warning about inaccessible repo")
	}
}

func TestVerifier_RateLimited_Unverifiable(t *testing.T) {
	// When the API returns 403 (rate limited), reachability is unknown. That is
	// NOT evidence of an imposter, so the verifier marks the result unverifiable
	// rather than a fork/imposter commit — even when the commit is unsigned.
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "dddddddddddddddddddddddddddddddddddddddd"
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
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `{"message":"API rate limit exceeded"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(t.Context(), owner, repo, sha)
	if err != nil {
		t.Fatalf("expected graceful handling, got error: %v", err)
	}

	if result.IsForkCommit {
		t.Error("rate-limited (unverifiable) reachability must not be classified as an imposter")
	}
	if !result.Unverifiable {
		t.Error("expected rate-limited verification to be marked unverifiable")
	}
}

func TestVerifier_RateLimited_SignedPasses(t *testing.T) {
	// When rate limited but commit IS signed, don't flag as suspicious —
	// signature alone is sufficient evidence of legitimacy.
	const (
		owner = "actions"
		repo  = "checkout"
		sha   = "eeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeeee"
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
			"author": map[string]any{"name": "GitHub"},
		})
	})
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
		fmt.Fprintln(w, `{"message":"API rate limit exceeded"}`)
	})

	srv := httptest.NewServer(mux)
	defer srv.Close()

	client := testGHClient(t, srv.URL)
	v := NewVerifier(client)

	result, err := v.Verify(t.Context(), owner, repo, sha)
	if err != nil {
		t.Fatalf("expected graceful handling, got error: %v", err)
	}

	if result.IsForkCommit {
		t.Error("signed commit should NOT be flagged as suspicious even when rate limited")
	}
	if len(result.Warnings) == 0 {
		t.Error("expected a warning about rate limiting")
	}
}

func TestVerifier_NestedAnnotatedTags(t *testing.T) {
	// Tag object → tag object → commit (two levels of indirection)
	const (
		owner       = "example"
		repo        = "nested-tags"
		outerTagSHA = "1111111111111111111111111111111111111111"
		innerTagSHA = "2222222222222222222222222222222222222222"
		commitSHA   = "3333333333333333333333333333333333333333"
	)

	mux := http.NewServeMux()

	// GetCommit for outerTagSHA → 404
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+outerTagSHA, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	// GetTag for outerTagSHA → points to innerTagSHA (another tag)
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/tags/"+outerTagSHA, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    outerTagSHA,
			"object": map[string]any{"type": "tag", "sha": innerTagSHA},
		})
	})
	// GetTag for innerTagSHA → points to commitSHA
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/tags/"+innerTagSHA, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":    innerTagSHA,
			"object": map[string]any{"type": "commit", "sha": commitSHA},
		})
	})
	// GetCommit for commitSHA → success
	mux.HandleFunc("/api/v3/repos/"+owner+"/"+repo+"/git/commits/"+commitSHA, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{
			"sha":          commitSHA,
			"verification": map[string]any{"verified": true, "signature": "sig", "reason": "valid"},
			"author":       map[string]any{"name": "Author"},
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

	result, err := v.Verify(t.Context(), owner, repo, outerTagSHA)
	if err != nil {
		t.Fatal(err)
	}

	if result.IsForkCommit {
		t.Error("nested annotated tags should NOT be flagged as fork commit")
	}
	if !result.Signed {
		t.Error("expected signed after nested tag dereference")
	}
}
