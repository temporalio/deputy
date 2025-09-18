package gitutil

import (
	"crypto"
	"fmt"
	"os"
	"testing"

	githash "github.com/go-git/go-git/v5/plumbing/hash"
	"github.com/pjbgf/sha1cd"
)

func TestMaybeDisableSHA1CollisionDetection(t *testing.T) {
	// Ensure starting with collision-detecting implementation
	if err := githash.RegisterHash(crypto.SHA1, sha1cd.New); err != nil {
		t.Fatalf("register sha1cd: %v", err)
	}
	if typ := fmt.Sprintf("%T", githash.New(crypto.SHA1)); typ != "*sha1cd.digest" {
		t.Fatalf("expected sha1cd digest, got %s", typ)
	}

	os.Setenv("DEPUTY_UNSAFE_NO_SHA1CD", "1")
	t.Cleanup(func() {
		os.Unsetenv("DEPUTY_UNSAFE_NO_SHA1CD")
		_ = githash.RegisterHash(crypto.SHA1, sha1cd.New)
	})

	maybeDisableSHA1CollisionDetection()

	if typ := fmt.Sprintf("%T", githash.New(crypto.SHA1)); typ != "*sha1.digest" {
		t.Fatalf("expected standard sha1 digest, got %s", typ)
	}
}
