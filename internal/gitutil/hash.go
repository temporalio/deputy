package gitutil

import (
	"crypto"
	stdsha1 "crypto/sha1"
	"os"

	githash "github.com/go-git/go-git/v5/plumbing/hash"
)

// maybeDisableSHA1CollisionDetection replaces go-git's default SHA1
// implementation with the standard library's version when the
// DEPUTY_UNSAFE_NO_SHA1CD environment variable is set. This disables
// collision detection for faster clones at the cost of integrity checks.
func maybeDisableSHA1CollisionDetection() {
	if os.Getenv("DEPUTY_UNSAFE_NO_SHA1CD") != "" {
		_ = githash.RegisterHash(crypto.SHA1, stdsha1.New)
	}
}

func init() {
	maybeDisableSHA1CollisionDetection()
}
