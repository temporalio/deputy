package git

import (
	"io"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
)

// ReadFileAtCommit retrieves the contents of a file at a specific commit.
// It returns an empty byte slice if the file does not exist or an error occurs.
func ReadFileAtCommit(repo *git.Repository, hash plumbing.Hash, path string) ([]byte, error) {
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return nil, err
	}
	f, err := commit.File(path)
	if err != nil {
		return nil, err
	}
	r, err := f.Reader()
	if err != nil {
		return nil, err
	}
	defer r.Close()
	return io.ReadAll(r)
}
