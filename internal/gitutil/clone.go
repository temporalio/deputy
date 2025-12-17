package gitutil

import (
	"context"

	billyos "github.com/go-git/go-billy/v5/osfs"
	gitlib "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing/cache"
	"github.com/go-git/go-git/v5/storage/filesystem"
)

// CloneContext clones a repository into dir using a filesystem storage that
// keeps file descriptors open for faster object access. The caller must invoke
// the returned cleanup function to release resources when done.
func CloneContext(ctx context.Context, dir string, opts *gitlib.CloneOptions) (*gitlib.Repository, func(), error) {
	fs := billyos.New(dir)
	dotgit, err := fs.Chroot(".git")
	if err != nil {
		return nil, nil, err
	}
	storer := filesystem.NewStorageWithOptions(dotgit, cache.NewObjectLRUDefault(), filesystem.Options{KeepDescriptors: true})
	repo, err := gitlib.CloneContext(ctx, storer, fs, opts)
	if err != nil {
		return nil, nil, err
	}
	cleanup := func() { _ = storer.Close() } // best-effort storer cleanup
	return repo, cleanup, nil
}
