// Command docsgen regenerates the generated documentation sections in place.
// Run it from the repository root or via go generate ./internal/docsgen/...
package main

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/temporalio/deputy/internal/docsgen"
)

func main() {
	root, err := repoRoot()
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	path := filepath.Join(root, filepath.FromSlash(docsgen.PolicyInputsDocPath))
	if err := docsgen.UpdateSection(path, docsgen.PolicyEntrypointsSection, docsgen.PolicyEntrypointsMarkdown()); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("regenerated %s section of %s\n", docsgen.PolicyEntrypointsSection, docsgen.PolicyInputsDocPath)
}

// repoRoot walks up from the working directory to the module root, so the
// command works from the repository root and from go generate's package
// directory alike.
func repoRoot() (string, error) {
	dir, err := os.Getwd()
	if err != nil {
		return "", err
	}
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir, nil
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			return "", fmt.Errorf("no go.mod found above %s", dir)
		}
		dir = parent
	}
}
