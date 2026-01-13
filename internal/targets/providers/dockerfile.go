package providers

import (
	"context"
	"os"
	"path/filepath"
	"strings"

	"github.com/picatz/deputy/internal/dockerfile"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(dockerfileProvider{})
}

const priorityDockerfile = 150 // Higher than localGit (100) to detect Dockerfiles first

// dockerfileProvider implements [targets.Provider] for Dockerfile files.
type dockerfileProvider struct{}

func (dockerfileProvider) Priority() int { return priorityDockerfile }

// Detect returns true if the target is a Dockerfile.
func (dockerfileProvider) Detect(_ context.Context, target string) bool {
	return isDockerfile(target)
}

// Open parses and materializes a Dockerfile target.
func (dockerfileProvider) Open(ctx context.Context, target string, opts map[string]string) (targets.Materialized, error) {
	path, err := filepath.Abs(target)
	if err != nil {
		return targets.Materialized{}, err
	}

	info, err := dockerfile.ParseFile(path)
	if err != nil {
		return targets.Materialized{}, err
	}

	// Run static analysis
	analysis := dockerfile.Analyze(info)

	return targets.Materialized{
		Path: path,
		Meta: targets.Descriptor{
			Kind:    targets.KindDockerfile,
			Target:  target,
			Options: opts,
		},
		Data: &DockerfileData{
			Info:     info,
			Analysis: analysis,
		},
	}, nil
}

// DockerfileData contains the parsed Dockerfile and analysis results.
type DockerfileData struct {
	Info     *dockerfile.Info
	Analysis *dockerfile.Analysis
}

// DockerfileInfo returns the parsed Dockerfile information.
// This method allows inventory.collector to access Dockerfile data
// without importing the providers package directly.
func (d *DockerfileData) DockerfileInfo() *dockerfile.Info {
	if d == nil {
		return nil
	}
	return d.Info
}

// DockerfileAnalysis returns the Dockerfile static analysis results.
// This method allows inventory.collector to access Dockerfile data
// without importing the providers package directly.
func (d *DockerfileData) DockerfileAnalysis() *dockerfile.Analysis {
	if d == nil {
		return nil
	}
	return d.Analysis
}

// isDockerfile returns true if the path looks like a Dockerfile.
func isDockerfile(path string) bool {
	// Must be a file, not a directory
	info, err := os.Stat(path)
	if err != nil || info.IsDir() {
		return false
	}

	base := filepath.Base(path)
	baseLower := strings.ToLower(base)

	// Exact matches
	if base == "Dockerfile" || base == "Containerfile" {
		return true
	}

	// Dockerfile.* pattern (e.g., Dockerfile.prod, Dockerfile.dev)
	if strings.HasPrefix(base, "Dockerfile.") {
		return true
	}

	// *.dockerfile pattern (e.g., app.dockerfile, build.dockerfile)
	if strings.HasSuffix(baseLower, ".dockerfile") {
		return true
	}

	// *Dockerfile pattern (e.g., test-Dockerfile, my.Dockerfile)
	if strings.HasSuffix(base, "Dockerfile") && base != "Dockerfile" {
		return true
	}

	// Containerfile.* pattern
	if strings.HasPrefix(base, "Containerfile.") {
		return true
	}

	// *.containerfile pattern
	if strings.HasSuffix(baseLower, ".containerfile") {
		return true
	}

	// *Containerfile pattern
	if strings.HasSuffix(base, "Containerfile") && base != "Containerfile" {
		return true
	}

	return false
}

// FindDockerfiles searches a directory for Dockerfile files.
func FindDockerfiles(root string) ([]string, error) {
	var results []string
	err := filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		// Skip hidden directories
		if d.IsDir() && strings.HasPrefix(d.Name(), ".") {
			return filepath.SkipDir
		}
		// Skip common non-source directories
		if d.IsDir() {
			name := d.Name()
			if name == "node_modules" || name == "vendor" || name == ".git" {
				return filepath.SkipDir
			}
		}
		if !d.IsDir() && isDockerfile(path) {
			results = append(results, path)
		}
		return nil
	})
	return results, err
}
