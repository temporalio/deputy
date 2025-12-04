package inventory

import (
	"bufio"
	"bytes"
	"io/fs"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/purl"

	"github.com/picatz/deputy/internal/repository/workspace"
)

var (
	reGemCall      = regexp.MustCompile(`\bgem\s+["']([^"']+)["'](.*)`)
	reGemQuotedVal = regexp.MustCompile(`["']([^"']+)["']`)
)

// collectGemfilePackages scans the workspace for Gemfiles and extracts
// dependencies declared within them. It walks the filesystem, skipping
// directories and non-Gemfile files.
func collectGemfilePackages(ws workspace.FS) ([]*extractor.Package, error) {
	var pkgs []*extractor.Package
	fsys := fs.FS(ws)
	err := fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		if d.IsDir() {
			return nil
		}
		if filepath.Base(path) != "Gemfile" {
			return nil
		}
		data, err := ws.ReadFile(path)
		if err != nil {
			return err
		}
		pkgs = append(pkgs, parseGemfileDependencies(path, data)...)
		return nil
	})
	if err != nil {
		return nil, err
	}
	return pkgs, nil
}

// parseGemfileDependencies parses the content of a Gemfile to identify
// declared dependencies. It uses regex matching to find `gem` declarations
// and extracts the package name and version constraints.
func parseGemfileDependencies(path string, content []byte) []*extractor.Package {
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var buffer string
	var out []*extractor.Package
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		buffer += " " + line
		if strings.HasSuffix(line, "\\") || (strings.HasSuffix(line, ",") && !strings.Contains(line, ")")) {
			continue
		}
		if pkg := gemDependencyFromLine(buffer, path); pkg != nil {
			out = append(out, pkg)
		}
		buffer = ""
	}
	if buffer != "" {
		if pkg := gemDependencyFromLine(buffer, path); pkg != nil {
			out = append(out, pkg)
		}
	}
	return out
}

// gemDependencyFromLine parses a single line (or accumulated buffer) to extract a gem dependency.
func gemDependencyFromLine(line, path string) *extractor.Package {
	if !strings.Contains(line, "gem ") {
		return nil
	}
	m := reGemCall.FindStringSubmatch(line)
	if len(m) < 2 {
		return nil
	}
	name := strings.TrimSpace(m[1])
	if name == "" || strings.EqualFold(name, "gemspec") {
		return nil
	}
	version := ""
	if matches := reGemQuotedVal.FindAllStringSubmatch(m[2], -1); len(matches) > 0 {
		version = normalizeGemConstraint(matches[0][1])
	}
	return &extractor.Package{
		Name:      name,
		Version:   version,
		PURLType:  purl.TypeGem,
		Locations: []string{path},
	}
}

// normalizeGemConstraint cleans up a version constraint string to extract the version number.
func normalizeGemConstraint(expr string) string {
	expr = strings.TrimSpace(expr)
	expr = strings.Trim(expr, "\"'")
	if expr == "" {
		return ""
	}
	expr = strings.TrimLeft(expr, "=<>~^! ")
	expr = strings.TrimSpace(expr)
	if idx := strings.IndexAny(expr, ", "); idx >= 0 {
		expr = expr[:idx]
	}
	return expr
}
