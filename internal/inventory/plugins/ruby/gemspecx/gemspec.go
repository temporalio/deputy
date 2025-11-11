package gemspecx

import (
	"bufio"
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
)

const (
	// Name exposes the plugin identifier so we can replace the upstream implementation.
	Name = "ruby/gemspec"
)

var (
	reSpec             = regexp.MustCompile(`^Gem::Specification\.new`)
	reName             = regexp.MustCompile(`\s*\w+\.name\s*=\s*["']([^"']+)["']`)
	reVerLiteral       = regexp.MustCompile(`\s*\w+\.version\s*=\s*["']([^"']+)["']`)
	reVerConstant      = regexp.MustCompile(`\s*\w+\.version\s*=\s*([A-Za-z0-9_:]+)`)
	reRequireStatement = regexp.MustCompile(`require(?:_relative)?\s+["']([^"']+)["']`)
	reVersionConst     = regexp.MustCompile(`VERSION\s*=\s*["']([^"']+)["']`)
	reFileReadExpand   = regexp.MustCompile(`File\.read\(\s*File\.expand_path\(["']([^"']+)["']\s*,\s*__FILE__\s*\)\s*\)`)
	reFileReadLiteral  = regexp.MustCompile(`File\.read\(\s*["']([^"']+)["']\s*\)`)
)

// Extractor mirrors the upstream gemspec extractor but with better version fallbacks.
type Extractor struct{}

func New() filesystem.Extractor { return &Extractor{} }

func (Extractor) Name() string                       { return Name }
func (Extractor) Version() int                       { return 0 }
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	return filepath.Ext(api.Path()) == ".gemspec"
}

func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	pkgs, err := extractPackages(input)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("gemspec.parse: %w", err)
	}
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		if len(pkg.Locations) == 0 {
			pkg.Locations = []string{input.Path}
		}
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

func extractPackages(input *filesystem.ScanInput) ([]*extractor.Package, error) {
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return nil, err
	}
	scanner := bufio.NewScanner(bytes.NewReader(data))
	gemName, gemVersion := "", ""
	versionConst := ""
	var requires []string
	foundSpec := false

	for scanner.Scan() {
		line := scanner.Text()

		if m := reRequireStatement.FindStringSubmatch(line); len(m) > 1 {
			requires = append(requires, m[1])
		}

		if !foundSpec {
			if reSpec.FindString(line) != "" {
				foundSpec = true
			}
			continue
		}
		if gemName == "" {
			if m := reName.FindStringSubmatch(line); len(m) > 1 {
				gemName = m[1]
				continue
			}
		}
		if gemVersion == "" {
			if m := reVerLiteral.FindStringSubmatch(line); len(m) > 1 {
				gemVersion = m[1]
				continue
			}
			if versionConst == "" {
				if m := reVerConstant.FindStringSubmatch(line); len(m) > 1 {
					versionConst = m[1]
				}
			}
		}
		if gemName != "" && gemVersion != "" {
			break
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}
	if !foundSpec {
		return nil, nil
	}
	if gemName == "" {
		return nil, fmt.Errorf("failed to parse gemspec name")
	}
	if gemVersion == "" {
		v, err := resolveVersionFromRequires(input.FS, filepath.Dir(input.Path), gemName, versionConst, requires)
		if err != nil {
			return nil, fmt.Errorf("failed to parse gemspec version: %w", err)
		}
		gemVersion = v
	}
	pkgs := []*extractor.Package{
		{
			Name:     gemName,
			Version:  gemVersion,
			PURLType: purl.TypeGem,
			Locations: []string{
				input.Path,
			},
		},
	}
	pkgs = append(pkgs, parseGemDependencies(data, input.Path)...)
	return pkgs, nil
}

func resolveVersionFromRequires(fs scalibrfs.FS, gemspecDir, gemName, versionConst string, requires []string) (string, error) {
	candidates := make([]string, 0, len(requires)+1)
	for _, req := range requires {
		if strings.Contains(req, "version") {
			candidates = append(candidates, req)
			if !strings.HasPrefix(req, "lib/") && !strings.HasPrefix(req, "./lib/") {
				candidates = append(candidates, filepath.Join("lib", req))
			}
		}
	}
	if len(candidates) == 0 {
		guess := filepath.Join("lib", strings.ReplaceAll(gemName, "-", "/"), "version")
		candidates = append(candidates, guess)
	}
	seen := map[string]struct{}{}
	for _, rel := range candidates {
		rel = strings.TrimSpace(rel)
		if rel == "" {
			continue
		}
		if !strings.HasSuffix(rel, ".rb") {
			rel += ".rb"
		}
		full := joinRelativePath(gemspecDir, rel)
		if full == "" {
			continue
		}
		if _, ok := seen[full]; ok {
			continue
		}
		seen[full] = struct{}{}
		if version := readVersionFromPath(fs, full, versionConst); version != "" {
			return version, nil
		}
	}
	return "", fmt.Errorf("unable to resolve version constant %q", versionConst)
}

func readVersionFromPath(fs scalibrfs.FS, relPath string, versionConst string) string {
	f, err := fs.Open(relPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	contentBytes, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	content := string(contentBytes)
	constName := "VERSION"
	if versionConst != "" {
		if idx := strings.LastIndex(versionConst, "::"); idx >= 0 && idx < len(versionConst)-2 {
			constName = versionConst[idx+2:]
		} else {
			constName = versionConst
		}
	}
	reConst := regexp.MustCompile(regexp.QuoteMeta(constName) + `\s*=\s*["']([^"']+)["']`)
	if m := reConst.FindStringSubmatch(content); len(m) > 1 {
		return m[1]
	}
	if constName == "VERSION" {
		if m := reVersionConst.FindStringSubmatch(content); len(m) > 1 {
			return m[1]
		}
	}
	baseDir := filepath.Dir(relPath)
	if m := reFileReadExpand.FindStringSubmatch(content); len(m) > 1 {
		target := joinRelativePath(baseDir, m[1])
		if text := readTrimmedFile(fs, target); text != "" {
			return text
		}
	}
	if m := reFileReadLiteral.FindStringSubmatch(content); len(m) > 1 {
		target := joinRelativePath(baseDir, m[1])
		if text := readTrimmedFile(fs, target); text != "" {
			return text
		}
	}
	return ""
}

func readTrimmedFile(fs scalibrfs.FS, relPath string) string {
	f, err := fs.Open(relPath)
	if err != nil {
		return ""
	}
	defer f.Close()
	data, err := io.ReadAll(f)
	if err != nil {
		return ""
	}
	return strings.TrimSpace(string(data))
}

func joinRelativePath(baseDir, rel string) string {
	base := strings.TrimPrefix(baseDir, "./")
	joined := filepath.Clean(filepath.Join("/", base, rel))
	joined = strings.TrimPrefix(joined, "/")
	if joined == "" || strings.HasPrefix(joined, "..") {
		return ""
	}
	return joined
}

var (
	reDependencyCall = regexp.MustCompile(`add_(?:runtime_)?dependency\s*\(?\s*["']([^"']+)["'](.*)`)
	reQuotedValue    = regexp.MustCompile(`["']([^"']+)["']`)
)

func parseGemDependencies(content []byte, gemspecPath string) []*extractor.Package {
	pkgs := []*extractor.Package{}
	scanner := bufio.NewScanner(bytes.NewReader(content))
	var buffer string
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		buffer += " " + line
		if strings.HasSuffix(line, ",") && !strings.Contains(line, ")") {
			continue
		}
		if pkg := dependencyFromLine(buffer, gemspecPath); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
		buffer = ""
	}
	if buffer != "" {
		if pkg := dependencyFromLine(buffer, gemspecPath); pkg != nil {
			pkgs = append(pkgs, pkg)
		}
	}
	return pkgs
}

func dependencyFromLine(line, gemspecPath string) *extractor.Package {
	if !strings.Contains(line, "add_dependency") {
		return nil
	}
	m := reDependencyCall.FindStringSubmatch(line)
	if len(m) < 2 {
		return nil
	}
	name := strings.TrimSpace(m[1])
	if name == "" {
		return nil
	}
	version := ""
	if matches := reQuotedValue.FindAllStringSubmatch(m[2], -1); len(matches) > 0 {
		version = normalizeGemConstraint(matches[0][1])
	}
	return &extractor.Package{
		Name:      name,
		Version:   version,
		PURLType:  purl.TypeGem,
		Locations: []string{gemspecPath},
	}
}

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
