package actionsx

import (
	"context"
	"fmt"
	"io"
	"path"
	"path/filepath"
	"strings"
	"sync"

	"github.com/goccy/go-yaml"
	"github.com/google/osv-scalibr/extractor"
	"github.com/google/osv-scalibr/extractor/filesystem"
	scalibrfs "github.com/google/osv-scalibr/fs"
	"github.com/google/osv-scalibr/inventory"
	"github.com/google/osv-scalibr/plugin"
	"github.com/google/osv-scalibr/purl"
	"github.com/temporalio/deputy/internal/purlx"
)

const (
	// Name is the internal plugin identifier.
	Name = "github/actions"
)

// Extractor implements an OSV-Scalibr filesystem extractor for GitHub Actions.
type Extractor struct{}

// New returns a new GitHub Actions extractor.
func New() filesystem.Extractor { return &Extractor{} }

// Name returns the plugin name as understood by Deputy.
func (Extractor) Name() string { return Name }

// Version returns the plugin version; Deputy uses 0 for internal plugins.
func (Extractor) Version() int { return 0 }

// Requirements declares required capabilities; GitHub Actions scanning is filesystem-only.
func (Extractor) Requirements() *plugin.Capabilities { return &plugin.Capabilities{} }

// FileRequired limits extraction to workflow YAML files.
func (Extractor) FileRequired(api filesystem.FileAPI) bool {
	p := filepath.ToSlash(api.Path())
	if !strings.HasPrefix(p, ".github/workflows/") {
		return false
	}
	ext := strings.ToLower(filepath.Ext(p))
	return ext == ".yml" || ext == ".yaml"
}

// Extract parses a workflow YAML and returns discovered action dependencies.
func (Extractor) Extract(ctx context.Context, input *filesystem.ScanInput) (inventory.Inventory, error) {
	if input == nil || input.Reader == nil {
		return inventory.Inventory{}, nil
	}
	data, err := io.ReadAll(input.Reader)
	if err != nil {
		return inventory.Inventory{}, err
	}
	state := newParseState(input.FS)
	pkgs, err := state.parseWorkflow(ctx, input.Path, data, 0)
	if err != nil {
		return inventory.Inventory{}, fmt.Errorf("workflow.parse: %w", err)
	}
	if len(pkgs) == 0 {
		return inventory.Inventory{}, nil
	}
	return inventory.Inventory{Packages: pkgs}, nil
}

type parseState struct {
	fs      scalibrfs.FS
	visited map[string]struct{}
	mu      sync.Mutex
}

// newParseState creates parser state shared across recursive parses.
func newParseState(fs scalibrfs.FS) *parseState {
	return &parseState{
		fs:      fs,
		visited: make(map[string]struct{}),
	}
}

const maxRecursionDepth = 8

// parseWorkflow parses a workflow YAML document, extracting job- and step-level uses statements.
// It recurses into local composite actions and reusable workflows up to maxRecursionDepth.
func (s *parseState) parseWorkflow(ctx context.Context, filePath string, content []byte, depth int) ([]*extractor.Package, error) {
	if depth > maxRecursionDepth {
		return nil, nil
	}
	if s.markVisited(filePath) {
		return nil, nil
	}

	var root any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	rootMap, ok := asMap(root)
	if !ok {
		return nil, nil
	}
	var out []*extractor.Package

	jobsRaw, ok := rootMap["jobs"]
	if ok {
		if jobsMap, ok := asMap(jobsRaw); ok {
			for _, jobVal := range jobsMap {
				jobMap, ok := asMap(jobVal)
				if !ok {
					continue
				}
				// Job-level reusable workflow.
				if usesStr, ok := asString(jobMap["uses"]); ok {
					pkgs, err := s.handleUses(ctx, filePath, usesStr, depth)
					if err != nil {
						return nil, err
					}
					out = append(out, pkgs...)
				}
				// Step actions.
				if stepsVal, ok := jobMap["steps"]; ok {
					if stepsList, ok := asList(stepsVal); ok {
						for _, stepVal := range stepsList {
							stepMap, ok := asMap(stepVal)
							if !ok {
								continue
							}
							if usesStr, ok := asString(stepMap["uses"]); ok {
								pkgs, err := s.handleUses(ctx, filePath, usesStr, depth)
								if err != nil {
									return nil, err
								}
								out = append(out, pkgs...)
							}
						}
					}
				}
			}
		}
	}

	return dedupPackages(out), nil
}

// parseActionManifest parses a local action.yml|yaml file and returns any nested uses dependencies.
// Only composite and docker action types contribute dependencies.
func (s *parseState) parseActionManifest(ctx context.Context, filePath string, content []byte, depth int) ([]*extractor.Package, error) {
	if depth > maxRecursionDepth {
		return nil, nil
	}
	var root any
	if err := yaml.Unmarshal(content, &root); err != nil {
		return nil, err
	}
	rootMap, ok := asMap(root)
	if !ok {
		return nil, nil
	}
	runsVal, ok := rootMap["runs"]
	if !ok {
		return nil, nil
	}
	runsMap, ok := asMap(runsVal)
	if !ok {
		return nil, nil
	}
	using, _ := asString(runsMap["using"])
	switch strings.ToLower(strings.TrimSpace(using)) {
	case "composite":
		stepsVal, ok := runsMap["steps"]
		if !ok {
			return nil, nil
		}
		stepsList, ok := asList(stepsVal)
		if !ok {
			return nil, nil
		}
		var out []*extractor.Package
		for _, stepVal := range stepsList {
			stepMap, ok := asMap(stepVal)
			if !ok {
				continue
			}
			if usesStr, ok := asString(stepMap["uses"]); ok {
				pkgs, err := s.handleUses(ctx, filePath, usesStr, depth)
				if err != nil {
					return nil, err
				}
				out = append(out, pkgs...)
			}
		}
		return dedupPackages(out), nil
	case "docker":
		image, _ := asString(runsMap["image"])
		image = strings.TrimSpace(image)
		if after, ok0 := strings.CutPrefix(image, "docker://"); ok0 {
			return []*extractor.Package{dockerPackageFromRef(after, filePath)}, nil
		}
		// Local Dockerfile; no external dependency.
		return nil, nil
	default:
		return nil, nil
	}
}

// handleUses interprets a uses string from a workflow/action context and returns corresponding packages.
// Local references are resolved and parsed recursively; remote and docker references are emitted directly.
func (s *parseState) handleUses(ctx context.Context, parentPath string, usesStr string, depth int) ([]*extractor.Package, error) {
	usesStr = strings.TrimSpace(usesStr)
	if usesStr == "" {
		return nil, nil
	}
	if after, ok := strings.CutPrefix(usesStr, "docker://"); ok {
		return []*extractor.Package{dockerPackageFromRef(after, parentPath)}, nil
	}

	// Local action or reusable workflow. The $/ prefix is GitHub's
	// self-repository syntax: it resolves repo-root-relative at the exact
	// commit the workflow is running, so like ./ it is an in-repo reference
	// to recurse into, never a remote package.
	if strings.HasPrefix(usesStr, "./") || strings.HasPrefix(usesStr, "../") || strings.HasPrefix(usesStr, "$/") {
		for _, target := range s.resolveLocalCandidates(parentPath, usesStr) {
			if target == "" {
				continue
			}
			ext := strings.ToLower(path.Ext(target))
			if ext == ".yml" || ext == ".yaml" {
				// Local reusable workflow.
				data, err := readFile(s.fs, target)
				if err != nil {
					continue
				}
				return s.parseWorkflow(ctx, target, data, depth+1)
			}
			// Local action directory.
			manifest := path.Join(target, "action.yml")
			data, err := readFile(s.fs, manifest)
			if err != nil {
				manifest = path.Join(target, "action.yaml")
				data, err = readFile(s.fs, manifest)
			}
			if err != nil {
				continue
			}
			return s.parseActionManifest(ctx, manifest, data, depth+1)
		}
		return nil, nil
	}

	// Remote action or reusable workflow.
	pre, ref := splitUsesRef(usesStr)
	repo, subpath, ok := splitRepoAndSubpath(pre)
	if !ok {
		return nil, nil
	}
	pkg := &extractor.Package{
		Name:      repo,
		Version:   ref,
		PURLType:  purlx.TypeGitHubActions,
		Locations: []string{parentPath},
		Metadata: &UsesMetadata{
			Raw:     usesStr,
			Subpath: subpath,
		},
	}
	return []*extractor.Package{pkg}, nil
}

// UsesMetadata captures raw uses strings and any subpath.
type UsesMetadata struct {
	Raw     string
	Subpath string
}

// usesSubpath returns the action subpath recorded in a package's metadata, or
// "" when there is none. Used to keep same-repo subpath actions distinct.
func usesSubpath(p *extractor.Package) string {
	if md, ok := p.Metadata.(*UsesMetadata); ok {
		return md.Subpath
	}
	return ""
}

// splitUsesRef splits a uses string into the pre-@ portion and ref (version/tag/SHA).
// If no @ is present, ref is empty.
func splitUsesRef(raw string) (pre, ref string) {
	pre, ref, _ = strings.Cut(raw, "@")
	return strings.TrimSpace(pre), strings.TrimSpace(ref)
}

// splitRepoAndSubpath splits a remote uses prefix into "owner/repo" and an optional subpath.
// It returns ok=false when the prefix isn't of the form owner/repo[/...].
func splitRepoAndSubpath(pre string) (repo, subpath string, ok bool) {
	parts := strings.Split(strings.Trim(pre, "/"), "/")
	if len(parts) < 2 {
		return "", "", false
	}
	repo = parts[0] + "/" + parts[1]
	if len(parts) > 2 {
		subpath = strings.Join(parts[2:], "/")
	}
	return repo, subpath, true
}

// dockerPackageFromRef converts a docker:// reference into an extractor.Package.
// Digest references are treated as OCI packages; tag references as Docker packages.
func dockerPackageFromRef(ref, parentPath string) *extractor.Package {
	name, version, hasDigest := splitDockerRef(ref)
	purlType := purl.TypeDocker
	if hasDigest {
		purlType = purl.TypeOCI
	}
	return &extractor.Package{
		Name:      name,
		Version:   version,
		PURLType:  purlType,
		Locations: []string{parentPath},
		Metadata: &UsesMetadata{
			Raw: "docker://" + ref,
		},
	}
}

// splitDockerRef parses a docker image reference into name and version/tag or digest.
// It reports hasDigest=true for @sha256:... style references.
func splitDockerRef(ref string) (name, version string, hasDigest bool) {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return "", "", false
	}
	if before, after, ok := strings.Cut(ref, "@"); ok {
		name = before
		version = after
		return strings.TrimSpace(name), strings.TrimSpace(version), true
	}
	// Find tag after last slash.
	lastSlash := strings.LastIndex(ref, "/")
	tagIdx := strings.LastIndex(ref, ":")
	if tagIdx > lastSlash {
		name = ref[:tagIdx]
		version = ref[tagIdx+1:]
		return strings.TrimSpace(name), strings.TrimSpace(version), false
	}
	return ref, "", false
}

// resolveLocalCandidates returns best-effort candidate paths for a local uses reference.
// GitHub resolves local uses relative to repository root; we also try relative to the
// declaring file for compatibility with existing repositories.
func (s *parseState) resolveLocalCandidates(parentPath, rel string) []string {
	rel = filepath.ToSlash(strings.TrimSpace(rel))

	// Self-repository references ($/path) are defined repo-root-relative,
	// so no parent-relative fallback applies.
	if after, ok := strings.CutPrefix(rel, "$/"); ok {
		candidate := path.Clean(after)
		if candidate == "." || candidate == ".." || strings.HasPrefix(candidate, "../") {
			return nil
		}
		return []string{candidate}
	}

	rel = strings.TrimPrefix(rel, "./")
	rootCandidate := path.Clean(rel)
	if rootCandidate == "." {
		rootCandidate = ""
	}
	if rootCandidate != "" && (rootCandidate == ".." || strings.HasPrefix(rootCandidate, "../")) {
		rootCandidate = ""
	}

	// Fallback: also try relative to the declaring file for best-effort compatibility.
	parentDir := path.Dir(filepath.ToSlash(parentPath))
	parentCandidate := path.Clean(path.Join(parentDir, rel))
	parentCandidate = strings.TrimPrefix(parentCandidate, "./")
	if parentCandidate == "." || parentCandidate == ".." || strings.HasPrefix(parentCandidate, "../") {
		parentCandidate = ""
	}

	if rootCandidate == parentCandidate || parentCandidate == "" {
		return []string{rootCandidate}
	}
	if rootCandidate == "" {
		return []string{parentCandidate}
	}
	return []string{rootCandidate, parentCandidate}
}

// markVisited records a file path as visited for recursion cycle detection.
// It returns true if the path was already visited.
func (s *parseState) markVisited(p string) bool {
	s.mu.Lock()
	defer s.mu.Unlock()
	p = filepath.ToSlash(p)
	if _, ok := s.visited[p]; ok {
		return true
	}
	s.visited[p] = struct{}{}
	return false
}

// readFile reads a file from a scalibr filesystem.
func readFile(fs scalibrfs.FS, p string) ([]byte, error) {
	if fs == nil {
		return nil, fmt.Errorf("nil fs")
	}
	f, err := fs.Open(p)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	return io.ReadAll(f)
}

// asMap attempts to coerce a YAML-decoded value into a string-keyed map.
func asMap(v any) (map[string]any, bool) {
	switch t := v.(type) {
	case map[string]any:
		return t, true
	case map[any]any:
		out := make(map[string]any, len(t))
		for k, val := range t {
			ks, ok := k.(string)
			if !ok {
				continue
			}
			out[ks] = val
		}
		return out, true
	default:
		return nil, false
	}
}

// asList attempts to coerce a YAML-decoded value into a slice.
func asList(v any) ([]any, bool) {
	t, ok := v.([]any)
	if !ok {
		return nil, false
	}
	return []any(t), true
}

// asString attempts to coerce a YAML-decoded value into a string.
func asString(v any) (string, bool) {
	if v == nil {
		return "", false
	}
	switch t := v.(type) {
	case string:
		return t, true
	default:
		return "", false
	}
}

// dedupPackages collapses identical packages (type+name+subpath+version) and
// merges locations. The subpath is part of the identity: actions/cache/restore
// and actions/cache/save share an owner/repo (Name) but are distinct actions,
// so keying on Name alone would silently drop one of them.
func dedupPackages(in []*extractor.Package) []*extractor.Package {
	if len(in) == 0 {
		return nil
	}
	seen := map[string]*extractor.Package{}
	for _, p := range in {
		if p == nil {
			continue
		}
		key := strings.ToLower(strings.TrimSpace(p.PURLType)) + "|" + strings.ToLower(strings.TrimSpace(p.Name)) + "|" + strings.ToLower(strings.TrimSpace(usesSubpath(p))) + "|" + strings.TrimSpace(p.Version)
		existing := seen[key]
		if existing == nil {
			seen[key] = p
			continue
		}
		existing.Locations = appendUnique(existing.Locations, p.Locations...)
	}
	out := make([]*extractor.Package, 0, len(seen))
	for _, p := range seen {
		out = append(out, p)
	}
	return out
}

// appendUnique appends non-empty, non-duplicate strings to dst.
func appendUnique(dst []string, src ...string) []string {
	if len(src) == 0 {
		return dst
	}
	seen := map[string]struct{}{}
	for _, d := range dst {
		seen[d] = struct{}{}
	}
	for _, s := range src {
		if s == "" {
			continue
		}
		if _, ok := seen[s]; ok {
			continue
		}
		seen[s] = struct{}{}
		dst = append(dst, s)
	}
	return dst
}
