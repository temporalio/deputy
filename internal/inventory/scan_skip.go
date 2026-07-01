package inventory

import (
	"bufio"
	"cmp"
	"io/fs"
	"path"
	"path/filepath"
	"slices"
	"strings"

	"github.com/go-git/go-git/v5/plumbing/format/gitignore"
	"github.com/gobwas/glob"
	"github.com/google/osv-scalibr/extractor"

	"github.com/temporalio/deputy/internal/repository/workspace"
)

// compileScanSkipDirGlob combines Deputy's explicit exclude paths with
// directory patterns from .gitignore. SCALIBR may ask SkipDirGlob about absolute
// host paths, so matching is normalized back to scan-root-relative slash paths.
// The gitignore matcher is compiled once by the caller and shared with
// filterGitignoredPackageLocations to avoid a second workspace walk.
func compileScanSkipDirGlob(ws workspace.FS, opts ScanOptions, ignoredDirs gitignore.Matcher) (glob.Glob, error) {
	excludes, err := CompileExcludePaths(opts.ExcludePaths)
	if err != nil {
		return nil, err
	}

	if excludes == nil && ignoredDirs == nil {
		return nil, nil
	}
	return &scanSkipDirGlob{
		root:        ws.RootPath(),
		excludes:    excludes,
		ignoredDirs: ignoredDirs,
	}, nil
}

type scanSkipDirGlob struct {
	root        string
	excludes    glob.Glob
	ignoredDirs gitignore.Matcher
}

func (g *scanSkipDirGlob) Match(p string) bool {
	rel := scanRootRelativePath(g.root, p)
	if rel == "" {
		return false
	}
	if g.excludes != nil && g.excludes.Match(rel) {
		return true
	}
	if g.ignoredDirs != nil && g.ignoredDirs.Match(strings.Split(rel, "/"), true) {
		return true
	}
	return false
}

func scanRootRelativePath(root, p string) string {
	p = strings.TrimSpace(p)
	if p == "" {
		return ""
	}
	if root != "" && filepath.IsAbs(p) {
		if rel, err := filepath.Rel(root, p); err == nil && rel != "." && rel != ".." && !strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
			p = rel
		} else if err == nil && rel == "." {
			p = ""
		}
	}
	p = filepath.ToSlash(p)
	p = strings.TrimPrefix(p, "./")
	return strings.Trim(p, "/")
}

func compileWorkspaceGitignore(ws workspace.FS) (gitignore.Matcher, error) {
	var files []string
	err := fs.WalkDir(ws, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return fs.SkipDir
			}
			return nil
		}
		if d.Name() == ".gitignore" {
			files = append(files, p)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	slices.SortFunc(files, func(a, b string) int {
		aDepth := strings.Count(path.Dir(filepath.ToSlash(a)), "/")
		bDepth := strings.Count(path.Dir(filepath.ToSlash(b)), "/")
		if aDepth != bDepth {
			return cmp.Compare(aDepth, bDepth)
		}
		return strings.Compare(a, b)
	})

	var patterns []gitignore.Pattern
	for _, p := range files {
		data, err := ws.ReadFile(p)
		if err != nil {
			return nil, err
		}
		domain := gitignoreDomain(p)
		scanner := bufio.NewScanner(strings.NewReader(string(data)))
		for scanner.Scan() {
			line := scanner.Text()
			if strings.HasPrefix(line, "#") || strings.TrimSpace(line) == "" {
				continue
			}
			patterns = append(patterns, gitignore.ParsePattern(line, domain))
		}
		if err := scanner.Err(); err != nil {
			return nil, err
		}
	}
	if len(patterns) == 0 {
		return nil, nil
	}
	return gitignore.NewMatcher(patterns), nil
}

func filterGitignoredPackageLocations(ws workspace.FS, pkgs []*extractor.Package, ignored gitignore.Matcher) []*extractor.Package {
	if ignored == nil || len(pkgs) == 0 {
		return pkgs
	}

	out := make([]*extractor.Package, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil || len(pkg.Locations) == 0 {
			out = append(out, pkg)
			continue
		}

		keptLocations := slices.DeleteFunc(slices.Clone(pkg.Locations), func(loc string) bool {
			rel := scanRootRelativePath(ws.RootPath(), loc)
			return rel != "" && ignored.Match(strings.Split(rel, "/"), false)
		})
		if len(keptLocations) == 0 {
			continue
		}
		if len(keptLocations) != len(pkg.Locations) {
			pkgCopy := *pkg
			pkgCopy.Locations = keptLocations
			pkg = &pkgCopy
		}
		out = append(out, pkg)
	}
	return out
}

func gitignoreDomain(ignoreFile string) []string {
	dir := path.Dir(filepath.ToSlash(ignoreFile))
	if dir == "." || dir == "/" {
		return nil
	}
	return strings.Split(strings.Trim(dir, "/"), "/")
}
