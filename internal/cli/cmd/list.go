package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"
	cmp "github.com/picatz/deputy/internal/compare"
	gitx "github.com/picatz/deputy/internal/git"
	inv "github.com/picatz/deputy/internal/inventory"
	sbomx "github.com/picatz/deputy/internal/sbom"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"
)

// ListItem represents a single dependency entry for output.
type ListItem struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"` // package or module, depending on level
	Version   string `json:"version"`
	Module    string `json:"module"` // module root (always populated for Go)
	IsDirect  bool   `json:"isDirect"`
	PURL      string `json:"purl,omitempty"`
}

// ListResult captures list command output for machine consumption.
type ListResult struct {
	Repo      string     `json:"repo"`
	Ref       string     `json:"ref"`
	Commit    string     `json:"commit"`
	Generated string     `json:"generated"`
	Count     int        `json:"count"`
	Items     []ListItem `json:"items"`
}

// AddListCommand registers the list (ls) subcommand.
func AddListCommand(root *cobra.Command) {
	var ref, format, outPath, level string
	var ecos []string
	var noHeader bool
	var onlyDirect bool

	cmd := &cobra.Command{
		Use:     "list [repo]",
		Aliases: []string{"ls"},
		Short:   "List dependencies in a repository",
		Long: `List dependencies (no scan or diff) as normalized PURLs for easy grep/jq workflows.

Emits one PURL per discovered package (no dedup), mirroring what the SBOM command would include,
with a direct/indirect classification.`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			repoPath := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				repoPath = args[0]
			} else {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			if ref == "" {
				ref = "HEAD"
			}

			items, commitHash, _, err := collectListItems(ctx, repoPath, ref, ecos, level)
			if err != nil {
				return err
			}

			var w io.Writer = os.Stdout
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			switch strings.ToLower(format) {
			case "", "text":
				if onlyDirect {
					items = filterOnlyDirect(items)
				}
				return writeListText(w, items, !noHeader)
			case "tsv":
				if onlyDirect {
					items = filterOnlyDirect(items)
				}
				return writeListTSV(w, items, !noHeader)
			case "json":
				result := ListResult{
					Repo:      repoPath,
					Ref:       shortGitRef(refOrHEAD(ref)),
					Commit:    commitHash,
					Generated: timeNowUTC(),
					Count:     len(items),
					Items:     items,
				}
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(result)
			default:
				return fmt.Errorf("unsupported --format %q (use text|tsv|json)", format)
			}
		},
		Example: `BASIC USAGE:
  # List dependencies for current repository at HEAD
  deputy list

  # List dependencies for a specific ref
  deputy list --ref v1.2.3
  deputy list --ref main

  # TSV for easy grep/cut/awk
  deputy list --format tsv | cut -f1

  # JSON for jq
  deputy list --format json | jq '.items[] | {purl: .purl, direct: .isDirect}'

REMOTE REPOSITORIES:
  deputy list github.com/username/repo
  deputy list --ref v1.0.0 https://github.com/username/repo.git`,
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"go"}, "Ecosystems to include (e.g., go)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | tsv | json")
	cmd.Flags().StringVar(&level, "level", "package", "(Reserved) Output granularity; currently always emits package-level entries")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().BoolVar(&noHeader, "no-header", false, "Omit header row for text/tsv formats")
	cmd.Flags().BoolVar(&onlyDirect, "only-direct", false, "Only include direct dependencies")

	root.AddCommand(cmd)
}

// collectListItems gathers packages for repo/ref (supporting remote clone) and converts to ListItem set.
func collectListItems(ctx context.Context, repoPath, ref string, _ []string, level string) ([]ListItem, string, string, error) {
	localRepoPath := repoPath
	var cleanup func()

	// Handle remote repositories
	if _, err := os.Stat(repoPath); err != nil {
		u := sbomx.ToHTTPSGitURL(repoPath)
		if u == "" {
			return nil, "", "", fmt.Errorf("could not interpret repo %q as local path or remote URL", repoPath)
		}
		auth := sbomx.AuthForURL(u)
		rn, err := sbomx.ResolveReferenceName(ctx, u, auth, ref)
		if err == nil {
			ref = rn.String()
		}
		path, cf, err := sbomx.CloneRepoToTemp(ctx, u, auth, rn)
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to clone remote repo %s: %w", u, err)
		}
		localRepoPath = path
		cleanup = cf
		defer func() {
			if cleanup != nil {
				cleanup()
			}
		}()
	}

	effRef := refOrHEAD(ref)
	if strings.EqualFold(effRef, "HEAD") {
		// If user explicitly set --ref HEAD, use HEAD~0 to include working tree state like other commands
		// but only when the flag was explicitly set (not detectable here). Follow scan's behavior: prefer HEAD~0 when --ref changed.
		// We approximate that when ref was explicitly "HEAD" we keep HEAD; otherwise callers can pass HEAD~0.
	}

	var pkgs []*extractor.Package
	var err error
	if strings.EqualFold(effRef, "HEAD") {
		pkgs, err = inv.ScanPackagesWorking(ctx, localRepoPath)
	} else {
		repo, e := git.PlainOpen(localRepoPath)
		if e != nil {
			return nil, "", "", e
		}
		h, e := gitx.ResolveRevisionEnhanced(repo, effRef)
		if e != nil {
			return nil, "", "", e
		}
		pkgs, err = inv.ScanPackagesAtCommitSnapshot(ctx, localRepoPath, *h)
	}
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to collect inventory: %w", err)
	}

	// Determine direct dependencies from go.mod at the specified reference
	var goModData []byte
	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0") {
		if b, e := os.ReadFile(filepath.Join(localRepoPath, "go.mod")); e == nil {
			goModData = b
		}
	} else {
		if repo, e := git.PlainOpen(localRepoPath); e == nil {
			if h, e := gitx.ResolveRevisionEnhanced(repo, effRef); e == nil && h != nil {
				if b, e := gitx.ReadFileAtCommit(repo, *h, "go.mod"); e == nil {
					goModData = b
				}
			}
		}
	}
	depsLoose := cmp.GetDirectDependenciesFromGoMod(goModData)
	depsExact := directModulesFromGoMod(goModData)

	items := toListItems(localRepoPath, pkgs, depsLoose, depsExact, level)
	sort.Slice(items, func(i, j int) bool {
		// Sort by PURL for stable output
		if items[i].PURL == items[j].PURL {
			if items[i].IsDirect == items[j].IsDirect {
				return items[i].Name < items[j].Name
			}
			// direct first
			return items[i].IsDirect && !items[j].IsDirect
		}
		return items[i].PURL < items[j].PURL
	})

	// Repo metadata
	commitHash, _ := getRepoMetadata(localRepoPath, ref)
	return items, commitHash, "", nil
}

// toListItems converts extractor packages into unique list entries based on level.
// level: "module" or "package".
func toListItems(repoPath string, pkgs []*extractor.Package, depsLoose map[string]bool, depsExact map[string]bool, _ string) []ListItem {
	if depsLoose == nil {
		depsLoose = cmp.GetDirectDependencies()
	}
	if depsExact == nil {
		depsExact = map[string]bool{"stdlib": true}
	}
	out := make([]ListItem, 0, len(pkgs))
	for _, p := range pkgs {
		if p == nil || p.Name == "" || p.Version == "" {
			continue
		}
		info := cmp.ParseGoPackage(p)
		module := bestModuleForPackage(p.Name, depsExact)
		if module == "" {
			module = cmp.GetModuleRoot(info.CanonicalName)
		}
		li := ListItem{
			Ecosystem: "go",
			Name:      p.Name,
			Version:   p.Version,
			Module:    module,
			IsDirect:  isDirectForPackage(p.Name, depsExact),
		}
		if pu := p.PURL(); pu != nil {
			li.PURL = normalizeGolangPURLLikeSBOM(pu.String(), repoPath)
		} else {
			full := info.CanonicalName
			ns := ""
			name := full
			if idx := strings.LastIndex(full, "/"); idx >= 0 {
				ns = full[:idx]
				name = full[idx+1:]
			}
			li.PURL = scalpurl.PackageURL{Type: scalpurl.TypeGolang, Namespace: ns, Name: name, Version: p.Version}.String()
		}
		out = append(out, li)
	}
	return out
}

// semverCompareGo compares two Go module versions; returns 1 if a>b, -1 if a<b, 0 if equal.
func semverCompareGo(a, b string) int {
	aa := a
	bb := b
	if aa != "" && aa[0] != 'v' {
		aa = "v" + aa
	}
	if bb != "" && bb[0] != 'v' {
		bb = "v" + bb
	}
	return semver.Compare(aa, bb)
}

// writeListText prints a simple space-separated table (with optional header).
func writeListText(w io.Writer, items []ListItem, header bool) error {
	// PURL + DIRECT only
	purlH, dirH := "PURL", "DIRECT"
	purlW := len(purlH)
	dirW := len(dirH)
	for _, it := range items {
		if l := len(it.PURL); l > purlW {
			purlW = l
		}
		d := "indirect"
		if it.IsDirect {
			d = "direct"
		}
		if l := len(d); l > dirW {
			dirW = l
		}
	}
	pad := func(n int) string {
		if n <= 0 {
			return ""
		}
		return strings.Repeat(" ", n)
	}
	if header {
		fmt.Fprintf(w, "%s%s%s\n", ui.StyleHeader.Render(purlH), pad(purlW-len(purlH)+2), ui.StyleHeader.Render(dirH))
	}
	for _, it := range items {
		d := "indirect"
		dStyled := ui.StyleDim.Render(d)
		if it.IsDirect {
			d = "direct"
			dStyled = ui.StyleUpgraded.Render(d)
		}
		fmt.Fprintf(w, "%s%s%s\n", it.PURL, pad(purlW-len(it.PURL)+2), dStyled)
	}
	return nil
}

// writeListTSV prints a tab-separated list (with optional header).
func writeListTSV(w io.Writer, items []ListItem, header bool) error {
	if header {
		fmt.Fprintln(w, "purl\tdirect")
	}
	for _, it := range items {
		direct := "false"
		if it.IsDirect {
			direct = "true"
		}
		fmt.Fprintf(w, "%s\t%s\n", it.PURL, direct)
	}
	return nil
}

// directModulesFromGoMod extracts exact module paths from go.mod for direct deps.
func directModulesFromGoMod(data []byte) map[string]bool {
	m := map[string]bool{"stdlib": true}
	if len(data) == 0 {
		return m
	}
	lines := strings.Split(string(data), "\n")
	for _, ln := range lines {
		ln = strings.TrimSpace(ln)
		if ln == "" || strings.HasPrefix(ln, "//") {
			continue
		}
		if strings.Contains(ln, "// indirect") {
			continue
		}
		fields := strings.Fields(ln)
		if len(fields) >= 2 && strings.Contains(fields[0], "/") {
			m[fields[0]] = true
		}
	}
	return m
}

// isDirectForPackage checks if any exact direct module path prefixes the package name.
func isDirectForPackage(pkg string, direct map[string]bool) bool {
	if direct == nil {
		return false
	}
	for mod := range direct {
		if mod == "stdlib" {
			continue
		}
		if pkg == mod || strings.HasPrefix(pkg, mod+"/") {
			return true
		}
	}
	return false
}

// bestModuleForPackage returns the longest direct module prefix of a package name if any.
func bestModuleForPackage(pkg string, direct map[string]bool) string {
	best := ""
	for mod := range direct {
		if mod == "stdlib" {
			continue
		}
		if pkg == mod || strings.HasPrefix(pkg, mod+"/") {
			if len(mod) > len(best) {
				best = mod
			}
		}
	}
	return best
}

// rewriteGolangPURLName best-effort replacement of name and version in a golang purl string.
func rewriteGolangPURLName(purlStr, name, version string) string {
	pp, err := scalpurl.FromString(purlStr)
	if err != nil || pp.Type != scalpurl.TypeGolang {
		return purlStr
	}
	if idx := strings.LastIndex(name, "/"); idx >= 0 {
		pp.Namespace = name[:idx]
		pp.Name = name[idx+1:]
	} else {
		pp.Namespace = ""
		pp.Name = name
	}
	pp.Version = version
	return pp.String()
}

// normalizeGolangPURLLikeSBOM mirrors the SBOM normalization for Golang PURLs.
// It expands relative names (., ./sub) to the module path read from go.mod.
func normalizeGolangPURLLikeSBOM(purlStr, repoPath string) string {
	if purlStr == "" {
		return purlStr
	}
	pp, err := scalpurl.FromString(purlStr)
	if err != nil || pp.Type != scalpurl.TypeGolang {
		return purlStr
	}
	// Build full path from current namespace/name
	full := pp.Name
	if pp.Namespace != "" {
		full = pp.Namespace + "/" + pp.Name
	}
	// Expand relative names to module path
	if full == "." || strings.HasPrefix(full, "./") {
		if modPath := readModulePathLocal(repoPath); modPath != "" {
			rel := strings.TrimPrefix(full, "./")
			if rel == "." {
				rel = ""
			}
			full = modPath
			if rel != "" {
				full = modPath + "/" + rel
			}
		}
	}
	// Normalize to namespace + name by splitting at last '/'
	ns := ""
	nm := full
	if idx := strings.LastIndex(full, "/"); idx > 0 {
		ns = full[:idx]
		nm = full[idx+1:]
	}
	pp.Namespace = ns
	pp.Name = nm
	return pp.String()
}

func readModulePathLocal(repoPath string) string {
	b, err := os.ReadFile(filepath.Join(repoPath, "go.mod"))
	if err != nil {
		return ""
	}
	if mf, err := modfile.Parse("go.mod", b, nil); err == nil && mf != nil && mf.Module != nil {
		return mf.Module.Mod.Path
	}
	return ""
}

func filterOnlyDirect(items []ListItem) []ListItem {
	out := items[:0]
	for _, it := range items {
		if it.IsDirect {
			out = append(out, it)
		}
	}
	return out
}

// timeNowUTC is isolated for testability.
func timeNowUTC() string { return time.Now().UTC().Format(time.RFC3339) }
