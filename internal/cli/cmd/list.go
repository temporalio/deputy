package cmd

import (
	"cmp"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"slices"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	scalpurl "github.com/google/osv-scalibr/purl"
	"github.com/picatz/deputy/internal/auth"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/gitutil"
	gitx "github.com/picatz/deputy/internal/gitutil"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/picatz/deputy/internal/otel"
	"github.com/picatz/deputy/internal/purlx"
	"github.com/picatz/deputy/internal/repository"
	"github.com/picatz/deputy/internal/repository/workspace"
	"github.com/picatz/deputy/internal/scan"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"golang.org/x/mod/modfile"
)

// ListItem represents a single dependency entry for output.
type ListItem struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"` // package or module, depending on level
	Version   string `json:"version"`
	Module    string `json:"module"` // module root when applicable (Go modules)
	IsDirect  bool   `json:"isDirect"`
	PURL      string `json:"purl,omitempty"`
	Sources   string `json:"sources,omitempty"`
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
	var (
		ref, format, outPath, level string
		ecos                        []string
		noHeader                    bool
		onlyDirect                  bool
		showSources                 bool
	)

	cmd := &cobra.Command{
		Use:           "list [repo]",
		Aliases:       []string{"ls"},
		Short:         "List dependencies in a repository",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `List all dependencies in a repository as Package URLs (PURLs).

This command provides a flat list of all discovered dependencies, including
transitive ones. It is designed for:
• Scripting and automation (easy to grep/jq)
• Inventory auditing
• Verifying dependency detection

OUTPUT FORMATS:
• text: Tab-separated values (PURL, Direct/Indirect)
• json: Structured JSON output with metadata

The output mirrors what would be included in an SBOM but in a more lightweight format.`,
		Example: `BASIC USAGE:
  # List dependencies in current repo
  deputy list

  # List dependencies in a remote repo
  deputy list https://github.com/example/repo

FILTERING & FORMATTING:
  # Output as JSON
  deputy list --format json

  # Only show direct dependencies
  deputy list --direct

  # Filter by ecosystem
  deputy list --ecosystems go,npm

  # Save to file
  deputy list --output deps.txt`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			repoPath := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				repoPath = args[0]
			}
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			if ref == "" {
				ref = "HEAD"
			}

			items, commitHash, _, err := collectListItems(ctx, repoPath, ref, ecos, showSources)
			if err != nil {
				return err
			}

			var w io.Writer = cmd.OutOrStdout()
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			switch strings.ToLower(format) {
			case "", FormatText:
				if onlyDirect {
					items = filterOnlyDirect(items)
				}
				return writeListText(w, items, !noHeader, showSources)
			case FormatTSV:
				if onlyDirect {
					items = filterOnlyDirect(items)
				}
				return writeListTSV(w, items, !noHeader, showSources)
			case FormatJSON:
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
				return flags.UnsupportedFormatError("--format", format, "text|tsv|json")
			}
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", []string{"all"}, "Ecosystems to include: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | tsv | json")
	cmd.Flags().StringVar(&level, "level", "package", "(Reserved) Output granularity; currently always emits package-level entries")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().BoolVar(&noHeader, "no-header", false, "Omit header row for text/tsv formats")
	cmd.Flags().BoolVar(&onlyDirect, "only-direct", false, "Only include direct dependencies")
	cmd.Flags().BoolVar(&showSources, "show-sources", false, "Show manifest/lockfile sources where dependencies were found")

	root.AddCommand(cmd)
}

// collectListItems gathers packages for repo/ref (supporting remote clone) and converts to ListItem set.
func collectListItems(ctx context.Context, repoPath, ref string, ecosystems []string, showSources bool) ([]ListItem, string, string, error) {
	ctx, span := otel.StartSpan(ctx, "deputy.list",
		trace.WithAttributes(
			attribute.String("deputy.target.path", repoPath),
			attribute.String("deputy.target.ref", ref),
		))
	defer span.End()

	var (
		src *repository.Source
		err error
	)
	if fi, statErr := os.Stat(repoPath); statErr == nil && fi.IsDir() {
		src, err = repository.Open(repoPath)
		if err != nil {
			otel.SetSpanError(span, err)
			return nil, "", "", err
		}
	}
	if src == nil {
		u := gitutil.ToHTTPSGitURL(repoPath)
		if u == "" {
			return nil, "", "", fmt.Errorf("could not interpret target %q as local path or remote Git URL", repoPath)
		}
		// Use the unified auth package for secure, host-aware credential resolution
		gitAuth, _ := auth.GitAuthForURL(ctx, u)
		rn, resolveErr := gitutil.ResolveReferenceName(ctx, u, gitAuth, ref)
		if resolveErr == nil && rn.String() != "" {
			ref = rn.String()
		}
		cloneOpts := &git.CloneOptions{
			URL:          u,
			Depth:        1,
			SingleBranch: true,
			Tags:         git.NoTags,
			Auth:         gitAuth,
		}
		if rn.String() != "" {
			cloneOpts.ReferenceName = rn
		}
		src, err = repository.Clone(ctx, cloneOpts, true)
		if err != nil && cloneOpts.ReferenceName != "" {
			cloneOpts.ReferenceName = ""
			src, err = repository.Clone(ctx, cloneOpts, true)
		}
		if err != nil {
			return nil, "", "", fmt.Errorf("failed to clone remote repo %s: %w", u, err)
		}
	}
	defer src.Close()

	repo := src.Repo
	ws := src.Workspace

	effRef := refOrHEAD(ref)
	var (
		pkgs       []*extractor.Package
		targetHash *plumbing.Hash
	)
	scanOpts := inv.ScanOptions{Ecosystems: ecosystems}
	if strings.EqualFold(effRef, "HEAD") {
		pkgs, err = inv.ScanPackagesWorking(ctx, ws, scanOpts)
	}
	if !strings.EqualFold(effRef, "HEAD") {
		targetHash, err = gitx.ResolveRevisionEnhanced(repo, effRef)
		if err != nil {
			return nil, "", "", err
		}
		pkgs, err = inv.ScanPackagesAtCommitSnapshot(ctx, repo, *targetHash, scanOpts)
	}
	if err != nil {
		return nil, "", "", fmt.Errorf("failed to collect inventory: %w", err)
	}

	goDirect := map[string]bool{"stdlib": true}
	var manifestRes scan.ManifestResolver
	switch {
	case strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "HEAD~0"):
		goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		manifestRes = scan.NewWorkspaceManifestResolver(ws)
	case targetHash != nil:
		if direct, err := compare.CollectGoDirectModulesFromCommit(repo, *targetHash); err == nil {
			goDirect = direct
		}
		manifestRes = scan.NewGitManifestResolver(repo, *targetHash)
	default:
		// Fallback: use workspace for current state
		goDirect = compare.CollectGoDirectModulesFromWorkspace(ws)
		manifestRes = scan.NewWorkspaceManifestResolver(ws)
	}

	pkgInputs := scan.PackagesToInputs(pkgs, scan.PackageInputOptions{GoDirect: goDirect, Resolver: manifestRes})
	pkgDirect := scan.BuildPackageDirectMap(pkgInputs)
	pkgSources := scan.BuildPackageSources(pkgInputs)

	items := toListItems(ws, pkgs, goDirect, pkgDirect, pkgSources, showSources)
	slices.SortFunc(items, func(a, b ListItem) int {
		// Sort by PURL for stable output
		if c := cmp.Compare(a.PURL, b.PURL); c != 0 {
			return c
		}
		if a.IsDirect != b.IsDirect {
			// direct first
			if a.IsDirect {
				return -1
			}
			return 1
		}
		return cmp.Compare(a.Name, b.Name)
	})

	// Repo metadata
	commitHash := ""
	switch {
	case strings.EqualFold(effRef, "HEAD"):
		if head, err := repo.Head(); err == nil {
			commitHash = head.Hash().String()
		}
	case targetHash != nil:
		commitHash = targetHash.String()
	}

	// Record results on span
	span.SetAttributes(attribute.Int("deputy.package.count", len(items)))
	otel.SetSpanOK(span)

	return items, commitHash, "", nil
}

// toListItems converts extractor packages into unique list entries.
func toListItems(ws workspace.FS, pkgs []*extractor.Package, goDirect map[string]bool, pkgDirect map[string]bool, pkgSources map[string][]string, showSources bool) []ListItem {
	if goDirect == nil {
		goDirect = map[string]bool{}
	}
	entries := make(map[string]*ListItem)
	order := make([]string, 0, len(pkgs))
	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		ecos := strings.TrimSpace(p.Ecosystem())
		if ecos == "" && p.PURLType != "" {
			ecos = p.PURLType
		}
		if purlx.IsGitHubActionsType(ecos) {
			ecos = "GitHub Actions"
		}
		li := ListItem{
			Ecosystem: ecos,
			Name:      p.Name,
			Version:   p.Version,
		}
		key := packageKeyFromExtractor(p)
		if showSources && pkgSources != nil && key != "" {
			li.Sources = formatSources(pkgSources[key])
		}
		if pkgDirect != nil && key != "" {
			if pkgDirect[key] {
				li.IsDirect = true
			}
		}
		switch {
		case purlx.IsGitHubActionsType(p.PURLType):
			li.PURL = purlx.GitHubActionsPURLFromPackage(p)
		case p.PURL() != nil:
			li.PURL = p.PURL().String()
		}
		if strings.EqualFold(ecos, "Go") || strings.EqualFold(p.PURLType, scalpurl.TypeGolang) {
			info := compare.ParseGoPackage(p)
			module := bestModuleForPackage(info.CanonicalName, goDirect)
			if module == "" {
				module = bestModuleForPackage(p.Name, goDirect)
			}
			if module == "" {
				module = compare.GetModuleRoot(info.CanonicalName)
			}
			li.Module = module
			if goDirect[module] {
				li.IsDirect = true
			}
			if pu := p.PURL(); pu != nil {
				li.PURL = normalizeGolangPURLLikeSBOM(pu.String(), ws)
			}
			if li.PURL == "" {
				full := info.CanonicalName
				ns := ""
				name := full
				if idx := strings.LastIndex(full, "/"); idx >= 0 {
					ns = full[:idx]
					name = full[idx+1:]
				}
				li.PURL = scalpurl.PackageURL{Type: scalpurl.TypeGolang, Namespace: ns, Name: name, Version: p.Version}.String()
			}
		}
		if !strings.EqualFold(ecos, "Go") && !strings.EqualFold(p.PURLType, scalpurl.TypeGolang) {
			if li.PURL == "" && p.PURLType != "" {
				li.PURL = scalpurl.PackageURL{Type: p.PURLType, Name: p.Name, Version: p.Version}.String()
			}
		}
		if key == "" {
			key = strings.ToLower(li.PURL)
		}
		if key == "" {
			key = fmt.Sprintf("%s|%s|%s", strings.ToLower(li.Ecosystem), strings.ToLower(li.Name), li.Version)
		}
		if existing, ok := entries[key]; ok {
			if li.IsDirect && !existing.IsDirect {
				existing.IsDirect = true
			}
			if showSources && existing.Sources == "" && li.Sources != "" {
				existing.Sources = li.Sources
			}
			continue
		}
		copied := li
		entries[key] = &copied
		order = append(order, key)
	}
	out := make([]ListItem, 0, len(entries))
	for _, key := range order {
		out = append(out, *entries[key])
	}
	return out
}

// bestModuleForPackage finds the longest matching module path for a given package
// from the set of direct dependencies.
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

// packageKeyFromExtractor generates a unique key for a package based on its ecosystem, name, and version.
func packageKeyFromExtractor(p *extractor.Package) string {
	if p == nil || p.Name == "" {
		return ""
	}
	version := strings.ToLower(strings.TrimSpace(p.Version))
	ecos := strings.TrimSpace(p.Ecosystem())
	if ecos == "" && p.PURLType != "" {
		ecos = p.PURLType
	}
	if purlx.IsGitHubActionsType(ecos) {
		ecos = "GitHub Actions"
	}
	name := strings.TrimSpace(p.Name)
	if name == "" {
		return ""
	}
	if strings.EqualFold(ecos, "Go") || strings.EqualFold(p.PURLType, scalpurl.TypeGolang) {
		info := compare.ParseGoPackage(p)
		canonical := strings.ToLower(info.CanonicalName)
		if canonical == "" {
			canonical = strings.ToLower(name)
		}
		return fmt.Sprintf("go|%s|%s", canonical, version)
	}
	lowerName := strings.ToLower(name)
	if ecos == "" {
		return fmt.Sprintf("%s|%s", lowerName, version)
	}
	return fmt.Sprintf("%s|%s|%s", strings.ToLower(ecos), lowerName, version)
}

// formatSources formats the list of sources into a comma-separated string, truncating if necessary.
func formatSources(sources []string) string {
	if len(sources) == 0 {
		return ""
	}
	const max = 3
	if len(sources) <= max {
		return strings.Join(sources, ", ")
	}
	return strings.Join(sources[:max], ", ") + fmt.Sprintf(", +%d more", len(sources)-max)
}

// writeListText prints a simple space-separated table (with optional header).
func writeListText(w io.Writer, items []ListItem, header bool, showSources bool) error {
	// PURL + DIRECT only
	purlH, dirH := "PURL", "DIRECT"
	purlW := len(purlH)
	dirW := len(dirH)
	sourcesH := "SOURCES"
	sourcesW := len(sourcesH)
	directCount, indirectCount := 0, 0
	for _, it := range items {
		if l := len(it.PURL); l > purlW {
			purlW = l
		}
		d := "indirect"
		if it.IsDirect {
			d = "direct"
			directCount++
		} else {
			indirectCount++
		}
		if l := len(d); l > dirW {
			dirW = l
		}
		if showSources {
			if l := len(it.Sources); l > sourcesW {
				sourcesW = l
			}
		}
	}
	pad := func(n int) string {
		if n <= 0 {
			return ""
		}
		return strings.Repeat(" ", n)
	}
	if header {
		if showSources {
			fmt.Fprintf(w, "%s%s%s%s%s%s\n",
				ui.StyleHeader.Render(purlH),
				pad(purlW-len(purlH)+2),
				ui.StyleHeader.Render(dirH),
				pad(dirW-len(dirH)+2),
				ui.StyleHeader.Render(sourcesH),
				pad(sourcesW-len(sourcesH)))
		} else {
			fmt.Fprintf(w, "%s%s%s\n", ui.StyleHeader.Render(purlH), pad(purlW-len(purlH)+2), ui.StyleHeader.Render(dirH))
		}
	}
	for _, it := range items {
		d := "indirect"
		dStyled := ui.StyleDim.Render(d)
		if it.IsDirect {
			d = "direct"
			dStyled = ui.StyleUpgraded.Render(d)
		}
		if showSources {
			src := it.Sources
			fmt.Fprintf(w, "%s%s%s%s%s%s\n",
				it.PURL,
				pad(purlW-len(it.PURL)+2),
				dStyled,
				pad(dirW-len(d)+2),
				src,
				pad(sourcesW-len(src)))
		} else {
			fmt.Fprintf(w, "%s%s%s\n", it.PURL, pad(purlW-len(it.PURL)+2), dStyled)
		}
	}

	// Print summary line
	total := len(items)
	if total > 0 {
		fmt.Fprintf(w, "\n%s\n", ui.StyleHeader.Render("Summary:"))
		fmt.Fprintf(w, "  %d total packages (%d direct, %d indirect)\n", total, directCount, indirectCount)
	}

	return nil
}

// writeListTSV prints a tab-separated list (with optional header).
func writeListTSV(w io.Writer, items []ListItem, header bool, showSources bool) error {
	if header {
		if showSources {
			fmt.Fprintln(w, "purl\tdirect\tsources")
		} else {
			fmt.Fprintln(w, "purl\tdirect")
		}
	}
	for _, it := range items {
		direct := "false"
		if it.IsDirect {
			direct = "true"
		}
		if showSources {
			fmt.Fprintf(w, "%s\t%s\t%s\n", it.PURL, direct, it.Sources)
		} else {
			fmt.Fprintf(w, "%s\t%s\n", it.PURL, direct)
		}
	}
	return nil
}

// normalizeGolangPURLLikeSBOM mirrors the SBOM normalization for Golang PURLs.
// It expands relative names (., ./sub) to the module path read from go.mod.
func normalizeGolangPURLLikeSBOM(purlStr string, ws workspace.ReadableFS) string {
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
		if modPath := readModulePathWorkspace(ws); modPath != "" {
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

// readModulePathWorkspace reads the module path from the go.mod file in the workspace.
func readModulePathWorkspace(ws workspace.ReadableFS) string {
	if ws == nil {
		return ""
	}
	b, err := ws.ReadFile("go.mod")
	if err != nil {
		return ""
	}
	if mf, err := modfile.Parse("go.mod", b, nil); err == nil && mf != nil && mf.Module != nil {
		return mf.Module.Mod.Path
	}
	return ""
}

// filterOnlyDirect filters the list items to include only direct dependencies.
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
