package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	"github.com/spf13/cobra"
	"osv.dev/bindings/go/osvdev"
)

// indirection points for tests
var collectInventoryForScan = collectInventoryAtRef

// addScanSubcommand registers the scan subcommand to perform vulnerability scanning at a ref.
func addScanSubcommand(root *cobra.Command) {
	var (
		ref     string
		ecos    []string
		outPath string
		format  string // text | json
	)

	cmd := &cobra.Command{
		Use:   "scan [repo]",
		Short: "Scan dependencies for known vulnerabilities (OSV)",
		Long:  "Scan the repository at the given Git ref for known vulnerabilities using osv.dev. Uses scalibr for inventory and consolidates vulnerabilities for actionable output.",
		Args:  cobra.MaximumNArgs(1),
		Example: strings.TrimSpace(`
          # Scan current repository (HEAD) and print a human-friendly report
          deputy scan
          deputy scan --ref=main

          # Scan a specific local path
          deputy scan ./path/to/repo
          deputy scan ./path/to/repo --ref=v1.2.3

          # Scan a remote GitHub repository (shorthand or URL)
          deputy scan github.com/hashicorp/vault
          deputy scan github.com/hashicorp/vault --ref=v1.16.0
          deputy scan https://github.com/hashicorp/vault --ref=main

          # JSON output (machine-readable)
          deputy scan --format=json > report.vulns.json
        `),
		RunE: func(cmd *cobra.Command, args []string) error {
			// Resolve repo path or remote
			repoPath := ""
			if len(args) > 0 {
				repoPath = strings.TrimSpace(args[0])
			}
			if repoPath == "" {
				var err error
				repoPath, err = os.Getwd()
				if err != nil {
					return err
				}
			}

			localRepoPath := repoPath
			var cleanup func()
			if !isExistingDir(repoPath) {
				// remote shorthand or URL
				u := toHTTPSGitURL(repoPath)
				if u == "" {
					return fmt.Errorf("could not interpret repo %q as local path or remote URL", repoPath)
				}
				auth := authForURL(u)
				rn, derr := resolveReferenceName(cmd.Context(), u, auth, ref)
				if derr == nil {
					ref = rn.String()
				}
				path, cf, cerr := cloneRepoToTemp(cmd.Context(), u, auth, rn)
				if cerr != nil {
					return fmt.Errorf("failed to clone remote repo %s: %w", u, cerr)
				}
				localRepoPath = path
				cleanup = cf
				defer func() {
					if cleanup != nil {
						_ = os.RemoveAll(localRepoPath)
						cleanup = nil
					}
				}()
			}

			// Inventory packages at ref
			pkgs, err := collectInventoryForScan(cmd.Context(), localRepoPath, refOrHEAD(ref), ecos)
			if err != nil {
				return err
			}

			// Convert to PackageChange slice for OSV query (treat as added at this ref)
			changes := make([]PackageChange, 0, len(pkgs))
			for _, p := range pkgs {
				if p == nil || p.Name == "" {
					continue
				}
				changes = append(changes, PackageChange{
					Name:          p.Name,
					TargetVersion: p.Version,
					ChangeType:    Added,
					Ecosystem:     string(EcosystemGo), // currently Go-focused OSV queries
					IsDirect:      false,
				})
			}

			// Query OSV
			vulns, err := queryOSVBatch(cmd.Context(), osvdev.DefaultClient(), changes)
			if err != nil {
				// proceed but report warning and continue to output empty results
				fmt.Fprintf(cmd.ErrOrStderr(), "Warning: OSV query failed: %v\n", err)
			}

			// Output
			var w io.Writer = os.Stdout
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return err
				}
				defer f.Close()
				w = f
			}

			// Resolve the commit hash for display/reference
			commitHash := ""
			originURL := ""
			if repo, err := git.PlainOpen(localRepoPath); err == nil {
				if h, herr := repo.ResolveRevision(plumbing.Revision(refOrHEAD(ref))); herr == nil && h != nil {
					commitHash = h.String()
				} else if headRef, herr2 := repo.Head(); herr2 == nil {
					commitHash = headRef.Hash().String()
				}
				// Attempt to read upstream origin URL for context
				if r, rerr := repo.Remote("origin"); rerr == nil && r != nil && r.Config() != nil && len(r.Config().URLs) > 0 {
					u := strings.TrimSpace(r.Config().URLs[0])
					if u != "" {
						// Normalize common SSH forms to https for readability
						if strings.HasPrefix(u, "git@github.com:") {
							p := strings.TrimPrefix(u, "git@github.com:")
							if !strings.HasSuffix(p, ".git") {
								p += ".git"
							}
							originURL = "https://github.com/" + p
						} else if strings.HasPrefix(u, "ssh://git@github.com/") {
							p := strings.TrimPrefix(u, "ssh://git@github.com/")
							if !strings.HasSuffix(p, ".git") {
								p += ".git"
							}
							originURL = "https://github.com/" + p
						} else {
							// Handle https and bare github.com forms
							if n := toHTTPSGitURL(u); n != "" {
								originURL = n
							} else {
								originURL = u
							}
						}
					}
				}
			}
			shortRef := shortGitRef(refOrHEAD(ref))
			shortHash := commitHash
			if len(shortHash) > 7 {
				shortHash = shortHash[:7]
			}

			switch strings.ToLower(format) {
			case "", "text":
				// Print scan context with consistent spacing: one blank line above and below
				fmt.Printf("\nScanned %s @ %s (%s)\n", repoPath, shortRef, shortHash)
				if originURL != "" {
					fmt.Println("  " + styleMeta.Render("Origin: ") + originURL)
				}
				displayVulnerabilities(vulns)
				// Detect and print module deprecations (known set)
				if deps := detectModuleDeprecations(pkgs); len(deps) > 0 {
					fmt.Printf("\n%s\n", styleHeader.Render("Module Deprecations:"))
					for _, d := range deps {
						line := fmt.Sprintf("  %s %s -> %s", styleVersion.Render("•"), styleBold.Render(d.Module), styleVersion.Render(d.Suggest))
						if d.URL != "" {
							line += " " + styleDim.Render("("+d.URL+")")
						}
						fmt.Println(line)
					}
				}
				return nil
			case "json":
				rep := buildScanReport(repoPath, refOrHEAD(ref), shortHash, vulns, len(pkgs))
				enc := json.NewEncoder(w)
				enc.SetIndent("", "  ")
				return enc.Encode(rep)
			default:
				return fmt.Errorf("unsupported --format %q (use text|json)", format)
			}
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference to scan (commit, tag, branch)")
	cmd.Flags().StringSliceVar(&ecos, "ecosystems", nil, "Limit to specific ecosystems (e.g., go,npm,pip). Defaults to auto-detect.")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | json")

	root.AddCommand(cmd)
}

// refOrHEAD normalizes empty ref to HEAD
func refOrHEAD(r string) string {
	if strings.TrimSpace(r) == "" {
		return "HEAD"
	}
	return r
}

// scanReport is a concise machine-readable report for --format=json
type scanReport struct {
	Repo            string                      `json:"repo"`
	Ref             string                      `json:"ref"`
	Commit          string                      `json:"commit"`
	Generated       string                      `json:"generated"`
	PackagesScanned int                         `json:"packagesScanned"`
	Stats           VulnerabilityStats          `json:"stats"`
	Vulns           []ConsolidatedVulnerability `json:"vulnerabilities"`
}

func buildScanReport(repo, ref, commit string, vulns []Vulnerability, pkgCount int) scanReport {
	consolidated := consolidateVulnerabilities(vulns)
	stats := categorizeVulnerabilities(vulns)
	return scanReport{
		Repo:            repo,
		Ref:             shortGitRef(ref),
		Commit:          commit,
		Generated:       time.Now().UTC().Format(time.RFC3339),
		PackagesScanned: pkgCount,
		Stats:           stats,
		Vulns:           consolidated,
	}
}

// known module deprecations and suggested replacements
type moduleDeprecation struct {
	Module  string
	Suggest string
	URL     string
}

var knownDeprecations = []moduleDeprecation{
	{Module: "github.com/aws/aws-sdk-go", Suggest: "github.com/aws/aws-sdk-go-v2", URL: "https://github.com/aws/aws-sdk-go-v2"},
}

// detectModuleDeprecations returns deprecations present in the scanned inventory
func detectModuleDeprecations(pkgs []*extractor.Package) []moduleDeprecation {
	if len(pkgs) == 0 {
		return nil
	}
	// Build a set of present module roots by inferring module path from package path
	present := map[string]struct{}{}
	for _, p := range pkgs {
		if p == nil || p.Name == "" {
			continue
		}
		name := p.Name
		// normalize: trim subpackages to module root heuristic (first 3 path parts for github.com)
		parts := strings.Split(name, "/")
		if len(parts) >= 3 && parts[0] == "github.com" {
			name = strings.Join(parts[:3], "/")
		}
		present[name] = struct{}{}
	}
	// Collect matches
	var out []moduleDeprecation
	seen := map[string]struct{}{}
	for _, d := range knownDeprecations {
		// match by exact or prefix
		if _, ok := present[d.Module]; ok {
			if _, dup := seen[d.Module]; !dup {
				out = append(out, d)
				seen[d.Module] = struct{}{}
			}
			continue
		}
		// Also detect subpackages
		for m := range present {
			if strings.HasPrefix(m, d.Module+"/") {
				if _, dup := seen[d.Module]; !dup {
					out = append(out, d)
					seen[d.Module] = struct{}{}
				}
				break
			}
		}
	}
	return out
}
