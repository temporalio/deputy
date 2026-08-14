package cmd

import (
	"cmp"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strings"

	"connectrpc.com/connect"

	"github.com/spf13/cobra"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	"github.com/temporalio/deputy/internal/cli/flags"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/services"
	ui "github.com/temporalio/deputy/internal/ui"
)

// ListItem represents a single dependency entry for output.
type ListItem struct {
	Ecosystem string `json:"ecosystem"`
	Name      string `json:"name"`
	Version   string `json:"version"`
	IsDirect  bool   `json:"isDirect"`
	PURL      string `json:"purl,omitempty"`
	Sources   string `json:"sources,omitempty"`
}

// AddListCommand registers the list (ls) subcommand.
func AddListCommand(root *cobra.Command, c *services.Clients) {
	var (
		ref, format, outPath string
		source, platform     string
		ecos                 []string
		noHeader             bool
		onlyDirect           bool
	)

	cmd := &cobra.Command{
		Use:           "list [target]",
		Aliases:       []string{"ls"},
		Short:         "List dependencies in a target",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `List all dependencies in a target as Package URLs (PURLs).

SUPPORTED TARGETS:
• Local directory or repository (default: current directory)
• Remote Git repository (https://github.com/owner/repo)
• Specific Git ref (--ref v1.0.0) - scans that exact snapshot
• Container image (docker://nginx:1.25 or --source remote nginx:1.25)
• Go/Rust binary file (./myapp, /usr/local/bin/tool)
• SBOM file (sbom.json, sbom.cdx, sbom.spdx)
• Single PURL (pkg:golang/github.com/foo/bar@v1.0.0)

This command provides a flat list of all discovered dependencies, including
transitive ones. It is designed for:
• Scripting and automation (easy to grep/jq)
• Inventory auditing
• Verifying dependency detection
• Comparing dependencies across git refs

OUTPUT FORMATS:
• text: Tab-separated values (PURL, Direct/Indirect)
• json: Structured JSON output with metadata

The output mirrors what would be included in an SBOM but in a more lightweight format.`,
		Example: `BASIC USAGE:
  # List dependencies in current repo
  deputy list

  # List dependencies in a remote repo
  deputy list https://github.com/example/repo

  # List dependencies at a specific Git ref (scans that snapshot)
  deputy list --ref v1.0.0
  deputy list --ref main
  deputy list --ref abc1234

  # List dependencies in the current working tree (uncommitted changes)
  deputy list --ref WORKING
  deputy list --ref HEAD

CONTAINER IMAGES:
  # List packages in a container image
  deputy list docker://nginx:1.25

  # Using --source flag for bare image refs
  deputy list --source remote alpine:3.19

  # Local Docker daemon image
  deputy list --source docker-daemon myapp:latest

  # Specify platform for multi-arch images
  deputy list --source remote --platform linux/amd64 nginx:latest

BINARIES & SBOMS:
  # List dependencies compiled into a Go binary
  deputy list ./myapp
  deputy list /usr/local/bin/deputy

  # List packages from an SBOM file
  deputy list sbom.json
  deputy list sbom.cdx

  # List from a single PURL
  deputy list pkg:golang/github.com/spf13/cobra@v1.8.0

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

			target := ""
			if len(args) > 0 && strings.TrimSpace(args[0]) != "" {
				target = args[0]
			}
			if target == "" {
				var err error
				target, err = os.Getwd()
				if err != nil {
					return fmt.Errorf("failed to get current directory: %w", err)
				}
			}

			// Normalize target based on source hint (for container images)
			if source != "" {
				normalized, err := normalizeListTarget(target, source)
				if err != nil {
					return err
				}
				target = normalized
			}

			if ref == "" {
				ref = "HEAD"
			}

			// Build request options
			opts := &listv1.ListOptions{
				OnlyDirect:   onlyDirect,
				Ref:          ref,
				Platform:     platform,
				ExcludePaths: excludePathsFromCmd(cmd),
			}
			if len(ecos) > 0 && !(len(ecos) == 1 && ecos[0] == "all") {
				opts.Ecosystems = ecos
			}

			// Call client API
			resp, err := c.Packages.ListPackages(ctx, connect.NewRequest(&listv1.ListPackagesRequest{
				Target:  target,
				Options: opts,
			}))
			if err != nil {
				return fmt.Errorf("list packages failed: %w", err)
			}

			// Convert proto packages to ListItems
			items := protoPackagesToListItems(resp.Msg.Packages)

			sortListItems(items)

			out, err := openOutputWriter(cmd, outPath)
			if err != nil {
				return err
			}
			defer out.Close()
			w := out.Writer

			switch strings.ToLower(format) {
			case "", FormatText:
				return writeListText(w, items, !noHeader, false)
			case FormatTSV:
				return writeListTSV(w, items, !noHeader, false)
			case FormatJSON:
				// Use protojson for consistent JSON output from proto response
				opts := internalproto.CLIJSONMarshalOptions()
				data, err := opts.Marshal(resp.Msg)
				if err != nil {
					return fmt.Errorf("marshal proto to JSON: %w", err)
				}
				if _, err := w.Write(data); err != nil {
					return err
				}
				_, err = w.Write([]byte("\n"))
				return err
			default:
				return flags.UnsupportedFormatError("--format", format, "text|tsv|json")
			}
		},
	}

	cmd.Flags().StringVarP(&ref, "ref", "r", "HEAD", "Git reference (commit, tag, branch)")
	cmd.Flags().StringSliceVarP(&ecos, "ecosystems", "e", []string{"all"}, "Ecosystems to include: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, mise, asdf, haskell, r, cpp (default: all)")
	addExcludePathFlag(cmd)
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | tsv | json")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().BoolVar(&noHeader, "no-header", false, "Omit header row for text/tsv formats")
	cmd.Flags().BoolVar(&onlyDirect, "only-direct", false, "Only include direct dependencies")
	cmd.Flags().BoolVar(&onlyDirect, "direct", false, "Alias for --only-direct")
	cmd.Flags().StringVarP(&source, "source", "s", "", "Target source type: remote, docker-daemon, tarball, oci-archive, oci-layout")
	cmd.Flags().StringVar(&platform, "platform", "", "Platform for container images (os/arch[/variant])")

	root.AddCommand(cmd)
}

// normalizeListTarget adds the appropriate URI scheme for container image targets.
func normalizeListTarget(input, source string) (string, error) {
	input = strings.TrimSpace(input)
	if input == "" {
		return "", fmt.Errorf("target is required")
	}
	// Already has a scheme
	if strings.Contains(input, "://") {
		return input, nil
	}
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "remote", "registry":
		return "docker://" + input, nil
	case "oci":
		return "oci://" + input, nil
	case "docker-daemon", "daemon", "local":
		return "docker-daemon://" + input, nil
	case "tarball", "archive", "oci-archive":
		return "tarball://" + input, nil
	case "oci-layout":
		return "oci-layout://" + input, nil
	default:
		return "", fmt.Errorf("unknown source type %q; use: remote, docker-daemon, tarball, oci-archive, oci-layout", source)
	}
}

// protoPackagesToListItems converts proto packages to ListItems for display.
func protoPackagesToListItems(pkgs []*dependencyv1.Package) []ListItem {
	items := make([]ListItem, 0, len(pkgs))
	for _, pkg := range pkgs {
		if pkg == nil {
			continue
		}
		items = append(items, ListItem{
			Ecosystem: pkg.Ecosystem,
			Name:      pkg.Name,
			Version:   pkg.Version,
			IsDirect:  pkg.Direct,
			PURL:      decodePURLForDisplay(pkg.Purl),
			Sources:   strings.Join(pkg.Locations, ", "),
		})
	}
	return items
}

func sortListItems(items []ListItem) {
	slices.SortFunc(items, compareListItems)
}

func compareListItems(a, b ListItem) int {
	if c := cmp.Compare(a.PURL, b.PURL); c != 0 {
		return c
	}
	if a.IsDirect != b.IsDirect {
		if a.IsDirect {
			return -1
		}
		return 1
	}
	if c := cmp.Compare(a.Name, b.Name); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Version, b.Version); c != 0 {
		return c
	}
	if c := cmp.Compare(a.Ecosystem, b.Ecosystem); c != 0 {
		return c
	}
	return cmp.Compare(a.Sources, b.Sources)
}

// decodePURLForDisplay decodes percent-encoded characters in a PURL for
// human-readable display. This converts %2F to /, %28 to (, etc.
// If decoding fails, returns the original string.
func decodePURLForDisplay(purl string) string {
	if purl == "" {
		return purl
	}
	// URL decode to make PURLs more readable
	// e.g., "pkg:docker/library%2Fgolang@1.25" -> "pkg:docker/library/golang@1.25"
	decoded, err := url.PathUnescape(purl)
	if err != nil {
		return purl
	}
	return decoded
}

// writeListText prints a simple space-separated table (with optional header).
func writeListText(w io.Writer, items []ListItem, header bool, showSources bool) error {
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
