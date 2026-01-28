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
	"google.golang.org/protobuf/encoding/protojson"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/services"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
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
		filter               string
		pageSize             int32
		pageToken            string
	)

	cmd := &cobra.Command{
		Use:           "list [target]",
		Aliases:       []string{"ls"},
		Short:         "List dependencies or available targets",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `List dependencies in a target, or list available targets in a collection.

The target URI determines the behavior:
• Specific targets (aws://ami/ami-xxx) → list packages inside
• Collection targets (aws://amis) → list available targets

SUPPORTED TARGETS:
• Local directory or repository (default: current directory)
• Remote Git repository (https://github.com/owner/repo)
• Specific Git ref (--ref v1.0.0) - scans that exact snapshot
• Container image (docker://nginx:1.25 or --source remote nginx:1.25)
• Go/Rust binary file (./myapp, /usr/local/bin/tool)
• SBOM file (sbom.json, sbom.cdx, sbom.spdx)
• Single PURL (pkg:golang/github.com/foo/bar@v1.0.0)
• AWS resources (aws://ami/ami-xxx, aws://ebs-snapshot/snap-xxx)

COLLECTION TARGETS (list available targets):
• aws://amis                     List available AMIs
• aws://amis?owner=self          List your own AMIs
• aws://amis?region=us-west-2    List AMIs in a specific region
• aws://ebs-snapshots            List available EBS snapshots
• docker://gcr.io/project/       List images in container registry
• github://myorg/                List repos in GitHub organization

OUTPUT FORMATS:
• text: Tab-separated values (PURL, Direct/Indirect for packages; URI, Name for targets)
• json: Structured JSON output with metadata

This command provides a flat list designed for:
• Scripting and automation (easy to grep/jq)
• Inventory auditing
• Verifying dependency detection
• Discovering cloud resources to scan`,
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

AWS CLOUD RESOURCES:
  # List available AMIs (collection)
  deputy list aws://amis
  deputy list aws://amis?owner=self
  deputy list aws://amis?region=us-west-2&tags.env=prod

  # List packages in a specific AMI
  deputy list aws://ami/ami-0123456789abcdef0

  # List available EBS snapshots (collection)
  deputy list aws://ebs-snapshots?owner=self

  # Scan discovered targets
  deputy list aws://amis?owner=self -f json | jq -r '.discovered_targets[].uri' | xargs deputy scan

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
  deputy list --only-direct

  # Filter by ecosystem
  deputy list --ecosystems go,npm

  # Save to file
  deputy list --output deps.txt

COLLECTION FILTERING (CEL expressions):
  # Filter discovered targets with CEL
  deputy list aws://amis --filter 'metadata["tags.env"] == "prod"'
  deputy list github://myorg/ --filter 'name.startsWith("api-")'
  deputy list docker://gcr.io/project/ --filter 'created_at > timestamp("2024-01-01T00:00:00Z")'

PAGINATION (for large collections):
  # Limit results
  deputy list aws://amis --page-size 50

  # Continue from previous page
  deputy list aws://amis --page-token "next-page-token"
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
				OnlyDirect: onlyDirect,
				Ref:        ref,
				Platform:   platform,
				PageSize:   pageSize,
				PageToken:  pageToken,
				Filter:     filter,
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

			var w io.Writer = cmd.OutOrStdout()
			if outPath != "" && outPath != "-" {
				f, err := os.Create(outPath)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer f.Close()
				w = f
			}

			// Handle collection responses (discovered targets) vs package responses
			if resp.Msg.IsCollection {
				// Sort discovered targets by URI for stable output
				targets := resp.Msg.DiscoveredTargets
				slices.SortFunc(targets, func(a, b *listv1.DiscoveredTarget) int {
					return cmp.Compare(a.Uri, b.Uri)
				})

				switch strings.ToLower(format) {
				case "", FormatText:
					return writeDiscoveredTargetsText(w, targets, !noHeader)
				case FormatTSV:
					return writeDiscoveredTargetsTSV(w, targets, !noHeader)
				case FormatJSON:
					jsonOpts := protojson.MarshalOptions{
						Multiline:       true,
						Indent:          "  ",
						EmitUnpopulated: false,
						UseProtoNames:   true,
					}
					data, err := jsonOpts.Marshal(resp.Msg)
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
			}

			// Convert proto packages to ListItems
			items := protoPackagesToListItems(resp.Msg.Packages)

			// Sort by PURL for stable output
			slices.SortFunc(items, func(a, b ListItem) int {
				if c := cmp.Compare(a.PURL, b.PURL); c != 0 {
					return c
				}
				if a.IsDirect != b.IsDirect {
					if a.IsDirect {
						return -1
					}
					return 1
				}
				return cmp.Compare(a.Name, b.Name)
			})

			switch strings.ToLower(format) {
			case "", FormatText:
				return writeListText(w, items, !noHeader, false)
			case FormatTSV:
				return writeListTSV(w, items, !noHeader, false)
			case FormatJSON:
				// Use protojson for consistent JSON output from proto response
				jsonOpts := protojson.MarshalOptions{
					Multiline:       true,
					Indent:          "  ",
					EmitUnpopulated: false,
					UseProtoNames:   true,
				}
				data, err := jsonOpts.Marshal(resp.Msg)
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
	cmd.Flags().StringSliceVarP(&ecos, "ecosystems", "e", []string{"all"}, "Ecosystems to include: go, npm, pypi, maven, rubygems, cargo, nuget, hex, pub, cocoapods, packagist, github-actions, haskell, r, cpp (default: all)")
	cmd.Flags().StringVarP(&format, "format", "f", "text", "Output format: text | tsv | json")
	cmd.Flags().StringVarP(&outPath, "output", "o", "-", "Output file path or '-' for stdout")
	cmd.Flags().BoolVar(&noHeader, "no-header", false, "Omit header row for text/tsv formats")
	cmd.Flags().BoolVar(&onlyDirect, "only-direct", false, "Only include direct dependencies")
	cmd.Flags().StringVarP(&source, "source", "s", "", "Target source type: remote, docker-daemon, tarball, oci-archive, oci-layout")
	cmd.Flags().StringVar(&platform, "platform", "", "Platform for container images (os/arch[/variant])")

	// Collection listing options
	cmd.Flags().StringVar(&filter, "filter", "", "CEL expression to filter discovered targets (collections only)")
	cmd.Flags().Int32Var(&pageSize, "page-size", 0, "Maximum number of results per page (collections only, default: 100)")
	cmd.Flags().StringVar(&pageToken, "page-token", "", "Token to continue from a previous list operation (collections only)")

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

// writeDiscoveredTargetsText prints discovered targets in a human-readable table format.
func writeDiscoveredTargetsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool) error {
	uriH, nameH, descH := "TARGET", "NAME", "DESCRIPTION"
	uriW, nameW := len(uriH), len(nameH)

	for _, t := range targets {
		if l := len(t.Uri); l > uriW {
			uriW = l
		}
		if l := len(t.Name); l > nameW {
			nameW = l
		}
	}

	// Cap column widths for readability
	if uriW > 60 {
		uriW = 60
	}
	if nameW > 40 {
		nameW = 40
	}

	pad := func(n int) string {
		if n <= 0 {
			return ""
		}
		return strings.Repeat(" ", n)
	}

	truncate := func(s string, max int) string {
		if len(s) <= max {
			return s
		}
		return s[:max-3] + "..."
	}

	if header {
		fmt.Fprintf(w, "%s%s%s%s%s\n",
			ui.StyleHeader.Render(uriH),
			pad(uriW-len(uriH)+2),
			ui.StyleHeader.Render(nameH),
			pad(nameW-len(nameH)+2),
			ui.StyleHeader.Render(descH))
	}

	for _, t := range targets {
		uri := truncate(t.Uri, uriW)
		name := truncate(t.Name, nameW)
		desc := t.Description
		if len(desc) > 60 {
			desc = desc[:57] + "..."
		}
		fmt.Fprintf(w, "%s%s%s%s%s\n",
			uri,
			pad(uriW-len(uri)+2),
			name,
			pad(nameW-len(name)+2),
			desc)
	}

	// Print summary
	if len(targets) > 0 {
		fmt.Fprintf(w, "\n%s\n", ui.StyleHeader.Render("Summary:"))
		fmt.Fprintf(w, "  %d targets discovered\n", len(targets))
	}

	return nil
}

// writeDiscoveredTargetsTSV prints discovered targets in TSV format.
func writeDiscoveredTargetsTSV(w io.Writer, targets []*listv1.DiscoveredTarget, header bool) error {
	if header {
		fmt.Fprintln(w, "uri\tname\tdescription\tcreated_at")
	}
	for _, t := range targets {
		createdAt := ""
		if t.CreatedAt != nil {
			createdAt = t.CreatedAt.AsTime().Format("2006-01-02T15:04:05Z")
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Uri, t.Name, t.Description, createdAt)
	}
	return nil
}
