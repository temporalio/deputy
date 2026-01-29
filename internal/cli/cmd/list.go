package cmd

import (
	"cmp"
	"context"
	"fmt"
	"io"
	"net/url"
	"os"
	"slices"
	"strconv"
	"strings"
	"time"

	"connectrpc.com/connect"
	"github.com/docker/docker/api/types/filters"
	imagetypes "github.com/docker/docker/api/types/image"
	"github.com/docker/docker/client"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/cli/flags"
	"github.com/picatz/deputy/internal/services"
	ui "github.com/picatz/deputy/internal/ui"
	"github.com/picatz/deputy/internal/ui/table"
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
		quick                bool
		all                  bool
		limit                int32
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
• docker://gcr.io/project/       List tags in container repository
• github://myorg/                List repos in GitHub organization
• github://myorg/repo/           List branches + tags in a repo
• github://myorg/repo/tags/      List only tags in a repo

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

CONTAINER REGISTRIES:
  # List tags in a container repository (remote registry)
  deputy list docker://nginx/
  deputy list docker://ghcr.io/sigstore/cosign/

  # List images from local Docker daemon (fast, no rate limits)
  deputy list docker://nginx/ --source docker-daemon
  deputy list docker://mycompany/myapp/ --source daemon

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

GITHUB:
  # List repos in an organization
  deputy list github://kubernetes/

  # List branches + tags in a repo
  deputy list github://kubernetes/kubectl/

  # List only tags
  deputy list github://kubernetes/kubectl/tags/

  # List only branches
  deputy list github://kubernetes/kubectl/branches/

  # Scan all release tags
  deputy list github://golang/go/tags/ -f json | jq -r '.discovered_targets[].uri' | xargs -P4 deputy scan

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

PAGINATION & LIMITS (for large collections):
  # Fetch all results (for scripting)
  deputy list github://kubernetes/ --all
  deputy list docker://gcr.io/project/ --all -f json | jq '.discovered_targets[].uri'

  # Limit total results
  deputy list github://kubernetes/ --limit 50
  deputy list github://kubernetes/ --all --limit 500

  # Manual pagination (default: 100 per page)
  deputy list aws://amis --page-size 50
  deputy list aws://amis --page-token "next-page-token"`,
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

			// Determine effective page size
			effectivePageSize := pageSize
			if effectivePageSize <= 0 {
				effectivePageSize = 100 // default
			}

			// Build request options
			opts := &listv1.ListOptions{
				OnlyDirect: onlyDirect,
				Ref:        ref,
				Platform:   platform,
				PageSize:   effectivePageSize,
				PageToken:  pageToken,
				Filter:     filter,
				Quick:      quick,
			}
			if len(ecos) > 0 && !(len(ecos) == 1 && ecos[0] == "all") {
				opts.Ecosystems = ecos
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

			// Handle --source docker-daemon for container collection URIs
			srcLower := strings.ToLower(strings.TrimSpace(source))
			isDaemonSource := srcLower == "docker-daemon" || srcLower == "daemon"
			if isDaemonSource && isContainerCollectionURI(target) {
				localTargets, err := listLocalDockerImages(ctx, target)
				if err != nil {
					return fmt.Errorf("list local images: %w", err)
				}

				// Apply limit if specified
				if limit > 0 && int32(len(localTargets)) > limit {
					localTargets = localTargets[:limit]
				}

				switch strings.ToLower(format) {
				case "", FormatText:
					return writeDiscoveredTargetsText(w, localTargets, !noHeader, nil)
				case FormatTSV:
					return writeDiscoveredTargetsTSV(w, localTargets, !noHeader)
				case FormatJSON:
					combinedResp := &listv1.ListPackagesResponse{
						IsCollection:      true,
						DiscoveredTargets: localTargets,
					}
					jsonOpts := protojson.MarshalOptions{
						Multiline:       true,
						Indent:          "  ",
						EmitUnpopulated: false,
						UseProtoNames:   true,
					}
					data, err := jsonOpts.Marshal(combinedResp)
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

			// Call client API
			resp, err := c.Packages.ListPackages(ctx, connect.NewRequest(&listv1.ListPackagesRequest{
				Target:  target,
				Options: opts,
			}))
			if err != nil {
				return fmt.Errorf("list packages failed: %w", err)
			}

			// Handle collection responses (discovered targets) vs package responses
			if resp.Msg.IsCollection {
				// Collect all targets (possibly across multiple pages)
				allTargets := resp.Msg.DiscoveredTargets
				nextToken := resp.Msg.NextPageToken

				// If --all is set, fetch all remaining pages
				if all && nextToken != "" {
					for nextToken != "" {
						// Check if we've hit the limit
						if limit > 0 && int32(len(allTargets)) >= limit {
							break
						}

						// Check context for cancellation
						if err := ctx.Err(); err != nil {
							return fmt.Errorf("list cancelled: %w", err)
						}

						// Fetch next page
						opts.PageToken = nextToken
						resp, err = c.Packages.ListPackages(ctx, connect.NewRequest(&listv1.ListPackagesRequest{
							Target:  target,
							Options: opts,
						}))
						if err != nil {
							return fmt.Errorf("list packages failed: %w", err)
						}

						allTargets = append(allTargets, resp.Msg.DiscoveredTargets...)
						nextToken = resp.Msg.NextPageToken
					}
				}

				// Apply limit if specified
				if limit > 0 && int32(len(allTargets)) > limit {
					allTargets = allTargets[:limit]
					nextToken = "" // Don't show pagination when we hit the limit
				}

				// Sort discovered targets by URI for stable output
				slices.SortFunc(allTargets, func(a, b *listv1.DiscoveredTarget) int {
					return cmp.Compare(a.Uri, b.Uri)
				})

				// Build pagination info for output (only show if not using --all)
				var pagination *paginationInfo
				if !all && nextToken != "" {
					pagination = &paginationInfo{
						nextPageToken: nextToken,
						pageSize:      effectivePageSize,
						currentTarget: target,
					}
				}

				switch strings.ToLower(format) {
				case "", FormatText:
					return writeDiscoveredTargetsText(w, allTargets, !noHeader, pagination)
				case FormatTSV:
					return writeDiscoveredTargetsTSV(w, allTargets, !noHeader)
				case FormatJSON:
					// Build a combined response for JSON output
					combinedResp := &listv1.ListPackagesResponse{
						IsCollection:      true,
						DiscoveredTargets: allTargets,
						NextPageToken:     nextToken,
					}
					jsonOpts := protojson.MarshalOptions{
						Multiline:       true,
						Indent:          "  ",
						EmitUnpopulated: false,
						UseProtoNames:   true,
					}
					data, err := jsonOpts.Marshal(combinedResp)
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

			// Determine if this target type supports direct/indirect distinction.
			// Repository-like targets (DIR, GIT) always support direct/indirect.
			// Container images support it when base image detection was used (LayerDetails populated).
			targetKind := targetv1.TargetKind_TARGET_KIND_UNSPECIFIED
			if resp.Msg.Target != nil {
				targetKind = resp.Msg.Target.Kind
			}
			showDirect := supportsDirectIndirect(targetKind) || hasBaseImageInfo(resp.Msg.Packages)

			switch strings.ToLower(format) {
			case "", FormatText:
				return writeListText(w, items, !noHeader, false, showDirect)
			case FormatTSV:
				return writeListTSV(w, items, !noHeader, false, showDirect)
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
	cmd.Flags().BoolVar(&quick, "quick", false, "Skip metadata fetching for faster listing (no digest/created_at)")
	cmd.Flags().BoolVarP(&all, "all", "a", false, "Fetch all pages (for scripting; may be slow for large collections)")
	cmd.Flags().Int32VarP(&limit, "limit", "l", 0, "Maximum total number of results to return (0 = no limit)")

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
	case "docker-daemon", "daemon":
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

// supportsDirectIndirect returns true if the target kind supports the direct/indirect
// dependency distinction. Only repository-like targets have meaningful direct/indirect
// semantics; container images, binaries, and other artifact types just have packages "present".
func supportsDirectIndirect(kind targetv1.TargetKind) bool {
	switch kind {
	case targetv1.TargetKind_TARGET_KIND_DIR,
		targetv1.TargetKind_TARGET_KIND_GIT,
		targetv1.TargetKind_TARGET_KIND_FILE:
		return true
	default:
		// Container images, binaries, VM images, cloud resources, SBOMs, etc.
		// don't have meaningful direct/indirect distinction by default
		return false
	}
}

// hasBaseImageInfo returns true if base image detection was used and meaningful
// direct/indirect info is available. This is indicated by at least one package
// having InBaseImage=true. Without base image detection, InBaseImage defaults to
// false for all packages, making the distinction meaningless.
func hasBaseImageInfo(pkgs []*dependencyv1.Package) bool {
	for _, pkg := range pkgs {
		if pkg != nil && pkg.LayerDetails != nil && pkg.LayerDetails.InBaseImage {
			return true
		}
	}
	return false
}

// writeListText prints a simple space-separated table (with optional header).
// When showDirect is false, the DIRECT column is omitted (for targets where
// direct/indirect doesn't apply, like container images and binaries).
func writeListText(w io.Writer, items []ListItem, header bool, showSources bool, showDirect bool) error {
	// Build columns based on what we're showing
	cols := []table.Column{
		{Header: "PURL", Type: table.TypeID, Priority: 2, MinWidth: 20},
	}
	if showDirect {
		cols = append(cols, table.Column{Header: "DIRECT", Type: table.TypeStatus, Priority: 1, MinWidth: 8})
	}
	if showSources {
		cols = append(cols, table.Column{Header: "SOURCES", Type: table.TypePath, Priority: 0, MinWidth: 10})
	}

	tbl := table.New(cols...)

	// Count direct/indirect for summary
	directCount, indirectCount := 0, 0

	for _, it := range items {
		row := []string{it.PURL}

		if showDirect {
			if it.IsDirect {
				row = append(row, "direct")
				directCount++
			} else {
				row = append(row, "indirect")
				indirectCount++
			}
		}

		if showSources {
			sources := it.Sources
			if sources == "" {
				sources = "-"
			}
			row = append(row, sources)
		}

		tbl.AddRow(row...)
	}

	tbl.Render(w, header)

	// Print summary line
	total := len(items)
	if total > 0 {
		fmt.Fprintf(w, "\n%s\n", ui.StyleHeader.Render("Summary:"))
		if showDirect {
			fmt.Fprintf(w, "  %d total packages (%d direct, %d indirect)\n", total, directCount, indirectCount)
		} else {
			fmt.Fprintf(w, "  %d total packages\n", total)
		}
	}

	return nil
}

// writeListTSV prints a tab-separated list (with optional header).
// When showDirect is false, the direct column is omitted (for targets where
// direct/indirect doesn't apply, like container images and binaries).
func writeListTSV(w io.Writer, items []ListItem, header bool, showSources bool, showDirect bool) error {
	if header {
		switch {
		case showSources && showDirect:
			fmt.Fprintln(w, "purl\tdirect\tsources")
		case showDirect:
			fmt.Fprintln(w, "purl\tdirect")
		case showSources:
			fmt.Fprintln(w, "purl\tsources")
		default:
			fmt.Fprintln(w, "purl")
		}
	}
	for _, it := range items {
		switch {
		case showSources && showDirect:
			direct := "false"
			if it.IsDirect {
				direct = "true"
			}
			fmt.Fprintf(w, "%s\t%s\t%s\n", it.PURL, direct, it.Sources)
		case showDirect:
			direct := "false"
			if it.IsDirect {
				direct = "true"
			}
			fmt.Fprintf(w, "%s\t%s\n", it.PURL, direct)
		case showSources:
			fmt.Fprintf(w, "%s\t%s\n", it.PURL, it.Sources)
		default:
			fmt.Fprintln(w, it.PURL)
		}
	}
	return nil
}

// paginationInfo contains information about pagination state for output formatting.
type paginationInfo struct {
	nextPageToken string // Token for the next page, empty if no more pages
	pageSize      int32  // Current page size
	currentTarget string // The target being listed (for showing next page command)
}

// hasMorePages returns true if there are more results available.
func (p *paginationInfo) hasMorePages() bool {
	return p != nil && p.nextPageToken != ""
}

// collectionType represents the type of collection being listed.
type collectionType int

const (
	collectionUnknown collectionType = iota
	collectionContainerTags
	collectionGitHubRepos
	collectionGitHubRefs
	collectionAWSResources
	// GitHub collection types for richer display
	collectionGitHubPRs
	collectionGitHubIssues
	collectionGitHubCommits
	collectionGitHubContributors
	collectionGitHubCollaborators
	collectionGitHubReleases
	collectionGitHubForks
	collectionGitHubWorkflows
	collectionGitHubWorkflowRuns
	collectionGitHubDependabot
	collectionGitHubCodeScanning
	collectionGitHubSecretScanning
	collectionGitHubAdvisories
	collectionGitHubPackages
	collectionGitHubReleaseAssets
)

// detectCollectionType determines the collection type from target metadata.
func detectCollectionType(targets []*listv1.DiscoveredTarget) collectionType {
	if len(targets) == 0 {
		return collectionUnknown
	}
	// Sample first target's metadata
	t := targets[0]
	if t.Metadata == nil {
		return collectionUnknown
	}

	// Check explicit type field first (most reliable)
	if typeVal, ok := t.Metadata["type"]; ok {
		switch typeVal {
		case "pull_request":
			return collectionGitHubPRs
		case "issue":
			return collectionGitHubIssues
		case "commit":
			return collectionGitHubCommits
		case "contributor":
			return collectionGitHubContributors
		case "collaborator":
			return collectionGitHubCollaborators
		case "release":
			return collectionGitHubReleases
		case "fork":
			return collectionGitHubForks
		case "workflow":
			return collectionGitHubWorkflows
		case "workflow_run":
			return collectionGitHubWorkflowRuns
		case "dependabot_alert":
			return collectionGitHubDependabot
		case "code_scanning_alert":
			return collectionGitHubCodeScanning
		case "secret_scanning_alert":
			return collectionGitHubSecretScanning
		case "security_advisory":
			return collectionGitHubAdvisories
		case "package":
			return collectionGitHubPackages
		case "release_asset":
			return collectionGitHubReleaseAssets
		}
	}

	// GitHub refs (branches/tags in a repo)
	if _, ok := t.Metadata["ref_type"]; ok {
		return collectionGitHubRefs
	}
	// GitHub repos (repos in an org)
	if _, ok := t.Metadata["default_branch"]; ok {
		return collectionGitHubRepos
	}
	// Container registry tags
	if _, ok := t.Metadata["repository"]; ok {
		if _, ok := t.Metadata["tag"]; ok {
			return collectionContainerTags
		}
	}
	// AWS resources
	if _, ok := t.Metadata["region"]; ok {
		return collectionAWSResources
	}
	if _, ok := t.Metadata["ami_id"]; ok {
		return collectionAWSResources
	}

	return collectionUnknown
}

// collectionLabels returns the header and summary labels for a collection type.
func collectionLabels(ct collectionType) (nameHeader, summaryNoun string) {
	switch ct {
	case collectionContainerTags:
		return "TAG", "tags"
	case collectionGitHubRepos:
		return "REPO", "repositories"
	case collectionGitHubRefs:
		return "REF", "refs"
	case collectionAWSResources:
		return "RESOURCE", "resources"
	case collectionGitHubPRs:
		return "PR", "pull requests"
	case collectionGitHubIssues:
		return "ISSUE", "issues"
	case collectionGitHubCommits:
		return "SHA", "commits"
	case collectionGitHubContributors:
		return "CONTRIBUTOR", "contributors"
	case collectionGitHubCollaborators:
		return "COLLABORATOR", "collaborators"
	case collectionGitHubReleases:
		return "RELEASE", "releases"
	case collectionGitHubForks:
		return "FORK", "forks"
	case collectionGitHubWorkflows:
		return "WORKFLOW", "workflows"
	case collectionGitHubWorkflowRuns:
		return "RUN", "workflow runs"
	case collectionGitHubDependabot:
		return "ALERT", "dependabot alerts"
	case collectionGitHubCodeScanning:
		return "FINDING", "code scanning alerts"
	case collectionGitHubSecretScanning:
		return "SECRET", "secret scanning alerts"
	case collectionGitHubAdvisories:
		return "ADVISORY", "security advisories"
	case collectionGitHubPackages:
		return "PACKAGE", "packages"
	case collectionGitHubReleaseAssets:
		return "ASSET", "release assets"
	default:
		return "NAME", "targets"
	}
}

// writeDiscoveredTargetsText prints discovered targets in a human-readable table format.
// Headers and columns are context-aware based on collection type.
func writeDiscoveredTargetsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, pagination *paginationInfo) error {
	// Detect collection type for context-aware display
	ct := detectCollectionType(targets)
	_, summaryNoun := collectionLabels(ct)

	// Route to type-specific formatters for optimal display
	switch ct {
	case collectionGitHubRefs:
		return writeGitHubRefsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubRepos:
		return writeGitHubReposText(w, targets, header, summaryNoun, pagination)
	case collectionContainerTags:
		return writeContainerTagsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubPRs:
		return writeGitHubPRsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubIssues:
		return writeGitHubIssuesText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubCommits:
		return writeGitHubCommitsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubContributors:
		return writeGitHubContributorsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubCollaborators:
		return writeGitHubCollaboratorsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubReleases:
		return writeGitHubReleasesText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubForks:
		return writeGitHubForksText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubWorkflows:
		return writeGitHubWorkflowsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubWorkflowRuns:
		return writeGitHubWorkflowRunsText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubDependabot:
		return writeGitHubDependabotText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubCodeScanning:
		return writeGitHubCodeScanningText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubSecretScanning:
		return writeGitHubSecretScanningText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubAdvisories:
		return writeGitHubAdvisoriesText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubPackages:
		return writeGitHubPackagesText(w, targets, header, summaryNoun, pagination)
	case collectionGitHubReleaseAssets:
		return writeGitHubReleaseAssetsText(w, targets, header, summaryNoun, pagination)
	default:
		return writeGenericTargetsText(w, targets, header, summaryNoun, pagination)
	}
}

// listShortSHA returns the first 7 characters of a SHA hash for display.
func listShortSHA(sha string) string {
	if len(sha) > 7 {
		return sha[:7]
	}
	return sha
}

// writeGitHubRefsText formats GitHub refs (branches/tags) with REF, TYPE, SHA columns.
func writeGitHubRefsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "REF", Type: table.TypeID, Priority: 2, MinWidth: 10},
		table.Column{Header: "TYPE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "SHA", Type: table.TypeText, Priority: 0, MinWidth: 7, MaxWidth: 7},
	)

	for _, t := range targets {
		refType := ""
		sha := ""
		if t.Metadata != nil {
			refType = t.Metadata["ref_type"]
			sha = listShortSHA(t.Metadata["sha"])
		}
		tbl.AddRow(t.Name, refType, sha)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubReposText formats GitHub repos with REPO, STARS, LANGUAGE, CREATED columns.
func writeGitHubReposText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	// Check if any targets have created_at
	hasCreated := false
	for _, t := range targets {
		if t.CreatedAt != nil {
			hasCreated = true
			break
		}
	}

	cols := []table.Column{
		{Header: "REPO", Type: table.TypeID, Priority: 3, MinWidth: 10},
		{Header: "STARS", Type: table.TypeNumber, Priority: 1, MinWidth: 5},
		{Header: "LANGUAGE", Type: table.TypeText, Priority: 2, MinWidth: 8},
	}
	if hasCreated {
		cols = append(cols, table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12})
	}
	tbl := table.New(cols...)

	for _, t := range targets {
		stars := ""
		lang := "-"
		if t.Metadata != nil {
			stars = t.Metadata["stars"]
			if t.Metadata["language"] != "" {
				lang = t.Metadata["language"]
			}
		}
		row := []string{t.Name, stars, lang}
		if hasCreated {
			created := ""
			if t.CreatedAt != nil {
				created = t.CreatedAt.AsTime().Format(time.RFC3339)
			}
			row = append(row, created)
		}
		tbl.AddRow(row...)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeContainerTagsText formats container tags with TAG, DIGEST, CREATED columns.
func writeContainerTagsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	// Analyze what columns we have data for
	hasDigest := false
	hasCreated := false
	digestCount := 0
	createdCount := 0

	for _, t := range targets {
		if t.Metadata != nil && t.Metadata["digest"] != "" {
			hasDigest = true
			digestCount++
		}
		if t.CreatedAt != nil {
			hasCreated = true
			createdCount++
		}
	}

	cols := []table.Column{
		{Header: "TAG", Type: table.TypeID, Priority: 2, MinWidth: 10},
	}
	if hasDigest {
		cols = append(cols, table.Column{Header: "DIGEST", Type: table.TypeDigest, Priority: 1, MinWidth: 12})
	}
	if hasCreated {
		cols = append(cols, table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12})
	}
	tbl := table.New(cols...)

	for _, t := range targets {
		row := []string{t.Name}
		if hasDigest {
			digest := "-"
			if t.Metadata != nil && t.Metadata["digest"] != "" {
				digest = t.Metadata["digest"]
			}
			row = append(row, digest)
		}
		if hasCreated {
			created := ""
			if t.CreatedAt != nil {
				created = t.CreatedAt.AsTime().Format(time.RFC3339)
			}
			row = append(row, created)
		}
		tbl.AddRow(row...)
	}

	tbl.Render(w, header)

	showTip := !hasDigest && !hasCreated
	writeSummary(w, len(targets), summaryNoun, showTip, pagination)

	// Show note about missing metadata
	hasMissingVisible := (hasDigest && digestCount < len(targets)) ||
		(hasCreated && createdCount < len(targets))
	if hasMissingVisible {
		fmt.Fprintln(w)
		fmt.Fprintln(w, ui.StyleDim.Render("  Note: \"-\" indicates metadata unavailable (registry rate limit or auth)"))
	}

	return nil
}

// writeGitHubPRsText formats PRs with NUMBER, TITLE, STATE, AUTHOR, CREATED columns.
func writeGitHubPRsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "PR", Type: table.TypeID, Priority: 4, MinWidth: 4},
		table.Column{Header: "TITLE", Type: table.TypeText, Priority: 3, MinWidth: 15},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 2, MinWidth: 6},
		table.Column{Header: "AUTHOR", Type: table.TypeText, Priority: 1, MinWidth: 8},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		state := ""
		author := ""
		if t.Metadata != nil {
			state = t.Metadata["state"]
			author = t.Metadata["author"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, t.Description, state, author, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubIssuesText formats issues with NUMBER, TITLE, STATE, AUTHOR, CREATED columns.
func writeGitHubIssuesText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "ISSUE", Type: table.TypeID, Priority: 4, MinWidth: 4},
		table.Column{Header: "TITLE", Type: table.TypeText, Priority: 3, MinWidth: 15},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 2, MinWidth: 6},
		table.Column{Header: "AUTHOR", Type: table.TypeText, Priority: 1, MinWidth: 8},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		state := ""
		author := ""
		if t.Metadata != nil {
			state = t.Metadata["state"]
			author = t.Metadata["author"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, t.Description, state, author, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubCommitsText formats commits with SHA, MESSAGE, AUTHOR, CREATED columns.
func writeGitHubCommitsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "SHA", Type: table.TypeID, Priority: 3, MinWidth: 7, MaxWidth: 7},
		table.Column{Header: "MESSAGE", Type: table.TypeText, Priority: 2, MinWidth: 20},
		table.Column{Header: "AUTHOR", Type: table.TypeText, Priority: 1, MinWidth: 8},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		author := ""
		if t.Metadata != nil {
			author = t.Metadata["author"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, t.Description, author, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubContributorsText formats contributors with NAME, CONTRIBUTIONS columns.
func writeGitHubContributorsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "CONTRIBUTOR", Type: table.TypeID, Priority: 1, MinWidth: 10},
		table.Column{Header: "COMMITS", Type: table.TypeNumber, Priority: 0, MinWidth: 6},
	)

	for _, t := range targets {
		contrib := ""
		if t.Metadata != nil {
			contrib = t.Metadata["contributions"]
		}
		tbl.AddRow(t.Name, contrib)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubCollaboratorsText formats collaborators with NAME, PERMISSION columns.
func writeGitHubCollaboratorsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "COLLABORATOR", Type: table.TypeID, Priority: 1, MinWidth: 10},
		table.Column{Header: "PERMISSION", Type: table.TypeStatus, Priority: 0, MinWidth: 6},
	)

	for _, t := range targets {
		perm := ""
		if t.Metadata != nil {
			perm = t.Metadata["permission"]
		}
		tbl.AddRow(t.Name, perm)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubReleasesText formats releases with NAME, TAG, PRERELEASE, CREATED columns.
func writeGitHubReleasesText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "RELEASE", Type: table.TypeID, Priority: 3, MinWidth: 10},
		table.Column{Header: "TAG", Type: table.TypeText, Priority: 2, MinWidth: 8},
		table.Column{Header: "TYPE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		tag := ""
		prerel := "stable"
		if t.Metadata != nil {
			tag = t.Metadata["tag"]
			if t.Metadata["prerelease"] == "true" {
				prerel = "prerelease"
			}
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, tag, prerel, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubForksText formats forks with REPO, OWNER, STARS, CREATED columns.
func writeGitHubForksText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "FORK", Type: table.TypeID, Priority: 3, MinWidth: 10},
		table.Column{Header: "OWNER", Type: table.TypeText, Priority: 2, MinWidth: 8},
		table.Column{Header: "STARS", Type: table.TypeNumber, Priority: 1, MinWidth: 5},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		repo := t.Name
		owner := ""
		stars := ""
		created := ""
		if t.Metadata != nil {
			owner = t.Metadata["fork_owner"]
			stars = t.Metadata["stars"]
		}
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(repo, owner, stars, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubWorkflowsText formats workflows with NAME, STATE, PATH columns.
func writeGitHubWorkflowsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "WORKFLOW", Type: table.TypeID, Priority: 2, MinWidth: 15},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "PATH", Type: table.TypePath, Priority: 0, MinWidth: 15},
	)

	for _, t := range targets {
		state := ""
		path := ""
		if t.Metadata != nil {
			state = t.Metadata["state"]
			path = t.Metadata["path"]
		}
		tbl.AddRow(t.Name, state, path)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubWorkflowRunsText formats workflow runs with RUN, WORKFLOW, STATUS, BRANCH, CREATED columns.
func writeGitHubWorkflowRunsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "RUN", Type: table.TypeID, Priority: 4, MinWidth: 6},
		table.Column{Header: "WORKFLOW", Type: table.TypeText, Priority: 2, MinWidth: 10},
		table.Column{Header: "STATUS", Type: table.TypeStatus, Priority: 3, MinWidth: 6},
		table.Column{Header: "BRANCH", Type: table.TypeText, Priority: 1, MinWidth: 8},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		workflow := ""
		status := ""
		branch := ""
		if t.Metadata != nil {
			workflow = t.Metadata["workflow_name"]
			status = t.Metadata["conclusion"]
			if status == "" {
				status = t.Metadata["status"]
			}
			branch = t.Metadata["branch"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, workflow, status, branch, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubDependabotText formats Dependabot alerts with PACKAGE, SEVERITY, STATE, CREATED columns.
func writeGitHubDependabotText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "PACKAGE", Type: table.TypeID, Priority: 3, MinWidth: 15},
		table.Column{Header: "SEVERITY", Type: table.TypeStatus, Priority: 2, MinWidth: 8},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		pkg := ""
		sev := ""
		state := ""
		if t.Metadata != nil {
			pkg = t.Metadata["package"]
			sev = t.Metadata["severity"]
			state = t.Metadata["state"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(pkg, sev, state, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubCodeScanningText formats code scanning alerts with RULE, SEVERITY, FILE, STATE, CREATED columns.
func writeGitHubCodeScanningText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "RULE", Type: table.TypeID, Priority: 4, MinWidth: 10},
		table.Column{Header: "SEVERITY", Type: table.TypeStatus, Priority: 3, MinWidth: 8},
		table.Column{Header: "FILE", Type: table.TypePath, Priority: 1, MinWidth: 10},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 2, MinWidth: 6},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		rule := ""
		sev := ""
		file := ""
		state := ""
		if t.Metadata != nil {
			rule = t.Metadata["rule_id"]
			sev = t.Metadata["rule_severity"]
			file = t.Metadata["file"]
			state = t.Metadata["state"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(rule, sev, file, state, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubSecretScanningText formats secret scanning alerts with TYPE, STATE, CREATED columns.
func writeGitHubSecretScanningText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "SECRET TYPE", Type: table.TypeID, Priority: 2, MinWidth: 15},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		secretType := t.Description
		state := ""
		if t.Metadata != nil {
			state = t.Metadata["state"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(secretType, state, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubAdvisoriesText formats security advisories with GHSA, SEVERITY, STATE, CREATED columns.
func writeGitHubAdvisoriesText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "GHSA", Type: table.TypeID, Priority: 3, MinWidth: 15},
		table.Column{Header: "SEVERITY", Type: table.TypeStatus, Priority: 2, MinWidth: 8},
		table.Column{Header: "STATE", Type: table.TypeStatus, Priority: 1, MinWidth: 6},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		sev := ""
		state := ""
		if t.Metadata != nil {
			sev = t.Metadata["severity"]
			state = t.Metadata["state"]
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, sev, state, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGitHubReleaseAssetsText formats release assets with NAME, TYPE, SIZE, DOWNLOADS columns.
func writeGitHubReleaseAssetsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "ASSET", Type: table.TypeID, Priority: 3, MinWidth: 15},
		table.Column{Header: "TYPE", Type: table.TypeStatus, Priority: 2, MinWidth: 8},
		table.Column{Header: "SIZE", Type: table.TypeText, Priority: 1, MinWidth: 6},
		table.Column{Header: "DOWNLOADS", Type: table.TypeNumber, Priority: 0, MinWidth: 6},
	)

	for _, t := range targets {
		assetType := ""
		size := ""
		downloads := ""
		if t.Metadata != nil {
			assetType = t.Metadata["asset_type"]
			if sizeStr := t.Metadata["size"]; sizeStr != "" {
				if bytes, err := strconv.ParseInt(sizeStr, 10, 64); err == nil {
					size = formatSizeCompact(bytes)
				}
			}
			downloads = t.Metadata["download_count"]
		}
		tbl.AddRow(t.Name, assetType, size, downloads)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// formatSizeCompact formats bytes as compact human-readable size.
func formatSizeCompact(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f%cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// writeGitHubPackagesText formats GitHub packages with NAME, TYPE, VERSIONS, REPO, CREATED columns.
func writeGitHubPackagesText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	tbl := table.New(
		table.Column{Header: "PACKAGE", Type: table.TypeID, Priority: 4, MinWidth: 15},
		table.Column{Header: "TYPE", Type: table.TypeStatus, Priority: 2, MinWidth: 8},
		table.Column{Header: "VERSIONS", Type: table.TypeNumber, Priority: 1, MinWidth: 6},
		table.Column{Header: "REPO", Type: table.TypeText, Priority: 3, MinWidth: 10},
		table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12},
	)

	for _, t := range targets {
		pkgType := ""
		versions := "-"
		repo := "-"
		if t.Metadata != nil {
			pkgType = t.Metadata["package_type"]
			if t.Metadata["version_count"] != "" {
				versions = t.Metadata["version_count"]
			}
			if t.Metadata["repository"] != "" {
				repo = t.Metadata["repository"]
			}
		}
		created := ""
		if t.CreatedAt != nil {
			created = t.CreatedAt.AsTime().Format(time.RFC3339)
		}
		tbl.AddRow(t.Name, pkgType, versions, repo, created)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeGenericTargetsText formats generic targets with NAME, CREATED columns.
func writeGenericTargetsText(w io.Writer, targets []*listv1.DiscoveredTarget, header bool, summaryNoun string, pagination *paginationInfo) error {
	// Check if any targets have created_at
	hasCreated := false
	for _, t := range targets {
		if t.CreatedAt != nil {
			hasCreated = true
			break
		}
	}

	cols := []table.Column{
		{Header: "NAME", Type: table.TypeID, Priority: 1, MinWidth: 15},
	}
	if hasCreated {
		cols = append(cols, table.Column{Header: "CREATED", Type: table.TypeDateFull, Priority: 0, MinWidth: 12})
	}
	tbl := table.New(cols...)

	for _, t := range targets {
		row := []string{t.Name}
		if hasCreated {
			created := ""
			if t.CreatedAt != nil {
				created = t.CreatedAt.AsTime().Format(time.RFC3339)
			}
			row = append(row, created)
		}
		tbl.AddRow(row...)
	}

	tbl.Render(w, header)
	writeSummary(w, len(targets), summaryNoun, false, pagination)
	return nil
}

// writeSummary prints the summary footer for discovered targets.
func writeSummary(w io.Writer, count int, noun string, showTip bool, pagination *paginationInfo) {
	fmt.Fprintf(w, "\n%s\n", ui.StyleHeader.Render("Summary:"))

	if count == 0 {
		fmt.Fprintf(w, "  No %s found\n", noun)
		return
	}

	// Show count with pagination context
	if pagination.hasMorePages() {
		fmt.Fprintf(w, "  %d %s shown (more available)\n", count, noun)
	} else {
		fmt.Fprintf(w, "  %d %s discovered\n", count, noun)
	}

	// Show how to get next page if there are more results
	if pagination.hasMorePages() {
		nextCmd := fmt.Sprintf("deputy list %s --page-token %q", pagination.currentTarget, pagination.nextPageToken)
		fmt.Fprintf(w, "\n  %s\n", ui.StyleDim.Render("Next page:"))
		fmt.Fprintf(w, "  %s\n", nextCmd)
	}

	if showTip {
		fmt.Fprintf(w, "\n  %s\n", ui.StyleDim.Render("Tip: Use -f json for full details (digest, created_at, URI)"))
	}
}

// writeDiscoveredTargetsTSV prints discovered targets in TSV format.
func writeDiscoveredTargetsTSV(w io.Writer, targets []*listv1.DiscoveredTarget, header bool) error {
	if header {
		fmt.Fprintln(w, "uri\tname\tdigest\tcreated_at")
	}
	for _, t := range targets {
		createdAt := ""
		if t.CreatedAt != nil {
			createdAt = t.CreatedAt.AsTime().Format("2006-01-02T15:04:05Z")
		}
		digest := ""
		if t.Metadata != nil {
			digest = t.Metadata["digest"]
		}
		fmt.Fprintf(w, "%s\t%s\t%s\t%s\n", t.Uri, t.Name, digest, createdAt)
	}
	return nil
}

// listLocalDockerImages lists images from the local Docker daemon matching a repository.
// The target should be a container collection URI like "docker://nginx/" or "docker://gcr.io/project/app/".
func listLocalDockerImages(ctx context.Context, target string) ([]*listv1.DiscoveredTarget, error) {
	// Parse the repository from the target URI
	repoPath, err := parseContainerCollectionTarget(target)
	if err != nil {
		return nil, fmt.Errorf("parse target: %w", err)
	}

	// Connect to the Docker daemon
	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return nil, fmt.Errorf("connect to Docker daemon: %w", err)
	}
	defer cli.Close()

	// List all images (we'll filter client-side for flexibility)
	images, err := cli.ImageList(ctx, imagetypes.ListOptions{
		All:     false, // Only show named images, not intermediate layers
		Filters: filters.NewArgs(),
	})
	if err != nil {
		return nil, fmt.Errorf("list images: %w", err)
	}

	// Filter and collect matching images
	var results []*listv1.DiscoveredTarget
	seen := make(map[string]bool) // Dedupe by tag

	for _, img := range images {
		for _, repoTag := range img.RepoTags {
			// Parse repo:tag
			repo, tag := parseRepoTag(repoTag)
			if repo == "" || tag == "" {
				continue
			}

			// Check if this image matches the requested repository
			if !matchesRepository(repo, repoPath) {
				continue
			}

			// Dedupe
			if seen[repoTag] {
				continue
			}
			seen[repoTag] = true

			// Build the discovered target
			uri := fmt.Sprintf("docker://%s", repoTag)
			dt := &listv1.DiscoveredTarget{
				Uri:  uri,
				Name: tag,
				Metadata: map[string]string{
					"repository": repo,
					"tag":        tag,
					"source":     "local",
				},
			}

			// Add digest if available (from RepoDigests)
			for _, repoDigest := range img.RepoDigests {
				digestRepo, digest := parseRepoDigest(repoDigest)
				if matchesRepository(digestRepo, repoPath) && digest != "" {
					dt.Metadata["digest"] = digest
					break
				}
			}

			// Add created time
			if img.Created > 0 {
				dt.CreatedAt = timestamppb.New(unixToTime(img.Created))
			}

			// Add size info
			if img.Size > 0 {
				dt.Metadata["size"] = formatSize(img.Size)
			}

			results = append(results, dt)
		}
	}

	// Sort by tag name for consistent output
	slices.SortFunc(results, func(a, b *listv1.DiscoveredTarget) int {
		return cmp.Compare(a.Name, b.Name)
	})

	return results, nil
}

// parseContainerCollectionTarget extracts the repository name from a container collection URI.
func parseContainerCollectionTarget(target string) (string, error) {
	// Remove scheme (docker://, oci://, container://)
	for _, scheme := range []string{"docker://", "oci://", "container://"} {
		if rest, found := strings.CutPrefix(target, scheme); found {
			target = rest
			break
		}
	}

	// Remove leading/trailing slashes
	target = strings.Trim(target, "/")

	if target == "" {
		return "", fmt.Errorf("empty repository path")
	}

	return target, nil
}

// parseRepoTag splits "repo:tag" into repo and tag components.
func parseRepoTag(repoTag string) (repo, tag string) {
	// Handle the case of digest references (repo@sha256:...)
	if strings.Contains(repoTag, "@") {
		return "", ""
	}

	lastColon := strings.LastIndex(repoTag, ":")
	if lastColon == -1 {
		return repoTag, ""
	}

	// Check if the colon is part of a port (e.g., localhost:5000/repo:tag)
	possibleTag := repoTag[lastColon+1:]
	if strings.Contains(possibleTag, "/") {
		// Colon is part of registry port, not tag separator
		return repoTag, ""
	}

	return repoTag[:lastColon], possibleTag
}

// parseRepoDigest splits "repo@sha256:..." into repo and digest components.
func parseRepoDigest(repoDigest string) (repo, digest string) {
	at := strings.LastIndex(repoDigest, "@")
	if at == -1 {
		return repoDigest, ""
	}
	return repoDigest[:at], repoDigest[at+1:]
}

// matchesRepository checks if an image repository matches the requested repository pattern.
func matchesRepository(imageRepo, requestedRepo string) bool {
	// Normalize Docker Hub short names
	imageRepo = normalizeDockerHubRepo(imageRepo)
	requestedRepo = normalizeDockerHubRepo(requestedRepo)

	return imageRepo == requestedRepo
}

// normalizeDockerHubRepo expands Docker Hub short names to full paths.
func normalizeDockerHubRepo(repo string) string {
	// Handle Docker Hub official images (no slash = library/name)
	if !strings.Contains(repo, "/") {
		return "docker.io/library/" + repo
	}

	// Handle Docker Hub user images (user/name = docker.io/user/name)
	if !strings.Contains(repo, ".") {
		return "docker.io/" + repo
	}

	// Handle index.docker.io -> docker.io
	if rest, found := strings.CutPrefix(repo, "index.docker.io/"); found {
		return "docker.io/" + rest
	}

	return repo
}

// unixToTime converts a Unix timestamp to time.Time.
func unixToTime(unix int64) time.Time {
	return time.Unix(unix, 0)
}

// formatSize formats bytes as human-readable size.
func formatSize(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%d B", bytes)
	}
	div, exp := int64(unit), 0
	for n := bytes / unit; n >= unit; n /= unit {
		div *= unit
		exp++
	}
	return fmt.Sprintf("%.1f %cB", float64(bytes)/float64(div), "KMGTPE"[exp])
}

// isContainerCollectionURI checks if a target is a container repository collection URI.
func isContainerCollectionURI(target string) bool {
	for _, scheme := range []string{"docker://", "oci://", "container://"} {
		if strings.HasPrefix(target, scheme) && strings.HasSuffix(target, "/") {
			return true
		}
	}
	return false
}
