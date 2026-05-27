package cmd

import (
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/temporalio/deputy/internal/cache"
	"github.com/temporalio/deputy/internal/cache/disk"
	"github.com/temporalio/deputy/internal/cache/sources"
	ui "github.com/temporalio/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// AddCacheCommand adds the cache subcommand to the root command.
func AddCacheCommand(root *cobra.Command) {
	cacheCmd := &cobra.Command{
		Use:   "cache",
		Short: "Manage offline data cache",
		Long: `Manage cached vulnerability and security data for offline use.

Deputy caches data from various sources to reduce API calls and enable offline
operation. Use these commands to initialize, update, or clear the cache.

SOURCES:
  osv     OSV vulnerability database (GitHub Actions)
  kev     CISA Known Exploited Vulnerabilities catalog
  epss    FIRST EPSS scores (populated on-demand)
  depsdev deps.dev license and dependency data`,
		Example: `  # Show cache status
  deputy cache status

  # Download data for offline use
  deputy cache init

  # Force refresh all caches
  deputy cache update --force

  # Clear specific cache
  deputy cache clear osv

  # Clear all caches
  deputy cache clear`,
	}

	cacheCmd.AddCommand(newCacheStatusCmd())
	cacheCmd.AddCommand(newCacheInitCmd())
	cacheCmd.AddCommand(newCacheUpdateCmd())
	cacheCmd.AddCommand(newCacheClearCmd())

	root.AddCommand(cacheCmd)
}

// buildRegistry creates a registry with all cache sources.
func buildRegistry() *cache.Registry {
	reg := cache.NewRegistry()
	// Pre-cacheable sources (bulk download)
	reg.Register(sources.NewOSVSource())
	reg.Register(sources.NewKEVSource())
	// On-demand sources (populated per-query, status-only)
	reg.Register(sources.NewEPSSSource())
	reg.Register(sources.NewDepsDevSource())
	return reg
}

// newCacheStatusCmd creates the "cache status" command.
func newCacheStatusCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "status",
		Short: "Show cache status and statistics",
		Long:  "Display the current state of all cache sources including freshness, size, and entry counts.",
		RunE:  runCacheStatus,
	}
}

func runCacheStatus(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	reg := buildRegistry()
	statuses, err := reg.Status(ctx)
	if err != nil {
		return err
	}

	// Calculate total size
	var totalSize int64
	for _, s := range statuses {
		totalSize += s.Size
	}

	// Print header
	fmt.Fprintln(os.Stdout)
	fmt.Fprintln(os.Stdout, ui.StyleHeader.Render("Cache Status"))
	fmt.Fprintln(os.Stdout)

	// Print table
	printStatusTable(statuses)

	// Print summary
	fmt.Fprintln(os.Stdout)
	fmt.Fprintf(os.Stdout, "Total: %s in %s\n",
		ui.StyleMeta.Render(cacheFormatSize(totalSize)),
		ui.StyleMeta.Render(disk.BaseDir()))

	return nil
}

// printStatusTable prints cache statuses in a table format.
func printStatusTable(statuses []cache.SourceStatus) {
	// Column widths
	const (
		nameWidth    = 12
		statusWidth  = 12
		entriesWidth = 10
		sizeWidth    = 12
		updatedWidth = 16
		expiresWidth = 12
	)

	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("7"))
	freshStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("2")) // Green
	staleStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("3")) // Yellow
	missingStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8")) // Gray

	// Header
	fmt.Fprintf(os.Stdout, "%s %s %s %s %s %s\n",
		headerStyle.Render(cachePadRight("Source", nameWidth)),
		headerStyle.Render(cachePadRight("Status", statusWidth)),
		headerStyle.Render(cachePadRight("Entries", entriesWidth)),
		headerStyle.Render(cachePadRight("Size", sizeWidth)),
		headerStyle.Render(cachePadRight("Updated", updatedWidth)),
		headerStyle.Render(cachePadRight("Expires", expiresWidth)),
	)

	// Separator
	fmt.Fprintln(os.Stdout, strings.Repeat("─", nameWidth+statusWidth+entriesWidth+sizeWidth+updatedWidth+expiresWidth+5))

	for _, s := range statuses {
		var statusStr string
		var statusStyle lipgloss.Style

		if s.Error != "" {
			statusStr = "Error"
			statusStyle = staleStyle
		} else if s.OnDemand {
			statusStr = "On-demand"
			statusStyle = missingStyle
		} else if !s.Available {
			statusStr = "Missing"
			statusStyle = missingStyle
		} else if s.Fresh {
			statusStr = "Fresh"
			statusStyle = freshStyle
		} else {
			statusStr = "Stale"
			statusStyle = staleStyle
		}

		// Format entries
		entriesStr := "-"
		if s.EntryCount > 0 {
			entriesStr = cacheFormatNumber(s.EntryCount)
		}

		// Format size
		sizeStr := "-"
		if s.Size > 0 {
			sizeStr = cacheFormatSize(s.Size)
		}

		// Format updated time
		updatedStr := "-"
		if !s.LastUpdated.IsZero() {
			updatedStr = cacheFormatTimeAgo(s.LastUpdated)
		}

		// Format expires
		expiresStr := "-"
		if !s.ExpiresAt.IsZero() && s.Available {
			remaining := time.Until(s.ExpiresAt)
			if remaining > 0 {
				expiresStr = formatDuration(remaining)
			} else {
				expiresStr = "expired"
			}
		}

		fmt.Fprintf(os.Stdout, "%s %s %s %s %s %s\n",
			padRight(s.Name, nameWidth),
			statusStyle.Render(padRight(statusStr, statusWidth)),
			padRight(entriesStr, entriesWidth),
			padRight(sizeStr, sizeWidth),
			padRight(updatedStr, updatedWidth),
			padRight(expiresStr, expiresWidth),
		)
	}
}

// newCacheInitCmd creates the "cache init" command.
func newCacheInitCmd() *cobra.Command {
	return &cobra.Command{
		Use:   "init [sources...]",
		Short: "Download data for offline use",
		Long: `Download vulnerability and security data for offline use.

If no sources are specified, downloads OSV and KEV data (recommended for offline scanning).

Available sources:
  osv     OSV vulnerability database (GitHub Actions) - ~50MB
  kev     CISA Known Exploited Vulnerabilities - ~2MB`,
		Example: `  deputy cache init           # Download OSV + KEV
  deputy cache init osv       # Just OSV
  deputy cache init kev osv   # KEV and OSV`,
		RunE: runCacheInit,
	}
}

func runCacheInit(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	reg := buildRegistry()

	// Default to OSV + KEV if no args
	sourceNames := args
	if len(sourceNames) == 0 {
		sourceNames = []string{"osv", "kev"}
	}

	for _, name := range sourceNames {
		src := reg.Get(name)
		if src == nil {
			return fmt.Errorf("unknown source: %s (available: %s)", name, strings.Join(reg.Names(), ", "))
		}

		// Create progress indicator
		progress := cache.NewUIProgressWriter(ctx, os.Stderr, "Downloading "+src.Description())
		progress.Start()

		err := src.Populate(ctx, cache.PopulateOptions{
			Force:          true,
			ProgressWriter: progress,
		})

		if err != nil {
			progress.Fail()
			return fmt.Errorf("%s: %w", name, err)
		}
		// progress.Done() is called by the source when download completes
	}

	return nil
}

// newCacheUpdateCmd creates the "cache update" command.
func newCacheUpdateCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "update [sources...]",
		Short: "Update stale cache data",
		Long: `Update cache data that has expired or is stale.

By default, only updates sources that have exceeded their TTL.
Use --force to refresh all sources regardless of TTL.`,
		Example: `  deputy cache update          # Update stale caches
  deputy cache update --force  # Force refresh all
  deputy cache update osv      # Update specific source`,
		RunE: runCacheUpdate,
	}

	cmd.Flags().Bool("force", false, "Force refresh even if not expired")
	return cmd
}

func runCacheUpdate(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	force, _ := cmd.Flags().GetBool("force")
	reg := buildRegistry()

	var toUpdate []cache.Source
	if len(args) > 0 {
		for _, name := range args {
			src := reg.Get(name)
			if src == nil {
				return fmt.Errorf("unknown source: %s", name)
			}
			toUpdate = append(toUpdate, src)
		}
	} else {
		toUpdate = reg.All()
	}

	updated := 0
	for _, src := range toUpdate {
		status, err := src.Status(ctx)
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", src.Name(), err)
			continue
		}

		if !force && status.Fresh {
			fmt.Fprintf(os.Stdout, "%s: %s\n", src.Name(), ui.StyleMeta.Render("fresh, skipping"))
			continue
		}

		// Create progress indicator
		progress := cache.NewUIProgressWriter(ctx, os.Stderr, "Updating "+src.Description())
		progress.Start()

		if err := src.Populate(ctx, cache.PopulateOptions{Force: force, ProgressWriter: progress}); err != nil {
			progress.Fail()
			fmt.Fprintf(os.Stderr, "  %s: %v\n", ui.StyleStatusError.Render("error"), err)
			continue
		}
		// progress.Done() is called by the source when download completes
		updated++
	}

	if updated == 0 && !force {
		fmt.Fprintln(os.Stdout, ui.StyleMeta.Render("All caches are fresh. Use --force to refresh anyway."))
	}

	return nil
}

// newCacheClearCmd creates the "cache clear" command.
func newCacheClearCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "clear [sources...]",
		Short: "Remove cached data",
		Long: `Remove cached data from disk.

If no sources are specified, clears all caches.
Use this to free disk space or force fresh downloads.`,
		Example: `  deputy cache clear       # Clear all caches
  deputy cache clear osv   # Clear only OSV cache
  deputy cache clear kev   # Clear only KEV cache`,
		RunE: runCacheClear,
	}

	cmd.Flags().BoolP("yes", "y", false, "Skip confirmation")
	return cmd
}

func runCacheClear(cmd *cobra.Command, args []string) error {
	ctx := cmd.Context()
	yes, _ := cmd.Flags().GetBool("yes")
	reg := buildRegistry()

	var toClear []cache.Source
	if len(args) > 0 {
		for _, name := range args {
			src := reg.Get(name)
			if src == nil {
				return fmt.Errorf("unknown source: %s", name)
			}
			toClear = append(toClear, src)
		}
	} else {
		toClear = reg.All()
	}

	// Confirm if not --yes
	if !yes {
		names := make([]string, len(toClear))
		for i, s := range toClear {
			names[i] = s.Name()
		}
		fmt.Fprintf(os.Stdout, "Clear cache for: %s\n", strings.Join(names, ", "))
		fmt.Fprint(os.Stdout, "Continue? [y/N] ")

		var response string
		if _, err := fmt.Scanln(&response); err != nil || !strings.HasPrefix(strings.ToLower(response), "y") {
			fmt.Fprintln(os.Stdout, "Aborted.")
			return nil
		}
	}

	for _, src := range toClear {
		if err := src.Clear(ctx); err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", src.Name(), err)
			continue
		}
		fmt.Fprintf(os.Stdout, "%s: %s\n", src.Name(), ui.StyleStatusSuccess.Render("cleared"))
	}

	return nil
}

// Helper functions

func cacheFormatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)

	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}

func cacheFormatNumber(n int) string {
	if n >= 1000 {
		return fmt.Sprintf("%d,%03d", n/1000, n%1000)
	}
	return fmt.Sprintf("%d", n)
}

func cacheFormatTimeAgo(t time.Time) string {
	d := time.Since(t)
	switch {
	case d < time.Minute:
		return "just now"
	case d < time.Hour:
		m := int(d.Minutes())
		if m == 1 {
			return "1 min ago"
		}
		return fmt.Sprintf("%d min ago", m)
	case d < 24*time.Hour:
		h := int(d.Hours())
		if h == 1 {
			return "1 hour ago"
		}
		return fmt.Sprintf("%d hours ago", h)
	default:
		days := int(d.Hours() / 24)
		if days == 1 {
			return "1 day ago"
		}
		return fmt.Sprintf("%d days ago", days)
	}
}

func cachePadRight(s string, width int) string {
	if len(s) >= width {
		return s[:width]
	}
	return s + strings.Repeat(" ", width-len(s))
}
