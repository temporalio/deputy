package cmd

import (
	"fmt"
	"io"
	"strings"

	"github.com/spf13/cobra"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	sbomv1 "github.com/temporalio/deputy/gen/deputy/sbom/v1"
	internalproto "github.com/temporalio/deputy/internal/proto"
	sbomx "github.com/temporalio/deputy/internal/sbom"
	"github.com/temporalio/deputy/internal/sbom/diff"
)

// addSBOMDiffCommand adds the 'sbom diff' subcommand.
func addSBOMDiffCommand(sbomCmd *cobra.Command) {
	var (
		outputFormat string
	)

	cmd := &cobra.Command{
		Use:   "diff <old-sbom> <new-sbom>",
		Short: "Compare two SBOMs and show differences",
		Long: `Compare two SBOM documents and display the differences.

This command analyzes two SBOMs and identifies:
  - Packages added in the new SBOM
  - Packages removed from the old SBOM
  - Packages with version changes (classified as major/minor/patch/downgrade)
  - License changes

SUPPORTED INPUT FORMATS:
  - Protobom JSON
  - CycloneDX JSON
  - SPDX JSON

USAGE:
  # Compare two SBOMs
  deputy sbom diff old.json new.json

  # Output as JSON for further processing
  deputy sbom diff old.json new.json --format json

  # Compare release versions
  deputy sbom diff v1.0.0-sbom.json v2.0.0-sbom.json`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			oldPath := args[0]
			newPath := args[1]

			// Read both SBOMs
			oldDoc, err := sbomx.ReadFile(oldPath)
			if err != nil {
				return fmt.Errorf("failed to read old SBOM %s: %w", oldPath, err)
			}

			newDoc, err := sbomx.ReadFile(newPath)
			if err != nil {
				return fmt.Errorf("failed to read new SBOM %s: %w", newPath, err)
			}

			// Calculate diff using the internal diff package
			result, err := diff.Compare(oldDoc, newDoc)
			if err != nil {
				return fmt.Errorf("failed to compare SBOMs: %w", err)
			}

			// Output
			switch strings.ToLower(outputFormat) {
			case "json":
				return outputDiffJSON(cmd.OutOrStdout(), result)
			default:
				return outputDiffText(cmd.OutOrStdout(), result, oldPath, newPath)
			}
		},
	}

	cmd.Flags().StringVarP(&outputFormat, "format", "f", "text", "Output format: text | json")

	sbomCmd.AddCommand(cmd)
}

// outputDiffJSON outputs the diff as JSON using proto types.
func outputDiffJSON(w io.Writer, d *diff.Diff) error {
	resp := diffToProto(d)
	opts := internalproto.CLIJSONMarshalOptions()
	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal proto to JSON: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// diffToProto converts a diff.Diff to sbomv1.DiffResponse.
func diffToProto(d *diff.Diff) *sbomv1.DiffResponse {
	resp := &sbomv1.DiffResponse{}

	// Convert added packages
	for _, pkg := range d.Added {
		resp.Added = append(resp.Added, &dependencyv1.Package{
			Purl:      pkg.PURL,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Licenses:  pkg.Licenses,
		})
	}

	// Convert removed packages
	for _, pkg := range d.Removed {
		resp.Removed = append(resp.Removed, &dependencyv1.Package{
			Purl:      pkg.PURL,
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Licenses:  pkg.Licenses,
		})
	}

	// Convert changed packages
	for _, c := range d.Changed {
		change := &sbomv1.PackageChange{
			Package: &dependencyv1.Package{
				Purl: c.PURL,
				Name: c.Name,
			},
			PreviousVersion: c.OldVersion,
			NewVersion:      c.NewVersion,
			Kind:            changeKindToProto(c.Kind),
		}
		if c.Licenses.HasChange() {
			change.LicenseChange = &sbomv1.LicenseChange{
				Added:   c.Licenses.Added,
				Removed: c.Licenses.Removed,
			}
		}
		resp.Modified = append(resp.Modified, change)
	}

	// Convert stats
	stats := d.Stats()
	resp.Stats = &sbomv1.DiffStats{
		AddedCount:         int32(stats.Added),
		RemovedCount:       int32(stats.Removed),
		ModifiedCount:      int32(stats.Changed),
		BreakingCount:      int32(stats.Breaking),
		DowngradeCount:     int32(stats.Downgrades),
		LicenseChangeCount: int32(stats.LicenseChanges),
	}

	return resp
}

// changeKindToProto converts diff.ChangeKind to sbomv1.ChangeKind.
func changeKindToProto(kind diff.ChangeKind) sbomv1.ChangeKind {
	switch kind {
	case diff.ChangeKindMajor:
		return sbomv1.ChangeKind_CHANGE_KIND_MAJOR
	case diff.ChangeKindMinor:
		return sbomv1.ChangeKind_CHANGE_KIND_MINOR
	case diff.ChangeKindPatch:
		return sbomv1.ChangeKind_CHANGE_KIND_PATCH
	case diff.ChangeKindDowngrade:
		return sbomv1.ChangeKind_CHANGE_KIND_DOWNGRADE
	default:
		return sbomv1.ChangeKind_CHANGE_KIND_UNSPECIFIED
	}
}

// outputDiffText outputs the diff in human-readable text format.
func outputDiffText(w io.Writer, d *diff.Diff, oldPath, newPath string) error {
	fmt.Fprintf(w, "SBOM Diff: %s -> %s\n", oldPath, newPath)
	fmt.Fprintf(w, "========================================\n\n")

	stats := d.Stats()

	fmt.Fprintf(w, "Summary:\n")
	fmt.Fprintf(w, "  Added:           %d packages\n", stats.Added)
	fmt.Fprintf(w, "  Removed:         %d packages\n", stats.Removed)
	fmt.Fprintf(w, "  Changed:         %d packages\n", stats.Changed)
	if stats.Breaking > 0 {
		fmt.Fprintf(w, "  Breaking changes: %d\n", stats.Breaking)
	}
	if stats.Downgrades > 0 {
		fmt.Fprintf(w, "  Downgrades:      %d\n", stats.Downgrades)
	}
	if stats.LicenseChanges > 0 {
		fmt.Fprintf(w, "  License changes: %d\n", stats.LicenseChanges)
	}
	fmt.Fprintln(w)

	if len(d.Added) > 0 {
		fmt.Fprintf(w, "Added (%d):\n", len(d.Added))
		for _, pkg := range d.Added {
			fmt.Fprintf(w, "  + %s\n", pkg.String())
		}
		fmt.Fprintln(w)
	}

	if len(d.Removed) > 0 {
		fmt.Fprintf(w, "Removed (%d):\n", len(d.Removed))
		for _, pkg := range d.Removed {
			fmt.Fprintf(w, "  - %s\n", pkg.String())
		}
		fmt.Fprintln(w)
	}

	if len(d.Changed) > 0 {
		fmt.Fprintf(w, "Changed (%d):\n", len(d.Changed))
		for _, c := range d.Changed {
			kindIndicator := ""
			switch c.Kind {
			case diff.ChangeKindMajor:
				kindIndicator = " [BREAKING]"
			case diff.ChangeKindMinor:
				kindIndicator = " [minor]"
			case diff.ChangeKindPatch:
				kindIndicator = " [patch]"
			case diff.ChangeKindDowngrade:
				kindIndicator = " [DOWNGRADE]"
			}
			fmt.Fprintf(w, "  ~ %s: %s -> %s%s\n", c.Name, c.OldVersion, c.NewVersion, kindIndicator)
			if c.Licenses.HasChange() {
				if len(c.Licenses.Added) > 0 {
					fmt.Fprintf(w, "      licenses +: %s\n", strings.Join(c.Licenses.Added, ", "))
				}
				if len(c.Licenses.Removed) > 0 {
					fmt.Fprintf(w, "      licenses -: %s\n", strings.Join(c.Licenses.Removed, ", "))
				}
			}
		}
		fmt.Fprintln(w)
	}

	if d.Empty() {
		fmt.Fprintln(w, "No changes detected")
	}

	return nil
}
