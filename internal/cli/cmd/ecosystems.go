package cmd

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/ecosystem"
	"github.com/spf13/cobra"
)

// AddEcosystemsCommand adds the ecosystems command to the root.
func AddEcosystemsCommand(root *cobra.Command) {
	ecosystemsCmd := &cobra.Command{
		Use:     "ecosystems",
		Aliases: []string{"eco"},
		Short:   "List supported package ecosystems and their capabilities",
		Long: `List all package ecosystems supported by Deputy and their capabilities.

Each ecosystem may support different features:
  • Inventory   Extract dependencies from lockfiles
  • Graph       Resolve dependency graph edges
  • Proxy       Download-time policy enforcement
  • License     License lookup enrichment
  • Fix         Automated fix suggestions
  • SBOM        Software Bill of Materials generation`,
		Example: `  # List all ecosystems
  deputy ecosystems

  # Show ecosystems with proxy support
  deputy ecosystems --capability proxy

  # List ecosystems as JSON
  deputy ecosystems --format json`,
	}

	// List subcommand (default behavior, can be explicit)
	listCmd := newEcosystemsListCommand()
	ecosystemsCmd.AddCommand(listCmd)

	// Make list the default when running "deputy ecosystems" with no subcommand
	ecosystemsCmd.RunE = listCmd.RunE
	ecosystemsCmd.Flags().AddFlagSet(listCmd.Flags())

	root.AddCommand(ecosystemsCmd)
}

func newEcosystemsListCommand() *cobra.Command {
	var (
		formatFlag     string
		capabilityFlag string
	)

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List supported ecosystems",
		RunE: func(cmd *cobra.Command, args []string) error {
			reg := ecosystem.Default()
			registrations := reg.All()

			// Filter by capability if specified
			if capabilityFlag != "" {
				cap := parseCapability(capabilityFlag)
				if cap == 0 {
					return fmt.Errorf("unknown capability: %s (valid: inventory, graph, proxy, license, fix, sbom)", capabilityFlag)
				}
				registrations = reg.WithCapability(cap)
			}

			switch formatFlag {
			case "json":
				return printEcosystemsJSON(cmd, registrations)
			default:
				return printEcosystemsTable(cmd, registrations)
			}
		},
	}

	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json)")
	cmd.Flags().StringVarP(&capabilityFlag, "capability", "c", "", "Filter by capability (inventory, graph, proxy, license, fix, sbom)")

	return cmd
}

func parseCapability(s string) ecosystem.Capability {
	switch strings.ToLower(strings.TrimSpace(s)) {
	case "inventory", "inv":
		return ecosystem.CapInventory
	case "graph":
		return ecosystem.CapGraph
	case "proxy":
		return ecosystem.CapProxy
	case "license", "lic":
		return ecosystem.CapLicense
	case "fix":
		return ecosystem.CapFix
	case "sbom":
		return ecosystem.CapSBOM
	default:
		return 0
	}
}

func printEcosystemsTable(cmd *cobra.Command, registrations []ecosystem.Registration) error {
	w := cmd.OutOrStdout()

	// Styles
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	ecoStyle := lipgloss.NewStyle().Bold(true)
	checkStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("10"))
	dashStyle := lipgloss.NewStyle().Foreground(lipgloss.Color("8"))

	check := checkStyle.Render("✓")
	dash := dashStyle.Render("·")

	// Header
	fmt.Fprintf(w, "%s  %s  %s  %s  %s  %s  %s  %s\n",
		headerStyle.Render(padRight("Ecosystem", 12)),
		headerStyle.Render(padRight("Description", 32)),
		headerStyle.Render("Inv"),
		headerStyle.Render("Grp"),
		headerStyle.Render("Prx"),
		headerStyle.Render("Lic"),
		headerStyle.Render("Fix"),
		headerStyle.Render("SBM"),
	)
	fmt.Fprintln(w, strings.Repeat("─", 80))

	for _, reg := range registrations {
		caps := reg.Capabilities

		fmt.Fprintf(w, "%s  %s  %s   %s   %s   %s   %s   %s\n",
			ecoStyle.Render(padRight(reg.DisplayName, 12)),
			padRight(truncate(reg.Description, 32), 32),
			capMark(caps&ecosystem.CapInventory != 0, check, dash),
			capMark(caps&ecosystem.CapGraph != 0, check, dash),
			capMark(caps&ecosystem.CapProxy != 0, check, dash),
			capMark(caps&ecosystem.CapLicense != 0, check, dash),
			capMark(caps&ecosystem.CapFix != 0, check, dash),
			capMark(caps&ecosystem.CapSBOM != 0, check, dash),
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Capabilities: Inv=Inventory, Grp=Graph, Prx=Proxy, Lic=License, Fix=Fix, SBM=SBOM\n")
	fmt.Fprintf(w, "Total: %d ecosystems\n", len(registrations))

	return nil
}

func printEcosystemsJSON(cmd *cobra.Command, registrations []ecosystem.Registration) error {
	w := cmd.OutOrStdout()

	fmt.Fprintln(w, "{")
	fmt.Fprintln(w, `  "ecosystems": [`)

	for i, reg := range registrations {
		caps := reg.CapabilityList()
		capStrs := make([]string, len(caps))
		for j, c := range caps {
			capStrs[j] = fmt.Sprintf("%q", strings.ToLower(c.String()))
		}

		aliasStrs := make([]string, len(reg.Aliases))
		for j, a := range reg.Aliases {
			aliasStrs[j] = fmt.Sprintf("%q", a)
		}

		lockfileStrs := make([]string, len(reg.Lockfiles))
		for j, l := range reg.Lockfiles {
			lockfileStrs[j] = fmt.Sprintf("%q", l)
		}

		comma := ","
		if i == len(registrations)-1 {
			comma = ""
		}

		fmt.Fprintf(w, `    {
      "id": %q,
      "name": %q,
      "description": %q,
      "aliases": [%s],
      "capabilities": [%s],
      "lockfiles": [%s],
      "upstream": %q,
      "osv_name": %q
    }%s
`,
			reg.Ecosystem,
			reg.DisplayName,
			reg.Description,
			strings.Join(aliasStrs, ", "),
			strings.Join(capStrs, ", "),
			strings.Join(lockfileStrs, ", "),
			reg.UpstreamURL,
			reg.OSVName,
			comma,
		)
	}

	fmt.Fprintln(w, "  ]")
	fmt.Fprintln(w, "}")

	return nil
}

func capMark(has bool, check, dash string) string {
	if has {
		return check
	}
	return dash
}

func padRight(s string, n int) string {
	if len(s) >= n {
		return s[:n]
	}
	return s + strings.Repeat(" ", n-len(s))
}

func truncate(s string, n int) string {
	if len(s) <= n {
		return s
	}
	if n <= 3 {
		return s[:n]
	}
	return s[:n-3] + "..."
}
