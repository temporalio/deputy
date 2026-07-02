package cmd

import (
	"fmt"
	"strings"

	"connectrpc.com/connect"
	"github.com/charmbracelet/lipgloss"

	"github.com/spf13/cobra"

	listv1 "github.com/temporalio/deputy/gen/deputy/list/v1"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/services"
)

// AddEcosystemsCommand adds the ecosystems command to the root.
func AddEcosystemsCommand(root *cobra.Command, c *services.Clients) {
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

  # List ecosystems as JSON
  deputy ecosystems --format json`,
	}

	// List subcommand (default behavior, can be explicit)
	listCmd := newEcosystemsListCommand(c)
	ecosystemsCmd.AddCommand(listCmd)

	// Make list the default when running "deputy ecosystems" with no subcommand
	ecosystemsCmd.RunE = listCmd.RunE
	ecosystemsCmd.Flags().AddFlagSet(listCmd.Flags())

	root.AddCommand(ecosystemsCmd)
}

func newEcosystemsListCommand(c *services.Clients) *cobra.Command {
	var formatFlag string

	cmd := &cobra.Command{
		Use:   "list",
		Short: "List supported ecosystems",
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			// Call client API
			resp, err := c.Packages.ListEcosystems(ctx, connect.NewRequest(&listv1.ListEcosystemsRequest{}))
			if err != nil {
				return fmt.Errorf("list ecosystems failed: %w", err)
			}

			switch formatFlag {
			case "json":
				return printEcosystemsJSON(cmd, resp.Msg.Ecosystems)
			default:
				return printEcosystemsTable(cmd, resp.Msg.Ecosystems)
			}
		},
	}

	cmd.Flags().StringVarP(&formatFlag, "format", "f", "table", "Output format (table, json)")

	return cmd
}

func printEcosystemsTable(cmd *cobra.Command, ecosystems []*listv1.EcosystemInfo) error {
	w := cmd.OutOrStdout()

	// Styles
	headerStyle := lipgloss.NewStyle().Bold(true).Foreground(lipgloss.Color("12"))
	ecoStyle := lipgloss.NewStyle().Bold(true)

	// Header
	fmt.Fprintf(w, "%s  %s  %s  %s\n",
		headerStyle.Render(padRight("Ecosystem", 12)),
		headerStyle.Render(padRight("Description", 32)),
		headerStyle.Render(padRight("Manifests", 30)),
		headerStyle.Render("Lockfiles"),
	)
	fmt.Fprintln(w, strings.Repeat("─", 100))

	for _, eco := range ecosystems {
		manifests := strings.Join(eco.ManifestFiles, ", ")
		lockfiles := strings.Join(eco.LockFiles, ", ")

		fmt.Fprintf(w, "%s  %s  %s  %s\n",
			ecoStyle.Render(padRight(eco.DisplayName, 12)),
			padRight(truncate(eco.Description, 32), 32),
			padRight(truncate(manifests, 30), 30),
			lockfiles,
		)
	}

	fmt.Fprintln(w)
	fmt.Fprintf(w, "Total: %d ecosystems\n", len(ecosystems))

	return nil
}

func printEcosystemsJSON(cmd *cobra.Command, ecosystems []*listv1.EcosystemInfo) error {
	w := cmd.OutOrStdout()

	resp := &listv1.ListEcosystemsResponse{
		Ecosystems: ecosystems,
	}

	opts := internalproto.CLIJSONMarshalOptions()

	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal ecosystems: %w", err)
	}

	_, err = w.Write(data)
	if err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
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
