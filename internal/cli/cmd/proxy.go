package cmd

import (
	"fmt"

	"github.com/picatz/deputy/internal/proxy"
	"github.com/spf13/cobra"
)

func AddProxyCommand(root *cobra.Command) {
	var cfgPath string
	var extraPolicies []string

	proxyCmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run Deputy's artifact proxy",
	}

	serveCmd := &cobra.Command{
		Use:   "serve --config proxy.yaml",
		Short: "Serve the Deputy proxy based on the configuration file",
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgPath == "" {
				return fmt.Errorf("missing --config")
			}
			cfg, err := proxy.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			server := proxy.NewServer(cfg, proxy.Options{PolicyPaths: extraPolicies})
			return server.Serve(cmd.Context())
		},
	}
	serveCmd.Flags().StringVarP(&cfgPath, "config", "c", "", "Proxy configuration file (YAML/JSON)")
	serveCmd.Flags().StringArrayVar(&extraPolicies, "policy", nil, "Additional CEL policy files or bundles (repeatable)")

	templateCmd := &cobra.Command{
		Use:   "template [ecosystem]",
		Short: "Emit a starter proxy configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			ecosystem := ""
			if len(args) > 0 {
				ecosystem = args[0]
			}
			out, err := proxy.MarshalTemplate(ecosystem)
			if err != nil {
				return err
			}
			fmt.Fprintln(cmd.OutOrStdout(), out)
			return nil
		},
	}

	registerProxyExecCommands(proxyCmd)
	proxyCmd.AddCommand(serveCmd, templateCmd)
	root.AddCommand(proxyCmd)
}
