package cmd

import (
	"fmt"

	"github.com/picatz/deputy/internal/proxy"
	"github.com/spf13/cobra"
)

// AddProxyCommand adds the "proxy" command and its subcommands to the root command.
// The proxy command allows running Deputy as an artifact proxy server.
func AddProxyCommand(root *cobra.Command) {
	var cfgPath string
	var extraPolicies []string

	proxyCmd := &cobra.Command{
		Use:   "proxy",
		Short: "Run Deputy's artifact proxy",
		Long: `Run a policy-enforcing artifact proxy for various package managers.

The proxy intercepts requests to upstream registries (like proxy.golang.org, npmjs.org, PyPI, RubyGems)
and evaluates CEL policies against the requested packages. If a policy denies a package (e.g., due to
vulnerabilities, license issues, or naming conventions), the proxy blocks the download.

MODES:
• exec: Run a single command wrapped with proxy configuration (e.g., 'deputy proxy go -- go get ...')
• serve: Run a standalone proxy server (requires configuration file)

SUPPORTED ECOSYSTEMS:
• Go (proxy.golang.org protocol)
• npm (npm registry protocol)
• PyPI (Simple API)
• RubyGems (Gem server API)

This tool is essential for "secure-by-default" development environments where you want to prevent
risky dependencies from ever entering your codebase.`,
		Example: `EXECUTION WRAPPERS:
  # Run go get with policy enforcement
  deputy proxy go -- go get github.com/example/pkg@latest

  # Run npm install with policy enforcement
  deputy proxy npm -- npm install

  # Run pip install with policy enforcement
  deputy proxy pypi -- pip install requests

STANDALONE SERVER:
  # Generate a starter configuration
  deputy proxy template > proxy.yaml

  # Run the proxy server
  deputy proxy serve --config proxy.yaml`,
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
