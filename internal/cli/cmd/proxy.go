package cmd

import (
	"fmt"

	deperrors "github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/proxy"
	"github.com/spf13/cobra"
)

// AddProxyCommand adds the "proxy" command and its subcommands to the root command.
// The proxy command allows running Deputy as an artifact proxy server.
func AddProxyCommand(root *cobra.Command) {
	var (
		cfgPath       string
		extraPolicies []string
		enableReadyz  bool
		enablePprof   bool
		enableVars    bool
	)

	proxyCmd := &cobra.Command{
		Use:           "proxy",
		Aliases:       []string{"px"},
		Short:         "Run Deputy's artifact proxy",
		SilenceErrors: true,
		SilenceUsage:  true,
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
• OCI (container registry API)

AUTHENTICATION:
The proxy supports JWT-based authentication via OIDC/JWKS. Configure auth in your proxy.yaml:
• mode: disabled (default), optional (validate if present), or required (reject without token)
• jwks: JWKS endpoint URL for key discovery (supports OIDC auto-discovery)
• static_keys: Inline public keys for offline validation
• issuers: Trusted token issuers (iss claim validation)
• audiences: Expected audiences (aud claim validation)
• required_claims: Claims that must be present in tokens

JWT claims are exposed as the 'jwt' variable in CEL policies, enabling claim-based access control.

This tool is essential for "secure-by-default" development environments where you want to prevent
risky dependencies from ever entering your codebase.`,
		Example: `EXECUTION WRAPPERS:
  # Run go get with policy enforcement
  deputy proxy go -- go get github.com/example/pkg@latest

  # Run npm install with policy enforcement
  deputy proxy npm -- npm install

  # Run pip install with policy enforcement
  deputy proxy pypi -- pip install requests

  # Run docker pull with policy enforcement
  deputy proxy oci -- docker pull ubuntu:latest

STANDALONE SERVER:
  # Generate a starter configuration
  deputy proxy template > proxy.yaml

  # Run the proxy server
  deputy proxy serve --config proxy.yaml

AUTHENTICATION (in proxy.yaml):
  listeners:
    - name: go-secure
      bind: ":8080"
      ecosystems: ["go"]
      upstream: https://proxy.golang.org
      policies: ["policy.yaml"]
      auth:
        mode: required
        jwks:
          url: https://auth.example.com/.well-known/jwks.json
        issuers: ["https://auth.example.com"]
        audiences: ["deputy-proxy"]`,
	}

	serveCmd := &cobra.Command{
		Use:           "serve --config proxy.yaml",
		Short:         "Serve the Deputy proxy based on the configuration file",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if cfgPath == "" {
				return deperrors.Suggest(
					fmt.Errorf("missing --config"),
					"Create a config file with 'deputy proxy template > proxy.yaml' then use --config proxy.yaml",
				)
			}
			cfg, err := proxy.LoadConfig(cfgPath)
			if err != nil {
				return err
			}
			server := proxy.NewServer(cfg, proxy.Options{
				PolicyPaths:  extraPolicies,
				EnableReadyz: enableReadyz,
				EnablePprof:  enablePprof,
				EnableVars:   enableVars,
			})
			return server.Serve(cmd.Context())
		},
	}
	serveCmd.Flags().StringVarP(&cfgPath, "config", "c", "", "Proxy configuration file (YAML/JSON)")
	serveCmd.Flags().StringArrayVar(&extraPolicies, "policy", nil, "Additional CEL policy files or bundles (repeatable)")
	serveCmd.Flags().BoolVar(&enableReadyz, "readyz", false, "Expose /readyz endpoint")
	serveCmd.Flags().BoolVar(&enablePprof, "pprof", false, "Expose /debug/pprof/* endpoints")
	serveCmd.Flags().BoolVar(&enableVars, "vars", false, "Expose /debug/vars endpoint (includes cache stats)")

	templateCmd := &cobra.Command{
		Use:           "template [ecosystem]",
		Short:         "Emit a starter proxy configuration",
		SilenceErrors: true,
		SilenceUsage:  true,
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
	proxyCmd.AddCommand(serveCmd, templateCmd, newOCIConfigCommand())
	root.AddCommand(proxyCmd)
}
