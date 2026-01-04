package cmd

import (
	"fmt"
	"net/url"
	"strings"

	"github.com/spf13/cobra"
)

func newOCIConfigCommand() *cobra.Command {
	var (
		proxyHost string
		proxyURL  string
		upstream  string
	)

	cmd := &cobra.Command{
		Use:           "oci-config",
		Short:         "Emit Docker/Podman registry config snippets for the OCI proxy",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			host, scheme, err := resolveOCIProxyTarget(proxyHost, proxyURL)
			if err != nil {
				return err
			}
			out := renderOCIConfigSnippets(host, scheme, upstream)
			fmt.Fprint(cmd.OutOrStdout(), out)
			return nil
		},
	}

	cmd.Flags().StringVar(&proxyHost, "host", "", "Proxy host:port (e.g., 127.0.0.1:8084)")
	cmd.Flags().StringVar(&proxyURL, "url", "", "Proxy URL (e.g., http://127.0.0.1:8084)")
	cmd.Flags().StringVar(&upstream, "upstream", "", "Upstream registry host for mirror snippets (e.g., ghcr.io)")
	return cmd
}

func resolveOCIProxyTarget(host, rawURL string) (string, string, error) {
	host = strings.TrimSpace(host)
	rawURL = strings.TrimSpace(rawURL)
	if host == "" && rawURL == "" {
		return "", "", fmt.Errorf("provide --host or --url")
	}
	if host != "" && rawURL != "" {
		return "", "", fmt.Errorf("use only one of --host or --url")
	}
	if rawURL != "" {
		parsed, err := url.Parse(rawURL)
		if err != nil {
			return "", "", fmt.Errorf("parse url: %w", err)
		}
		if parsed.Host == "" {
			return "", "", fmt.Errorf("url %q missing host", rawURL)
		}
		scheme := strings.ToLower(strings.TrimSpace(parsed.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		return parsed.Host, scheme, nil
	}
	scheme := "http"
	if strings.Contains(host, "://") {
		parsed, err := url.Parse(host)
		if err != nil {
			return "", "", fmt.Errorf("parse host: %w", err)
		}
		if parsed.Host == "" {
			return "", "", fmt.Errorf("host %q missing hostname", host)
		}
		scheme = strings.ToLower(strings.TrimSpace(parsed.Scheme))
		if scheme == "" {
			scheme = "http"
		}
		return parsed.Host, scheme, nil
	}
	return host, scheme, nil
}

func renderOCIConfigSnippets(proxyHost, scheme, upstream string) string {
	if scheme == "" {
		scheme = "http"
	}
	insecure := scheme != "https"
	upstreamHost := strings.TrimSpace(upstream)
	if upstreamHost == "" {
		upstreamHost = "<UPSTREAM_REGISTRY>"
	}
	proxyURL := scheme + "://" + proxyHost
	insecureVal := "false"
	if insecure {
		insecureVal = "true"
	}

	var b strings.Builder
	b.WriteString("# Docker daemon.json (registry mirror)\n")
	b.WriteString("# Add this under the root object in /etc/docker/daemon.json\n")
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"registry-mirrors\": [\"%s\"]\n", proxyURL))
	b.WriteString("}\n\n")

	b.WriteString("# Docker daemon.json (insecure registry for HTTP)\n")
	b.WriteString("# Only needed when the proxy is HTTP (not HTTPS).\n")
	b.WriteString("{\n")
	b.WriteString(fmt.Sprintf("  \"insecure-registries\": [\"%s\"]\n", proxyHost))
	b.WriteString("}\n\n")

	b.WriteString("# Podman /etc/containers/registries.conf (mirror)\n")
	b.WriteString("# Adjust prefix/location for your upstream registry.\n")
	b.WriteString("[[registry]]\n")
	b.WriteString(fmt.Sprintf("prefix = \"%s\"\n", upstreamHost))
	b.WriteString(fmt.Sprintf("location = \"%s\"\n\n", upstreamHost))
	b.WriteString("[[registry.mirror]]\n")
	b.WriteString(fmt.Sprintf("location = \"%s\"\n", proxyHost))
	b.WriteString(fmt.Sprintf("insecure = %s\n\n", insecureVal))

	b.WriteString("# Podman /etc/containers/registries.conf (direct registry)\n")
	b.WriteString("[[registry]]\n")
	b.WriteString(fmt.Sprintf("location = \"%s\"\n", proxyHost))
	b.WriteString(fmt.Sprintf("insecure = %s\n", insecureVal))
	return b.String()
}
