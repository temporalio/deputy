package cmd

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/picatz/deputy/internal/proxy"
	"github.com/spf13/cobra"
)

func registerProxyExecCommands(proxyCmd *cobra.Command) {
	specs := []proxyExecSpec{
		{
			name:            "go",
			defaultUpstream: "https://proxy.golang.org",
			short:           "Run Go commands with Deputy enforcing module policies",
			exampleCmd:      "deputy proxy go -- go mod download golang.org/x/text@v0.14.0",
			envPrep:         prepareGoEnv,
		},
		{
			name:            "npm",
			defaultUpstream: "https://registry.npmjs.org",
			short:           "Run npm/yarn/pnpm commands through Deputy",
			exampleCmd:      "deputy proxy npm -- npm pack lodash@4.17.21",
			envPrep:         prepareNPMEnv,
		},
		{
			name:            "pypi",
			defaultUpstream: "https://pypi.org",
			short:           "Run pip commands via Deputy's PyPI proxy",
			exampleCmd:      "deputy proxy pypi -- pip download requests==2.31.0 --no-deps",
			envPrep:         preparePyPIEnv,
		},
		{
			name:            "rubygems",
			defaultUpstream: "https://rubygems.org",
			short:           "Run gem/bundle commands with Deputy enforcement",
			exampleCmd:      "deputy proxy rubygems -- gem fetch bundler -v 2.4.22",
			envPrep:         prepareRubyGemsEnv,
		},
	}

	for _, spec := range specs {
		proxyCmd.AddCommand(newProxyExecCommand(spec))
	}
}

type proxyExecSpec struct {
	name            string
	defaultUpstream string
	short           string
	exampleCmd      string
	envPrep         envPreparer
}

type envPreparer func(proxyURL string) ([]string, func(), error)

type proxyExecConfig struct {
	ecosystem   string
	upstream    string
	policyPaths []string
	envPrep     envPreparer
}

func newProxyExecCommand(spec proxyExecSpec) *cobra.Command {
	var upstream string
	var policies []string
	cmd := &cobra.Command{
		Use:   spec.name + " -- <command> [args...]",
		Short: spec.short,
		Args: func(cmd *cobra.Command, args []string) error {
			if len(args) == 0 {
				return errors.New("provide the command to execute after --")
			}
			return nil
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := proxyExecConfig{
				ecosystem:   spec.name,
				upstream:    upstream,
				policyPaths: policies,
				envPrep:     spec.envPrep,
			}
			return runProxyExec(cmd.Context(), cfg, args)
		},
	}
	cmd.Flags().StringVar(&upstream, "upstream", spec.defaultUpstream, "Upstream registry to mirror")
	cmd.Flags().StringArrayVar(&policies, "policy", nil, "Additional CEL policy files to enforce")
	cmd.SilenceUsage = true
	trimmed := strings.TrimPrefix(spec.exampleCmd, fmt.Sprintf("deputy proxy %s -- ", spec.name))
	cmd.Example = spec.exampleCmd + "\n# pass additional policy bundles\n" + fmt.Sprintf("deputy proxy %s --policy corp.yaml -- %s", spec.name, trimmed)
	return cmd
}

var startProxyForEcosystem = startEcosystemProxy
var execProxyCommand = runExternalCommand

func runProxyExec(ctx context.Context, cfg proxyExecConfig, command []string) error {
	if len(command) == 0 {
		return fmt.Errorf("no command specified")
	}
	inst, err := startProxyForEcosystem(ctx, cfg.ecosystem, cfg.upstream, cfg.policyPaths)
	if err != nil {
		return err
	}
	defer func() {
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if err := inst.stop(shutdownCtx); err != nil {
			slog.Debug("proxy shutdown", "error", err)
		}
	}()

	env, cleanup, err := cfg.envPrep(inst.url)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if err := execProxyCommand(ctx, command, env); err != nil {
		return err
	}
	return nil
}

type proxyInstance struct {
	url  string
	stop func(context.Context) error
}

func startEcosystemProxy(ctx context.Context, ecosystem, upstream string, policies []string) (*proxyInstance, error) {
	var evaluator proxy.PolicyEvaluator
	var err error
	if len(policies) > 0 {
		evaluator, err = proxy.NewPolicyEngine(policies)
		if err != nil {
			return nil, err
		}
	}
	handler, err := handlerForEcosystem(ecosystem, upstream, evaluator)
	if err != nil {
		return nil, err
	}
	return startProxyInstance(ctx, handler)
}

func handlerForEcosystem(ecosystem, upstream string, evaluator proxy.PolicyEvaluator) (http.Handler, error) {
	switch ecosystem {
	case "go":
		return proxy.NewGoModuleHandler(upstream, evaluator)
	case "npm":
		return proxy.NewNPMHandler(upstream, evaluator)
	case "pypi":
		return proxy.NewPyPIHandler(upstream, evaluator)
	case "rubygems":
		return proxy.NewRubyGemsHandler(upstream, evaluator)
	default:
		return nil, fmt.Errorf("unsupported ecosystem %q", ecosystem)
	}
}

func startProxyInstance(ctx context.Context, handler http.Handler) (*proxyInstance, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	server := &http.Server{Handler: handler}
	errCh := make(chan error, 1)
	go func() {
		errCh <- server.Serve(ln)
	}()
	go func() {
		<-ctx.Done()
		shutdownCtx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdownCtx)
	}()
	proxyURL := "http://" + ln.Addr().String()
	stop := func(shutdownCtx context.Context) error {
		select {
		case err := <-errCh:
			if errors.Is(err, http.ErrServerClosed) {
				return nil
			}
			return err
		default:
		}
		return server.Shutdown(shutdownCtx)
	}
	return &proxyInstance{url: proxyURL, stop: stop}, nil
}

func runExternalCommand(ctx context.Context, command []string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.Run()
}

func prepareGoEnv(proxyURL string) ([]string, func(), error) {
	return []string{"GOPROXY=" + proxyURL + ",direct"}, nil, nil
}

func prepareNPMEnv(proxyURL string) ([]string, func(), error) {
	env := []string{
		"NPM_CONFIG_REGISTRY=" + proxyURL,
		"YARN_REGISTRY=" + proxyURL,
		"NPM_CONFIG_STRICT_SSL=false",
	}
	return env, nil, nil
}

func preparePyPIEnv(proxyURL string) ([]string, func(), error) {
	parsed, err := url.Parse(proxyURL)
	if err != nil {
		return nil, nil, err
	}
	host := parsed.Hostname()
	if port := parsed.Port(); port != "" {
		host = host + ":" + port
	}
	indexURL := strings.TrimRight(proxyURL, "/") + "/simple"
	env := []string{
		"PIP_INDEX_URL=" + indexURL,
		"PIP_TRUSTED_HOST=" + host,
	}
	return env, nil, nil
}

func prepareRubyGemsEnv(proxyURL string) ([]string, func(), error) {
	dir, err := os.MkdirTemp("", "deputy-gemrc-")
	if err != nil {
		return nil, nil, err
	}
	gemrc := filepath.Join(dir, "gemrc")
	contents := fmt.Sprintf(":sources:\n- %s\n", proxyURL)
	if err := os.WriteFile(gemrc, []byte(contents), 0o644); err != nil {
		os.RemoveAll(dir)
		return nil, nil, err
	}
	env := []string{
		"GEMRC=" + gemrc,
		"GEM_SOURCE=" + proxyURL,
		"BUNDLE_GEM__SOURCE__rubygems__org=" + proxyURL,
	}
	cleanup := func() {
		_ = os.RemoveAll(dir)
	}
	return env, cleanup, nil
}
