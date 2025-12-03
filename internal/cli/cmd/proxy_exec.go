package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"log/slog"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync/atomic"
	"time"

	"github.com/charmbracelet/lipgloss"
	"github.com/picatz/deputy/internal/proxy"
	"github.com/picatz/deputy/internal/ui"
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
	requested   string
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
				requested:   deriveRequestedSpec(spec.name, args),
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
	prevLogger := slog.Default()
	quietHandler := slog.NewTextHandler(io.Discard, &slog.HandlerOptions{Level: slog.LevelWarn})
	slog.SetDefault(slog.New(quietHandler))
	defer slog.SetDefault(prevLogger)

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

	eventsCtx, cancelEvents := context.WithCancel(ctx)
	defer cancelEvents()
	var lastEvent atomic.Pointer[proxyEvent]
	if inst.events != nil {
		go streamProxyEvents(eventsCtx, cfg.ecosystem, cfg.requested, inst.events, &lastEvent)
	}

	printProxyIntro(cfg, inst.url, command)

	env, cleanup, err := cfg.envPrep(inst.url)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if err := execProxyCommand(ctx, command, env); err != nil {
		if last := lastEvent.Load(); last == nil {
			fmt.Fprintf(os.Stderr, "[deputy] command failed (no policy event captured): %v\n", err)
		} else {
			printSummaryLine(*last, cfg.requested)
		}
		return err
	}
	return nil
}

// proxyInstance tracks the ephemeral proxy server for a single `deputy proxy` execution.
type proxyInstance struct {
	url    string
	stop   func(context.Context) error
	events <-chan proxyEvent
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
	instrumented, events := instrumentProxyHandler(handler)
	inst, err := startProxyInstance(ctx, instrumented)
	if err != nil {
		return nil, err
	}
	inst.events = events
	return inst, nil
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

// proxyEvent captures metadata about a proxied request that was denied by policy.
// proxyEvent captures metadata about a proxied request that was denied by policy.
// proxyEvent captures metadata about a proxied request that was denied by policy.
type proxyEvent struct {
	status    int
	reason    string
	method    string
	path      string
	policy    string
	ecosystem string
	name      string
	version   string
	operation string
}

// instrumentProxyHandler wraps the handler and emits proxyEvents when a denial occurs.
func instrumentProxyHandler(handler http.Handler) (http.Handler, <-chan proxyEvent) {
	events := make(chan proxyEvent, 16)
	wrapped := http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		rec := newProxyResponseWriter(w)
		handler.ServeHTTP(rec, r)
		status := rec.Status()
		hdr := rec.Header()
		policy := hdr.Get("X-Deputy-Policy")
		if status < 400 || (policy == "" && status != http.StatusForbidden) {
			return
		}
		reason := strings.TrimSpace(hdr.Get("X-Deputy-Reason"))
		if reason == "" {
			reason = strings.TrimSpace(rec.BodyPreview())
		}
		evt := proxyEvent{
			status:    status,
			reason:    reason,
			method:    r.Method,
			path:      r.URL.Path,
			policy:    policy,
			ecosystem: strings.TrimSpace(hdr.Get("X-Deputy-Ecosystem")),
			name:      strings.TrimSpace(hdr.Get("X-Deputy-Name")),
			version:   strings.TrimSpace(hdr.Get("X-Deputy-Version")),
			operation: strings.TrimSpace(hdr.Get("X-Deputy-Operation")),
		}
		select {
		case events <- evt:
		default:
		}
	})
	return wrapped, events
}

type proxyResponseWriter struct {
	http.ResponseWriter
	status int
	buf    *limitedBuffer
}

func newProxyResponseWriter(w http.ResponseWriter) *proxyResponseWriter {
	return &proxyResponseWriter{
		ResponseWriter: w,
		buf:            &limitedBuffer{limit: 2048},
	}
}

func (w *proxyResponseWriter) Header() http.Header { return w.ResponseWriter.Header() }

func (w *proxyResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

func (w *proxyResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.buf.Write(p)
	return w.ResponseWriter.Write(p)
}

func (w *proxyResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

func (w *proxyResponseWriter) BodyPreview() string { return w.buf.String() }

func (w *proxyResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

type limitedBuffer struct {
	limit int
	b     strings.Builder
}

func (b *limitedBuffer) Write(p []byte) {
	if b.limit <= 0 {
		return
	}
	remaining := b.limit - b.b.Len()
	if remaining <= 0 {
		return
	}
	if len(p) > remaining {
		p = p[:remaining]
	}
	_, _ = b.b.Write(p)
}

func (b *limitedBuffer) String() string {
	return b.b.String()
}

func runExternalCommand(ctx context.Context, command []string, extraEnv []string) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	cmd.Stdin = os.Stdin
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.Run()
}

// printProxyIntro renders a short header describing the proxied session.
func printProxyIntro(cfg proxyExecConfig, proxyURL string, command []string) {
	// Compact, single-line intro to reduce visual noise.
	// e.g. "deputy: proxying npm • policy: shai-hulud-npm.yaml"
	parts := []string{
		ui.StyleHeader.Render(fmt.Sprintf("deputy: proxying %s", cfg.ecosystem)),
	}
	if len(cfg.policyPaths) > 0 {
		shortPolicies := make([]string, len(cfg.policyPaths))
		for i, p := range cfg.policyPaths {
			shortPolicies[i] = filepath.Base(p)
		}
		parts = append(parts, ui.StyleMeta.Render(fmt.Sprintf("policy: %s", strings.Join(shortPolicies, ", "))))
	} else {
		parts = append(parts, ui.StyleMeta.Render("policy: none"))
	}
	
	// Join with a bullet point
	fmt.Fprintln(os.Stderr, strings.Join(parts, ui.StyleDim.Render(" • ")))
}

// streamProxyEvents continuously renders policy block events while the proxy runs.
func streamProxyEvents(ctx context.Context, ecosystem, requested string, events <-chan proxyEvent, last *atomic.Pointer[proxyEvent]) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			last.Store(&evt)
			printPolicyBlock(ecosystem, requested, evt)
		}
	}
}

// printPolicyBlock renders a formatted block describing a policy denial.
func printPolicyBlock(ecosystem, requested string, evt proxyEvent) {
	fmt.Fprintln(os.Stderr)
	
	// Determine labels based on ecosystem
	subjectLabel := "Subject"
	switch ecosystem {
	case "npm", "pypi", "rubygems":
		subjectLabel = "Package"
	case "go":
		subjectLabel = "Module"
	}

	fmt.Fprintf(os.Stderr, "%s %s %s\n", ui.StyleRemoved.Render("deputy: blocked"), ui.StyleRemoved.Render(ui.StyleSymbol.Render("×")), formatStatus(evt.status))
	
	pkg := pickFirst(evt.version, requested, evt.name)
	if pkg != "" {
		printColoredRow(subjectLabel, ui.StylePackageName.Render(pkg))
	}
	
	// Simplify request display: "GET /foo" -> "/foo" if it's just metadata, or keep it if it's interesting.
	// For now, we'll just show the path to keep it cleaner, or the operation if known.
	reqDesc := evt.path
	if evt.operation != "" && evt.operation != "metadata" {
		reqDesc = fmt.Sprintf("%s (%s)", evt.path, evt.operation)
	}
	printColoredRow("Request", ui.StylePath.Render(reqDesc))

	if pol := pickFirst(evt.policy); pol != "" {
		// Truncate policy path for display if it's too long
		displayPol := pol
		if parts := strings.Split(pol, "::"); len(parts) > 1 {
			// If it's "path/to/file.yaml::policy-name", show "file.yaml::policy-name"
			file := filepath.Base(parts[0])
			displayPol = file + "::" + parts[1]
		}
		printColoredRow("Policy", ui.StyleMeta.Render(displayPol))
	}
	if reason := pickFirst(evt.reason); reason != "" {
		printColoredRow("Reason", ui.StyleRemoved.Render(reason))
	}
}

func printAligned(w io.Writer, key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	fmt.Fprintf(w, "  %-10s: %s\n", key, value)
}

// printColoredRow writes an aligned key/value pair using Deputy CLI styles.
func printColoredRow(key, value string) {
	if strings.TrimSpace(value) == "" {
		return
	}
	// Dynamic padding based on key length, assuming max ~10 chars for alignment
	keyWidth := 10
	pad := keyWidth - lipgloss.Width(key)
	if pad < 1 {
		pad = 1
	}
	label := ui.StyleMeta.Render(key)
	fmt.Fprintf(os.Stderr, "  %s%s %s\n", label, strings.Repeat(" ", pad), value)
}

// pickFirst returns the first non-empty value in the provided list.
func pickFirst(values ...string) string {
	for _, v := range values {
		if s := strings.TrimSpace(v); s != "" {
			return s
		}
	}
	return ""
}

// formatStatus renders an HTTP status code using the warning color palette.
func formatStatus(status int) string {
	if status <= 0 {
		return ui.StyleMeta.Render("unknown")
	}
	return lipgloss.NewStyle().Foreground(lipgloss.Color("#FF5555")).Bold(true).Render(fmt.Sprintf("%d", status))
}

// printSummaryLine emits a compact summary after a blocked proxied command.
func printSummaryLine(evt proxyEvent, requested string) {
	pkg := pickFirst(evt.version, requested, evt.name)
	status := formatStatus(evt.status)
	reason := pickFirst(evt.reason)
	parts := []string{ui.StyleRemoved.Render(ui.StyleSymbol.Render("×")), status}
	if pkg != "" {
		parts = append(parts, ui.StylePackageName.Render(pkg))
	}
	if reason != "" {
		parts = append(parts, ui.StyleRemoved.Render(reason))
	}
	fmt.Fprintf(os.Stderr, "deputy: %s", strings.Join(parts, " "))
	if evt.policy != "" {
		// Truncate policy path for display if it's too long
		displayPol := evt.policy
		if parts := strings.Split(evt.policy, "::"); len(parts) > 1 {
			file := filepath.Base(parts[0])
			displayPol = file + "::" + parts[1]
		}
		fmt.Fprintf(os.Stderr, " %s", ui.StyleMeta.Render(fmt.Sprintf("(%s)", displayPol)))
	}
	fmt.Fprintln(os.Stderr)
}

// deriveRequestedSpec heuristically extracts the requested package spec from the child command.
func deriveRequestedSpec(ecosystem string, command []string) string {
	if len(command) == 0 {
		return ""
	}
	skips := map[string]map[string]bool{
		"npm": {
			"install": true, "add": true, "i": true, "ci": true, "update": true, "upgrade": true, "pack": true,
		},
		"go": {
			"mod": true, "download": true, "get": true,
		},
		"pypi": {
			"install": true, "download": true, "pip": true, "pip3": true,
		},
		"rubygems": {
			"install": true, "fetch": true, "bundle": true, "exec": true,
		},
	}
	var fallback string
	for _, tok := range command {
		if strings.HasPrefix(tok, "-") {
			continue
		}
		low := strings.ToLower(tok)
		if skips[ecosystem][low] {
			continue
		}
		if strings.Contains(tok, "@") || strings.Contains(tok, "==") || strings.Contains(tok, ":") || strings.Contains(tok, "/") {
			return tok
		}
		if fallback == "" {
			fallback = tok
		}
	}
	return fallback
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
