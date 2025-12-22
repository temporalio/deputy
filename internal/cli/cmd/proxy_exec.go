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
	"sync"
	"time"

	deputyerrors "github.com/picatz/deputy/internal/errors"
	"github.com/picatz/deputy/internal/proxy"
	"github.com/picatz/deputy/internal/ui"
	"github.com/spf13/cobra"
)

// registerProxyExecCommands registers the proxy execution commands for supported ecosystems.
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

// proxyExecSpec defines the configuration for a proxy execution command.
type proxyExecSpec struct {
	name            string
	defaultUpstream string
	short           string
	exampleCmd      string
	envPrep         envPreparer
}

// envPreparer is a function that prepares the environment variables for the proxied command.
// It returns the environment variables, a cleanup function, and an error if any.
type envPreparer func(proxyURL string) ([]string, func(), error)

// proxyExecConfig holds the runtime configuration for a proxy execution.
type proxyExecConfig struct {
	ecosystem   string
	upstream    string
	policyPaths []string
	envPrep     envPreparer
	requested   string
}

// newProxyExecCommand creates a new cobra.Command for a specific proxy execution specification.
func newProxyExecCommand(spec proxyExecSpec) *cobra.Command {
	var (
		upstream string
		policies []string
	)
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
			return runProxyExec(cmd.Context(), cfg, args, cmd.InOrStdin(), cmd.OutOrStdout(), cmd.ErrOrStderr())
		},
	}
	cmd.Flags().StringVar(&upstream, "upstream", spec.defaultUpstream, "Upstream registry to mirror")
	cmd.Flags().StringArrayVar(&policies, "policy", nil, "Additional CEL policy files to enforce")
	cmd.SilenceUsage = true
	cmd.SilenceErrors = true
	trimmed := strings.TrimPrefix(spec.exampleCmd, fmt.Sprintf("deputy proxy %s -- ", spec.name))
	cmd.Example = spec.exampleCmd + "\n# pass additional policy bundles\n" + fmt.Sprintf("deputy proxy %s --policy corp.yaml -- %s", spec.name, trimmed)
	return cmd
}

var startProxyForEcosystem = startEcosystemProxy
var execProxyCommand = runExternalCommand

// runProxyExec executes the proxy command.
// It starts the proxy server, prepares the environment, runs the command, and handles events.
func runProxyExec(ctx context.Context, cfg proxyExecConfig, command []string, stdin io.Reader, stdout, stderr io.Writer) error {
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

	var history eventHistory
	var eventsDone chan struct{}
	if inst.events != nil {
		eventsDone = make(chan struct{})
		go func() {
			defer close(eventsDone)
			streamProxyEvents(eventsCtx, cfg.ecosystem, cfg.requested, inst.events, &history, stderr)
		}()
	}

	// Skip intro line - Deputy announces itself via block messages if/when they occur.
	// This keeps the happy path (no blocks) completely silent.

	env, cleanup, err := cfg.envPrep(inst.url)
	if err != nil {
		return err
	}
	if cleanup != nil {
		defer cleanup()
	}
	if err := execProxyCommand(ctx, command, env, stdin, stdout, stderr); err != nil {
		cancelEvents()
		if eventsDone != nil {
			<-eventsDone
		}
		drainProxyEvents(inst.events, &history)
		printSummaryReport(stderr, history.All(), cfg.requested)
		return deputyerrors.Silent(err)
	}
	return nil
}

func drainProxyEvents(events <-chan proxyEvent, history *eventHistory) {
	if events == nil || history == nil {
		return
	}
	for {
		select {
		case evt := <-events:
			history.Add(evt)
		default:
			return
		}
	}
}

// eventHistory is a thread-safe collector for proxy events.
type eventHistory struct {
	mu     sync.Mutex
	events []proxyEvent
}

// Add appends an event to the history.
func (h *eventHistory) Add(evt proxyEvent) {
	h.mu.Lock()
	defer h.mu.Unlock()
	h.events = append(h.events, evt)
}

// All returns a copy of all collected events.
func (h *eventHistory) All() []proxyEvent {
	h.mu.Lock()
	defer h.mu.Unlock()
	// Return a copy
	out := make([]proxyEvent, len(h.events))
	copy(out, h.events)
	return out
}

// proxyInstance tracks the ephemeral proxy server for a single `deputy proxy` execution.
type proxyInstance struct {
	url    string
	stop   func(context.Context) error
	events <-chan proxyEvent
}

// startEcosystemProxy starts a proxy server for the specified ecosystem.
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

// handlerForEcosystem returns the appropriate HTTP handler for the given ecosystem.
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

// startProxyInstance starts the HTTP server for the proxy handler.
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
type proxyEvent struct {
	status      int
	reason      string
	remediation string
	method      string
	path        string
	policy      string
	ecosystem   string
	name        string
	version     string
	operation   string
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
			status:      status,
			reason:      reason,
			remediation: strings.TrimSpace(hdr.Get("X-Deputy-Remediation")),
			method:      r.Method,
			path:        r.URL.Path,
			policy:      policy,
			ecosystem:   strings.TrimSpace(hdr.Get("X-Deputy-Ecosystem")),
			name:        strings.TrimSpace(hdr.Get("X-Deputy-Name")),
			version:     strings.TrimSpace(hdr.Get("X-Deputy-Version")),
			operation:   strings.TrimSpace(hdr.Get("X-Deputy-Operation")),
		}
		select {
		case events <- evt:
		default:
		}
	})
	return wrapped, events
}

// proxyResponseWriter is a wrapper around http.ResponseWriter that captures the status code and a preview of the body.
type proxyResponseWriter struct {
	http.ResponseWriter
	status int
	buf    *limitedBuffer
}

// newProxyResponseWriter creates a new proxyResponseWriter.
func newProxyResponseWriter(w http.ResponseWriter) *proxyResponseWriter {
	return &proxyResponseWriter{
		ResponseWriter: w,
		buf:            &limitedBuffer{limit: 2048},
	}
}

// Header returns the header map that will be sent by WriteHeader.
func (w *proxyResponseWriter) Header() http.Header { return w.ResponseWriter.Header() }

// WriteHeader sends an HTTP response header with the provided status code.
func (w *proxyResponseWriter) WriteHeader(status int) {
	w.status = status
	w.ResponseWriter.WriteHeader(status)
}

// Write writes the data to the connection as part of an HTTP reply.
func (w *proxyResponseWriter) Write(p []byte) (int, error) {
	if w.status == 0 {
		w.status = http.StatusOK
	}
	w.buf.Write(p)
	return w.ResponseWriter.Write(p)
}

// Status returns the HTTP status code of the response.
func (w *proxyResponseWriter) Status() int {
	if w.status == 0 {
		return http.StatusOK
	}
	return w.status
}

// BodyPreview returns the captured body preview.
func (w *proxyResponseWriter) BodyPreview() string { return w.buf.String() }

// Flush flushes the response writer if it implements http.Flusher.
func (w *proxyResponseWriter) Flush() {
	if f, ok := w.ResponseWriter.(http.Flusher); ok {
		f.Flush()
	}
}

// limitedBuffer is a buffer that limits the amount of data written to it.
type limitedBuffer struct {
	limit int
	b     strings.Builder
}

// Write writes p to the buffer, truncating if the limit is reached.
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

// String returns the contents of the buffer as a string.
func (b *limitedBuffer) String() string {
	return b.b.String()
}

// runExternalCommand executes the given command with the provided environment variables.
func runExternalCommand(ctx context.Context, command []string, extraEnv []string, stdin io.Reader, stdout, stderr io.Writer) error {
	cmd := exec.CommandContext(ctx, command[0], command[1:]...)
	if stdout == nil {
		stdout = os.Stdout
	}
	if stderr == nil {
		stderr = os.Stderr
	}
	if stdin == nil {
		stdin = os.Stdin
	}
	cmd.Stdout = stdout
	cmd.Stderr = stderr
	cmd.Stdin = stdin
	cmd.Env = append(os.Environ(), extraEnv...)
	return cmd.Run()
}

// streamProxyEvents continuously renders policy block events while the proxy runs.
func streamProxyEvents(ctx context.Context, ecosystem, requested string, events <-chan proxyEvent, history *eventHistory, errW io.Writer) {
	for {
		select {
		case <-ctx.Done():
			return
		case evt, ok := <-events:
			if !ok {
				return
			}
			history.Add(evt)
			printPolicyBlock(errW, ecosystem, requested, evt)
		}
	}
}

// printPolicyBlock renders a helpful message for a blocked request.
func printPolicyBlock(errW io.Writer, ecosystem, requested string, evt proxyEvent) {
	if errW == nil {
		errW = io.Discard
	}
	// Construct a display name for the package/artifact
	name := evt.name
	version := evt.version
	if version == "" && requested != "" && strings.Contains(requested, evt.name) {
		// If we blocked a metadata request (no version), but we know what the user asked for,
		// show the requested spec to provide better context.
		if idx := strings.Index(requested, "@"); idx > 0 {
			name = requested[:idx]
			version = requested[idx+1:]
		} else {
			name = requested
		}
	}

	if name == "" {
		name = evt.path
	}

	// Visual separator before the block
	fmt.Fprintln(errW)

	// Header line: × name@version
	// Colors: × (red), name (bold white), @ (slate gray), version (bold white)
	if version != "" {
		fmt.Fprintf(errW, "%s %s%s%s\n",
			ui.StyleRemoved.Render("×"),
			ui.StyleBold.Render(name),
			ui.StyleSeparator.Render("@"),
			ui.StyleBold.Render(version))
	} else {
		fmt.Fprintf(errW, "%s %s\n",
			ui.StyleRemoved.Render("×"),
			ui.StyleBold.Render(name))
	}

	// Policy reference - file::rule with distinct colors
	if evt.policy != "" {
		file := evt.policy
		rule := ""
		if parts := strings.Split(evt.policy, "::"); len(parts) > 1 {
			file = filepath.Base(parts[0])
			rule = parts[1]
		}
		if rule != "" {
			fmt.Fprintf(errW, "  %s%s%s\n",
				ui.StylePolicyFile.Render(file),
				ui.StyleSeparator.Render("::"),
				ui.StylePolicyRule.Render(rule))
		} else {
			fmt.Fprintf(errW, "  %s\n",
				ui.StylePolicyFile.Render(file))
		}
	}

	// Why it was blocked - dim supporting text
	if evt.reason != "" {
		fmt.Fprintf(errW, "  %s\n",
			ui.StyleDim.Render(evt.reason))
	}

	// What to do about it - arrow is green, text is normal white
	if evt.remediation != "" {
		fmt.Fprintln(errW)
		wrapped := wrapText(evt.remediation, 70)
		fmt.Fprintf(errW, "  %s %s\n",
			ui.StyleAdded.Render("→"),
			wrapped)
	}

	fmt.Fprintln(errW)
}

// wrapText wraps long text to the specified width, indenting continuation lines.
// The indent parameter specifies additional spaces for continuation lines.
func wrapText(text string, width int) string {
	if len(text) <= width {
		return text
	}

	var lines []string
	words := strings.Fields(text)
	var currentLine strings.Builder

	for _, word := range words {
		switch {
		case currentLine.Len() == 0:
			currentLine.WriteString(word)
		case currentLine.Len()+1+len(word) <= width:
			currentLine.WriteString(" ")
			currentLine.WriteString(word)
		default:
			lines = append(lines, currentLine.String())
			currentLine.Reset()
			currentLine.WriteString(word)
		}
	}
	if currentLine.Len() > 0 {
		lines = append(lines, currentLine.String())
	}

	if len(lines) <= 1 {
		return text
	}

	// First line as-is, continuation lines indented to align after "→ " (4 spaces: 2 indent + 2 for arrow+space)
	result := lines[0]
	for i := 1; i < len(lines); i++ {
		result += "\n    " + lines[i]
	}
	return result
}

// printSummaryReport emits a summary of blocked requests.
// For a single block, it stays silent (the real-time line is sufficient).
// For multiple blocks, it provides a compact list.
func printSummaryReport(errW io.Writer, events []proxyEvent, requested string) {
	if errW == nil {
		errW = io.Discard
	}
	if len(events) == 0 {
		return
	}

	// Deduplicate events by package+policy to count unique blocks
	type blockInfo struct {
		pkg    string
		reason string
		evt    proxyEvent
	}
	seen := make(map[string]blockInfo)
	for _, evt := range events {
		pkg := evt.name
		switch {
		case evt.version != "":
			pkg = fmt.Sprintf("%s@%s", evt.name, evt.version)
		case requested != "" && evt.name != "" && strings.Contains(requested, evt.name):
			pkg = requested
		}
		if pkg == "" {
			pkg = requested
		}
		key := pkg + "::" + evt.policy
		if _, exists := seen[key]; !exists {
			seen[key] = blockInfo{pkg: pkg, reason: evt.reason, evt: evt}
		}
	}

	// For a single unique block, skip the summary - the real-time line was enough
	if len(seen) <= 1 {
		return
	}

	// Summary header
	fmt.Fprintln(errW)
	fmt.Fprintf(errW, "%s\n",
		ui.StyleRemoved.Render(fmt.Sprintf("── %d packages blocked ──", len(seen))))

	// Compact list
	for _, info := range seen {
		if info.pkg == "" {
			continue
		}
		fmt.Fprintf(errW, "  %s %s\n",
			ui.StyleRemoved.Render("×"),
			ui.StylePackageName.Render(info.pkg))
	}
	fmt.Fprintln(errW)
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

// prepareGoEnv prepares the environment for Go commands.
func prepareGoEnv(proxyURL string) ([]string, func(), error) {
	return []string{"GOPROXY=" + proxyURL + ",direct"}, nil, nil
}

// prepareNPMEnv prepares the environment for NPM commands.
func prepareNPMEnv(proxyURL string) ([]string, func(), error) {
	env := []string{
		"NPM_CONFIG_REGISTRY=" + proxyURL,
		"YARN_REGISTRY=" + proxyURL,
		"NPM_CONFIG_STRICT_SSL=false",
	}
	return env, nil, nil
}

// preparePyPIEnv prepares the environment for PyPI commands.
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

// prepareRubyGemsEnv prepares the environment for RubyGems commands.
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
