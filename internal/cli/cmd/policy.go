package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"

	gocmp "github.com/google/go-cmp/cmp"
	"github.com/spf13/cobra"
	"github.com/temporalio/deputy/internal/cli/flags"
	deperrors "github.com/temporalio/deputy/internal/errors"
	"github.com/temporalio/deputy/internal/otel"
	"github.com/temporalio/deputy/internal/policy"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
	"google.golang.org/protobuf/types/known/structpb"
)

// AddPolicyCommand registers the `deputy policy` command tree.
func AddPolicyCommand(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:           "policy",
		Aliases:       []string{"p", "pol"},
		Short:         "Work with Deputy CEL policies",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long: `Develop, test, and manage Deputy security policies.

Deputy uses the Common Expression Language (CEL) to define security policies for:
• Vulnerability management (e.g., "block critical severity")
• License compliance (e.g., "deny AGPL-3.0")
• Dependency constraints (e.g., "only allow approved scopes")

SUBCOMMANDS:
• eval:    Evaluate a policy against a JSON input
• lint:    Check policy structure, syntax, and types
• test:    Run unit tests for policies
• bundle:  Package multiple policies into a single file
• repl:    Interactive policy development shell
• lsp:     Language Server Protocol support for editors

These tools help you write robust policies before deploying them to the proxy or CI/CD.`,
		Example: `DEVELOPMENT WORKFLOW:
  # 1. Write a policy
  echo 'vulnerabilities.exists(v, v.Severity == "CRITICAL")' > policy.yaml

  # 2. Lint it
  deputy policy lint policy.yaml

  # 3. Test it interactively
  deputy policy repl

  # 4. Evaluate against real data
  deputy policy eval --policy policy.yaml --input context.json`,
	}
	cmd.AddCommand(newPolicyEvalCommand())
	cmd.AddCommand(newPolicyExamplesCommand())
	cmd.AddCommand(newPolicyLintCommand())
	cmd.AddCommand(newPolicyTestCommand())
	cmd.AddCommand(newPolicyBundleCommand())
	cmd.AddCommand(newPolicyInspectCommand())
	cmd.AddCommand(newPolicySimulateCommand())
	cmd.AddCommand(newPolicyREPLCommand())
	cmd.AddCommand(newPolicyLSPCommand())
	root.AddCommand(cmd)
}

// newPolicyEvalCommand creates the `eval` subcommand for evaluating policies.
func newPolicyEvalCommand() *cobra.Command {
	var (
		policyPath string
		inputPath  string
		format     string
	)
	cmd := &cobra.Command{
		Use:           "eval --policy policy.yaml --input input.json",
		Short:         "Evaluate a CEL policy against JSON input",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, span := otel.StartSpan(cmd.Context(), "deputy.policy.eval",
				trace.WithAttributes(
					attribute.String("deputy.policy.path", policyPath),
					attribute.String("deputy.policy.input", inputPath),
				))
			defer span.End()

			if strings.TrimSpace(policyPath) == "" {
				return deperrors.Suggest(
					errors.New("missing --policy path"),
					"Provide a policy file with --policy policy.yaml (see policy/examples/ for samples)",
				)
			}
			if strings.TrimSpace(inputPath) == "" {
				return deperrors.Suggest(
					errors.New("missing --input path"),
					"Provide input JSON with --input context.json (use 'deputy scan --format json' to generate)",
				)
			}
			policyBytes, err := readPathOrStdin(cmd.InOrStdin(), policyPath)
			if err != nil {
				otel.SetSpanError(span, err)
				return fmt.Errorf("read policy %q: %w", policyPath, err)
			}
			inputBytes, err := readPathOrStdin(cmd.InOrStdin(), inputPath)
			if err != nil {
				otel.SetSpanError(span, err)
				return fmt.Errorf("read input %q: %w", inputPath, err)
			}
			var payload map[string]any
			if err := json.Unmarshal(inputBytes, &payload); err != nil {
				otel.SetSpanError(span, err)
				return fmt.Errorf("parse input JSON: %w", err)
			}
			result, err := policy.Evaluate(ctx, string(policyBytes), payload)
			if err != nil {
				otel.SetSpanError(span, err)
				return fmt.Errorf("evaluate policy: %w", err)
			}
			otel.SetSpanOK(span)
			return writePolicyEvalOutput(cmd.OutOrStdout(), result, format)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to CEL policy source (use '-' for stdin)")
	cmd.Flags().StringVar(&inputPath, "input", "", "Path to JSON input (use '-' for stdin)")
	cmd.Flags().StringVar(&format, "format", "json", "Output format: json or text")
	return cmd
}

// newPolicyExamplesCommand creates the `examples` subcommand for generating example inputs.
func newPolicyExamplesCommand() *cobra.Command {
	var (
		level    string
		output   string
		listOnly bool
	)
	cmd := &cobra.Command{
		Use:   "examples [entrypoint]",
		Short: "Generate example input JSON for policy testing",
		Long: `Generate canonical example inputs for policy development and testing.

Examples use real Deputy proto types with realistic values that match what
you'll see in production. This helps you write policies with confidence
before deploying them.

ENTRYPOINT CATEGORIES:
  scan            Vulnerability scanning (scan_vulnerability, scan_report)
  proxy           Package proxy requests (go_artifact_request, npm_artifact_request, ...)
  diff            Dependency diffs (diff_report, diff_vulnerability, ...)
  container_diff  Container image diffs (container_diff_report, ...)
  dockerfile      Dockerfile analysis (dockerfile_report, dockerfile_stage)
  sbom            SBOM generation (sbom_report, sbom_component)
  graph           Dependency graphs (graph_report, graph_node, graph_edge)
  fix             Remediation planning (fix_plan, fix_plan_step)
  triage          Vulnerability triage (triage_report, triage_cluster)
  secrets         Secret scanning (secrets_report, secrets_finding)
  server          API authorization (service_scan_request, ...)
  sandbox         Sandboxed execution control (sandbox_execution, sandbox_command, ...)

Legacy aliases "container" and "service" are accepted where Deputy filters by
category, but generated examples use canonical category names.

DETAIL LEVELS:
  minimal       Only required fields with simplest values
  typical       Common fields users will encounter (default)
  comprehensive All fields with rich examples including enrichment data`,
		Example: `# List all available entrypoints
  deputy policy examples --list

  # Generate typical example for scan_vulnerability
  deputy policy examples scan_vulnerability

  # Generate comprehensive example with all fields
  deputy policy examples scan_vulnerability --level comprehensive

  # Save to file for testing
  deputy policy examples scan_vulnerability -o input.json

  # Quick workflow: generate input, then test policy
  deputy policy examples scan_vulnerability -o /tmp/input.json
  deputy policy eval --policy my-policy.yaml --input /tmp/input.json`,
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			// List mode
			if listOnly || len(args) == 0 {
				return listPolicyEntrypoints(cmd.OutOrStdout())
			}

			// Generate example mode
			epName := args[0]
			ep := policy.Entrypoint(epName)

			// Validate entrypoint
			profile := policy.GetBindingProfile(ep)
			if profile == nil {
				return deperrors.Suggest(
					fmt.Errorf("unknown entrypoint: %q", epName),
					"Run 'deputy policy examples --list' to see available entrypoints",
				)
			}

			// Parse level
			var exLevel policy.ExampleLevel
			switch strings.ToLower(level) {
			case "minimal", "min":
				exLevel = policy.ExampleLevelMinimal
			case "typical", "typ", "":
				exLevel = policy.ExampleLevelTypical
			case "comprehensive", "comp", "full":
				exLevel = policy.ExampleLevelComprehensive
			default:
				return deperrors.Suggest(
					fmt.Errorf("unknown level: %q", level),
					"Use 'minimal', 'typical', or 'comprehensive'",
				)
			}

			// Generate example
			example, err := policy.GenerateExample(ep, exLevel)
			if err != nil {
				return err
			}

			// Output
			dest, err := openOutputWriter(cmd, output)
			if err != nil {
				return err
			}
			defer dest.Close()
			out := dest.Writer

			// Write header comment if to stdout
			if output == "" || output == "-" {
				fmt.Fprintf(out, "// Example input for entrypoint: %s\n", ep)
				fmt.Fprintf(out, "// Level: %s\n", exLevel)
				fmt.Fprintf(out, "// %s\n", example.Description)
				if len(example.Comments) > 0 {
					fmt.Fprintln(out, "//")
					fmt.Fprintln(out, "// Variables:")
					for _, c := range example.Comments {
						fmt.Fprintf(out, "//   %s\n", c)
					}
				}
				fmt.Fprintln(out, "//")
				fmt.Fprintln(out, "// Severity constants (use in CEL expressions):")
				fmt.Fprintln(out, "//   severity.critical    = 4  (CVSS 9.0-10.0)")
				fmt.Fprintln(out, "//   severity.high        = 3  (CVSS 7.0-8.9)")
				fmt.Fprintln(out, "//   severity.medium      = 2  (CVSS 4.0-6.9)")
				fmt.Fprintln(out, "//   severity.low         = 1  (CVSS 0.1-3.9)")
				fmt.Fprintln(out, "//   severity.unspecified = 0")
				fmt.Fprintln(out, "//")
				fmt.Fprintln(out, "// Example CEL expressions:")
				fmt.Fprintln(out, "//   vulnerability.advisory.severity.level == severity.critical")
				fmt.Fprintln(out, "//   vulnerability.advisory.severity.level in [severity.critical, severity.high]")
				fmt.Fprintln(out, "//   vulnerability.package.direct == true")
				fmt.Fprintln(out, "//   size(vulnerability.advisory.fixed_versions) > 0")
				fmt.Fprintln(out)
			}

			fmt.Fprintln(out, example.JSON)
			return nil
		},
	}
	cmd.Flags().StringVarP(&level, "level", "l", "typical", "Detail level: minimal, typical, comprehensive")
	cmd.Flags().StringVarP(&output, "output", "o", "", "Output file (default: stdout)")
	cmd.Flags().BoolVar(&listOnly, "list", false, "List all available entrypoints")
	return cmd
}

// listPolicyEntrypoints prints all available entrypoints organized by category.
func listPolicyEntrypoints(w io.Writer) error {
	fmt.Fprintln(w, "Available policy entrypoints:")
	fmt.Fprintln(w)

	for _, cat := range policy.ExampleCategories {
		fmt.Fprintf(w, "  %s - %s\n", cat.Name, cat.Description)
		for _, ep := range cat.Entrypoints {
			profile := policy.GetBindingProfile(ep)
			if profile != nil {
				fmt.Fprintf(w, "    • %-30s %s\n", ep, profile.Description)
			} else {
				fmt.Fprintf(w, "    • %s\n", ep)
			}
		}
		fmt.Fprintln(w)
	}

	fmt.Fprintln(w, "Usage:")
	fmt.Fprintln(w, "  deputy policy examples <entrypoint>              Generate typical example")
	fmt.Fprintln(w, "  deputy policy examples <entrypoint> --level min  Minimal required fields")
	fmt.Fprintln(w, "  deputy policy examples <entrypoint> --level comp All fields with enrichment")
	fmt.Fprintln(w)
	fmt.Fprintln(w, "Example workflow:")
	fmt.Fprintln(w, "  deputy policy examples scan_vulnerability -o input.json")
	fmt.Fprintln(w, "  deputy policy eval --policy policy.yaml --input input.json")

	return nil
}

// newPolicyLintCommand creates the `lint` subcommand for validating policies.
func newPolicyLintCommand() *cobra.Command {
	var extraVars []string
	cmd := &cobra.Command{
		Use:           "lint <policy.yaml> [policy2.yaml ...]",
		Short:         "Lint policy bundles for structure, syntax, and type issues",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stdinUsed := false
			failures := 0
			for _, path := range args {
				data, err := readPathOrStdinOnce(cmd.InOrStdin(), path, &stdinUsed)
				if err != nil {
					return fmt.Errorf("read %q: %w", path, err)
				}
				// Prefer structured lint for YAML bundles: it validates the whole
				// bundle, not just the CEL, and reports clearer errors. The choice is
				// made from the bytes, so a bundle reaches the same checks however it
				// is supplied; deciding it from the path used to lint a piped bundle
				// as raw CEL and fail on its first key.
				handled, problems, err := lintStructuredBundle(data, path, extraVars, cmd.OutOrStdout())
				if err != nil {
					return err
				}
				if handled {
					failures += problems
					continue
				}
				// A compiled bundle holds its policies as compiled CEL, so it is loaded
				// as the policies it carries rather than compiled as one expression.
				// Loading it from the bytes is what makes stdin behave as the
				// identical file does, since stdin has no path to reread.
				if policy.IsCompiledBundle(data) {
					sources, err := policy.LoadSourcesFromBytes(data, path)
					if err != nil {
						return err
					}
					if err := lintSources(sources, extraVars); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s OK\n", labelPath(path))
					continue
				}
				// Raw CEL. Stdin is checked as the one source it is, while a file is
				// loaded, since it may hold several. Both go through lintSources, so a
				// source piped in is asked the same questions as the identical file.
				if path == "-" {
					if err := lintSources([]policy.Source{{Name: path, Body: string(data)}}, extraVars); err != nil {
						return err
					}
					fmt.Fprintf(cmd.OutOrStdout(), "%s OK\n", labelPath(path))
					continue
				}
				sources, err := policy.LoadSources([]string{path})
				if err != nil {
					return err
				}
				if err := lintSources(sources, extraVars); err != nil {
					return err
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s OK\n", labelPath(path))
			}
			if failures > 0 {
				return fmt.Errorf("%d policy problem(s) found", failures)
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&extraVars, "var", nil, "Additional variable names to declare while linting (repeatable)")
	return cmd
}

// lintSources checks every source a policy file loaded into the way loading it to
// run it does: the CEL has to compile, and the `//!` metadata beside it has to name
// vocabularies Deputy recognizes. It stops at the first source that fails, in the
// order the engine asks the same two questions, and renders a compiler failure with
// the caret snippet lint uses for a condition. A file may hold several policies, and
// a compiled bundle holds one source per policy it was built from.
//
// The metadata check is the engine's own (policy.ValidateSourceMetadata) rather than
// a second reading of it, and it is here for the raw source lint reads off stdin,
// which is the one source that reaches this without a loader having refused it
// already. A loaded source is checked as it is loaded, and an authored bundle
// reaches the same vocabularies through the node walk (see policy.ValidateBundle),
// so every path lint takes asks what loading the source to run it asks. Checking
// only the CEL let lint certify an artifact the loader refuses, which is worse than
// no lint: it is Deputy telling an operator their policy is fine.
func lintSources(sources []policy.Source, extraVars []string) error {
	for _, src := range sources {
		if err := policy.Compile(src.Body, extraVars); err != nil {
			known := append(policy.DefaultVariableNames(), extraVars...)
			return fmt.Errorf("%s: %s", src.Name, formatCelCompileError(err, src.Body, known))
		}
		if err := policy.ValidateSourceMetadata(src); err != nil {
			return err
		}
	}
	return nil
}

// lintStructuredBundle validates a YAML structured bundle with the same checks
// the editor runs, printing every issue it finds instead of stopping at the
// first. It reports handled=false when the data is not a structured bundle so
// the caller can fall back to compiling it as raw CEL, and returns the number of
// issues serious enough to fail the run (hints are advice, not failures).
//
// It takes the bytes rather than reading them, so stdin and a file are linted
// the same way; path only names the source in the issues it prints.
func lintStructuredBundle(data []byte, path string, extraVars []string, out io.Writer) (handled bool, problems int, err error) {
	// Gate on the bundle's shape, not on whether it decodes: a policy with a
	// mistyped field must reach validation and be told which field is wrong,
	// rather than falling through to the generic unrecognized-format error.
	if !policy.LooksLikeStructuredBundle(data) {
		return false, 0, nil
	}
	issues, err := policy.ValidateBundle(string(data), policy.ValidateOptions{
		Source:    path,
		ExtraVars: extraVars,
		CheckWhen: func(when policy.RuleWhen) []policy.Issue {
			compileErr := policy.Compile(when.Expr, when.DeclaredVars)
			if compileErr == nil {
				return nil
			}
			known := append(policy.DefaultVariableNames(), when.DeclaredVars...)
			return []policy.Issue{{
				Policy:    when.Policy,
				RuleIndex: when.RuleIndex,
				Line:      when.Line,
				Column:    when.Column,
				Severity:  policy.IssueError,
				Code:      "cel-error",
				Message:   formatCelCompileError(compileErr, when.Expr, known),
			}}
		},
	})
	if err != nil {
		return true, 0, fmt.Errorf("lint %q: %w", path, err)
	}
	for _, issue := range issues {
		if issue.Severity != policy.IssueHint {
			problems++
		}
		fmt.Fprintf(out, "%s\n", formatLintIssue(path, issue))
	}
	if problems == 0 {
		fmt.Fprintf(out, "%s OK\n", labelPath(path))
	}
	return true, problems, nil
}

// formatLintIssue renders one issue as a file-anchored line an editor or a human
// can jump to. Issues that come from loading the bundle name the file in their
// own message, so that prefix is dropped rather than printed twice.
func formatLintIssue(path string, issue policy.Issue) string {
	text := strings.Replace(issue.String(), path+"/", "", 1)
	text = strings.Replace(text, path+": ", "", 1)
	if issue.Line <= 0 {
		return fmt.Sprintf("%s: %s", labelPath(path), text)
	}
	return fmt.Sprintf("%s:%s", labelPath(path), text)
}

// readPathOrStdin reads data from the given path or stdin if path is "-".
func readPathOrStdin(stdin io.Reader, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

// readPathOrStdinOnce reads data from the given path or stdin, ensuring stdin is only read once.
func readPathOrStdinOnce(stdin io.Reader, path string, used *bool) ([]byte, error) {
	if path != "-" {
		return os.ReadFile(path)
	}
	if used != nil && *used {
		return nil, errors.New("stdin already consumed")
	}
	if used != nil {
		*used = true
	}
	return io.ReadAll(stdin)
}

// writePolicyEvalOutput writes the evaluation result to the writer in the specified format.
func writePolicyEvalOutput(w io.Writer, value any, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatJSON:
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal evaluation result: %w", err)
		}
		_, err = w.Write(append(data, '\n'))
		return err
	case FormatText:
		_, err := fmt.Fprintf(w, "%v\n", value)
		return err
	default:
		return flags.UnsupportedFormatError("--format", format, "text|json")
	}
}

// labelPath returns a display label for the given path, using "stdin" for "-".
func labelPath(path string) string {
	if path == "-" {
		return "stdin"
	}
	return path
}

var celErrRe = regexp.MustCompile(`ERROR: <input>:(\d+):(\d+): (.+)`)
var celErrPrefixRe = regexp.MustCompile(`(?i)^(cel:\s*)?error:\s*<input>:\d+:\d+:\s*`)
var undeclaredNameRe = regexp.MustCompile(`undeclared reference to '([^']+)'`)

// formatCelCompileError prettifies CEL errors with a caret snippet.
func formatCelCompileError(err error, src string, known []string) string {
	msg := err.Error()
	m := celErrRe.FindStringSubmatch(msg)
	if len(m) != 4 {
		return celDetail(msg)
	}
	lineNum := toInt(m[1])
	colNum := toInt(m[2])
	detail := celDetail(m[3])
	if name := extractUndeclaredName(msg); name != "" {
		if sugg, ok := suggestName(name, known); ok {
			detail = fmt.Sprintf("%s (did you mean '%s'?)", detail, sugg)
		}
	}
	lines := strings.Split(src, "\n")
	if lineNum < 1 || lineNum > len(lines) {
		return celDetail(msg)
	}
	line := strings.ReplaceAll(lines[lineNum-1], "\t", " ")
	// A caret needs a character to sit under. CEL names a line with none when the
	// source is empty, as a compiled bundle carrying no source for a policy is, and
	// when the error falls on a blank line inside one. Clamping the column to the
	// end of that line put it before the line's start and panicked the process, so
	// the detail is reported without a snippet, as the editor's formatter does.
	if line == "" {
		return celDetail(msg)
	}
	target := colNum - 1
	if name := extractUndeclaredName(msg); name != "" {
		if idx := strings.Index(line, name); idx >= 0 {
			target = idx
		}
	}
	if target < 0 {
		target = 0
	}
	if target >= len(line) {
		target = len(line) - 1
	}
	caret := strings.Repeat(" ", target) + "^"
	return fmt.Sprintf("CEL: %s\n%s\n%s", detail, line, caret)
}

// toInt converts a string to an integer, returning 0 on error.
func toInt(s string) int {
	n, _ := strconv.Atoi(s)
	return n
}

// celDetail mirrors LSP formatting: strip container suffix, first line only, drop generated CEL tail.
func celDetail(s string) string {
	if idx := strings.IndexByte(s, '\n'); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, " (in container"); idx >= 0 {
		s = s[:idx]
	}
	if idx := strings.Index(s, "|"); idx >= 0 {
		s = s[:idx]
	}
	s = celErrPrefixRe.ReplaceAllString(s, "")
	if idx := strings.Index(s, " | "); idx >= 0 {
		s = s[:idx]
	}
	return s
}

// extractUndeclaredName extracts the name of the undeclared variable from a CEL error message.
func extractUndeclaredName(msg string) string {
	m := undeclaredNameRe.FindStringSubmatch(msg)
	if len(m) == 2 {
		return m[1]
	}
	return ""
}

// suggestName finds the closest matching name from the known list using Levenshtein distance.
func suggestName(name string, known []string) (string, bool) {
	best := ""
	bestDist := 3
	for _, k := range known {
		d := levenshteinDistance(name, k)
		if d < bestDist {
			bestDist = d
			best = k
		}
	}
	if best == "" {
		return "", false
	}
	return best, true
}

// levenshteinDistance calculates the Levenshtein distance between two strings.
func levenshteinDistance(a, b string) int {
	la, lb := len(a), len(b)
	if la == 0 {
		return lb
	}
	if lb == 0 {
		return la
	}
	if la > lb {
		a, b = b, a
		la, lb = lb, la
	}
	prev := make([]int, la+1)
	for i := 0; i <= la; i++ {
		prev[i] = i
	}
	for j := 1; j <= lb; j++ {
		curr := make([]int, la+1)
		curr[0] = j
		for i := 1; i <= la; i++ {
			cost := 0
			if a[i-1] != b[j-1] {
				cost = 1
			}
			del := prev[i] + 1
			ins := curr[i-1] + 1
			sub := prev[i-1] + cost
			curr[i] = min(del, ins, sub)
		}
		prev = curr
	}
	return prev[la]
}

// newPolicyTestCommand creates the `test` subcommand for running policy tests.
func newPolicyTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:           "test <case.policytest.json|dir> [more...]",
		Short:         "Execute policy tests defined in JSON fixtures",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			files, err := collectPolicyTestFiles(args)
			if err != nil {
				return err
			}
			ctx := cmd.Context()
			total := 0
			for _, file := range files {
				n, err := runPolicyTestFile(ctx, file, cmd)
				if err != nil {
					return err
				}
				total += n
			}
			fmt.Fprintf(cmd.OutOrStdout(), "\n%d policy test(s) passed\n", total)
			return nil
		},
	}
	return cmd
}

// newPolicyBundleCommand creates the `bundle` subcommand for compiling policies into a bundle.
func newPolicyBundleCommand() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:           "bundle --output bundle.json <policy.yaml> [policy2.yaml ...]",
		Short:         "Compile CEL policies into a reusable bundle",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(outPath) == "" {
				return errors.New("missing --output path for bundle")
			}
			if len(args) == 0 {
				return errors.New("provide at least one CEL policy file")
			}
			bundle, err := policy.BuildBundle(args)
			if err != nil {
				return err
			}
			data, err := json.MarshalIndent(bundle, "", "  ")
			if err != nil {
				return err
			}
			if outPath == "-" {
				_, err = cmd.OutOrStdout().Write(append(data, '\n'))
				return err
			}
			return os.WriteFile(outPath, append(data, '\n'), 0o644)
		},
	}
	cmd.Flags().StringVarP(&outPath, "output", "o", "", "Destination bundle file (use '-' for stdout)")
	return cmd
}

// newPolicyInspectCommand creates the `inspect` subcommand for inspecting policies or bundles.
func newPolicyInspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:           "inspect <policy-or-bundle> [more...]",
		Short:         "Inspect CEL policies or bundles",
		SilenceErrors: true,
		SilenceUsage:  true,
		Args:          cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			for _, path := range args {
				if err := inspectPolicyPath(cmd.OutOrStdout(), path); err != nil {
					return err
				}
			}
			return nil
		},
	}
}

// newPolicySimulateCommand creates the `simulate` subcommand for running policies against inputs.
func newPolicySimulateCommand() *cobra.Command {
	var (
		policies []string
		inputs   []string
		format   string
	)
	cmd := &cobra.Command{
		Use:           "simulate --policy policy.yaml --input input.json",
		Short:         "Run policies against recorded JSON inputs",
		SilenceErrors: true,
		SilenceUsage:  true,
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(policies) == 0 {
				return errors.New("at least one --policy file is required")
			}
			if len(inputs) == 0 {
				return errors.New("at least one --input file is required")
			}
			payloads, err := loadSimulationInputs(cmd.InOrStdin(), inputs)
			if err != nil {
				return err
			}
			if len(payloads) == 0 {
				return fmt.Errorf("no payloads to evaluate")
			}
			sources, err := policy.LoadSources(policies)
			if err != nil {
				return err
			}
			for i, payload := range payloads {
				// Wrap arbitrary JSON in structpb.Struct for proto-first evaluation
				inputProto, err := structpb.NewStruct(payload)
				if err != nil {
					return fmt.Errorf("input %d: convert to proto: %w", i, err)
				}
				actions, err := policy.EvaluateAll(cmd.Context(), sources, inputProto)
				if err != nil {
					return fmt.Errorf("input %d: %w", i, err)
				}
				if err := writeSimulationResult(cmd.OutOrStdout(), format, i, payload, actions); err != nil {
					return err
				}
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&policies, "policy", nil, "Policy file or bundle to execute (repeatable)")
	cmd.Flags().StringArrayVar(&inputs, "input", nil, "JSON payload file or '-' for stdin (repeatable)")
	cmd.Flags().StringVar(&format, "format", "text", "Output format: text or json")
	return cmd
}

// policyTestCase represents a single test case for policy validation.
type policyTestCase struct {
	Name      string           `json:"name"`
	Policy    string           `json:"policy,omitempty"`
	Policies  []string         `json:"policies,omitempty"`
	Input     string           `json:"input"`
	InputJSON map[string]any   `json:"input_json,omitempty"`
	Want      []map[string]any `json:"want"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

// collectPolicyTestFiles gathers all policy test files from the provided paths.
func collectPolicyTestFiles(paths []string) ([]string, error) {
	var files []string
	for _, p := range paths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, err
		}
		if info.IsDir() {
			err = filepath.WalkDir(p, func(path string, d os.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() {
					return nil
				}
				if strings.HasSuffix(d.Name(), ".policytest.json") {
					files = append(files, path)
				}
				return nil
			})
			if err != nil {
				return nil, err
			}
			continue
		}
		files = append(files, p)
	}
	if len(files) == 0 {
		return nil, errors.New("no policy test files found")
	}
	slices.Sort(files)
	return files, nil
}

// runPolicyTestFile executes all test cases defined in a single file.
func runPolicyTestFile(ctx context.Context, path string, cmd *cobra.Command) (int, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return 0, fmt.Errorf("read %s: %w", path, err)
	}
	var cases []policyTestCase
	trim := strings.TrimSpace(string(data))
	if strings.HasPrefix(trim, "[") {
		if err := json.Unmarshal(data, &cases); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
	} else {
		var single policyTestCase
		if err := json.Unmarshal(data, &single); err != nil {
			return 0, fmt.Errorf("parse %s: %w", path, err)
		}
		cases = []policyTestCase{single}
	}
	baseDir := filepath.Dir(path)
	for i := range cases {
		if err := executePolicyTestCase(ctx, baseDir, path, &cases[i], cmd); err != nil {
			return i, err
		}
	}
	return len(cases), nil
}

// executePolicyTestCase runs a single policy test case and compares the result with the expected output.
func executePolicyTestCase(ctx context.Context, baseDir, file string, tc *policyTestCase, cmd *cobra.Command) error {
	name := tc.Name
	if name == "" {
		name = file
	}
	var policyPaths []string
	switch {
	case len(tc.Policies) > 0:
		policyPaths = append(policyPaths, tc.Policies...)
	case tc.Policy != "":
		policyPaths = append(policyPaths, tc.Policy)
	default:
		return fmt.Errorf("%s: test %q missing policy path", file, name)
	}
	for i, p := range policyPaths {
		if !filepath.IsAbs(p) {
			policyPaths[i] = filepath.Join(baseDir, p)
		}
	}
	inputMap := map[string]any{}
	switch {
	case tc.InputJSON != nil:
		inputMap = tc.InputJSON
	case strings.TrimSpace(tc.Input) != "":
		path := tc.Input
		if !filepath.IsAbs(path) {
			path = filepath.Join(baseDir, path)
		}
		bytes, err := os.ReadFile(path)
		if err != nil {
			return fmt.Errorf("%s (%s): %w", name, file, err)
		}
		if err := json.Unmarshal(bytes, &inputMap); err != nil {
			return fmt.Errorf("%s (%s): parse input: %w", name, file, err)
		}
	}

	sources, err := policy.LoadSources(policyPaths)
	if err != nil {
		return fmt.Errorf("%s (%s): %w", name, file, err)
	}
	// Wrap arbitrary JSON in structpb.Struct for proto-first evaluation
	inputProto, err := structpb.NewStruct(inputMap)
	if err != nil {
		return fmt.Errorf("%s (%s): convert to proto: %w", name, file, err)
	}
	actions, err := policy.EvaluateAll(ctx, sources, inputProto)
	if err != nil {
		return fmt.Errorf("%s (%s): %w", name, file, err)
	}
	actual := actionsToComparable(actions)
	if diff := gocmp.Diff(tc.Want, actual); diff != "" {
		return fmt.Errorf("%s (%s): unexpected actions (-want +got):\n%s", name, file, diff)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ %s\n", name)
	return nil
}

// actionsToComparable converts a list of policy actions into a comparable map format.
func actionsToComparable(actions []policy.Action) []map[string]any {
	out := make([]map[string]any, 0, len(actions))
	for _, act := range actions {
		if act.Raw != nil {
			out = append(out, act.Raw)
			continue
		}
		entry := map[string]any{
			"action": act.Type,
		}
		if act.Reason != "" {
			entry["reason"] = act.Reason
		}
		if act.Message != "" {
			entry["message"] = act.Message
		}
		if act.Remediation != "" {
			entry["remediation"] = act.Remediation
		}
		if act.Code != "" {
			entry["code"] = act.Code
		}
		if act.Status != nil {
			entry["status"] = *act.Status
		}
		if len(act.Headers) > 0 {
			entry["headers"] = act.Headers
		}
		if len(act.Annotations) > 0 {
			entry["annotations"] = act.Annotations
		}
		out = append(out, entry)
	}
	return out
}

// inspectPolicyPath inspects a policy file or bundle and prints its metadata.
func inspectPolicyPath(w io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bundle, ok := policy.ParseBundle(data); ok {
		// Describing a bundle is not the same question as loading one, and inspect
		// used to answer only the first: it read the bundle's shape and reported the
		// policies it holds, so a bundle whose `//! policy.mode` the loader refuses
		// was described as if Deputy could run it. Ask the loader for its verdict
		// before reporting anything, so every command that reads a compiled bundle
		// agrees about which ones are bundles Deputy will load.
		//
		// The shape is still read separately because the loader returns the policy
		// sources and not the schema version or the generation time, which are what
		// inspect exists to show.
		if _, err := policy.LoadSourcesFromBytes(data, path); err != nil {
			return err
		}
		fmt.Fprintf(w, "Bundle: %s\n", path)
		fmt.Fprintf(w, "  Schema: %s\n", bundle.SchemaVersion)
		if bundle.Generated != "" {
			fmt.Fprintf(w, "  Generated: %s\n", bundle.Generated)
		}
		fmt.Fprintf(w, "  Policies:\n")
		for _, p := range bundle.Policies {
			fmt.Fprintf(w, "    - %s\n", p.Name)
		}
		return nil
	}
	return fmt.Errorf("%s is not a policy bundle", path)
}

// loadSimulationInputs reads simulation inputs from the provided paths.
func loadSimulationInputs(stdin io.Reader, paths []string) ([]map[string]any, error) {
	var payloads []map[string]any
	stdinUsed := false
	for _, path := range paths {
		data, err := readPathOrStdinOnce(stdin, path, &stdinUsed)
		if err != nil {
			return nil, err
		}
		chunks, err := parseSimulationPayloads(data)
		if err != nil {
			return nil, fmt.Errorf("%s: %w", path, err)
		}
		payloads = append(payloads, chunks...)
	}
	return payloads, nil
}

// parseSimulationPayloads parses JSON data into a list of payloads.
func parseSimulationPayloads(data []byte) ([]map[string]any, error) {
	trim := strings.TrimSpace(string(data))
	if trim == "" {
		return nil, nil
	}
	if strings.HasPrefix(trim, "[") {
		var arr []map[string]any
		if err := json.Unmarshal([]byte(trim), &arr); err != nil {
			return nil, err
		}
		return arr, nil
	}
	if strings.HasPrefix(trim, "{") {
		var obj map[string]any
		if err := json.Unmarshal([]byte(trim), &obj); err != nil {
			return nil, err
		}
		return []map[string]any{obj}, nil
	}
	return nil, fmt.Errorf("input must be JSON object or array")
}

// writeSimulationResult writes the simulation result to the writer in the specified format.
func writeSimulationResult(w io.Writer, format string, index int, payload map[string]any, actions []policy.Action) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", FormatText:
		fmt.Fprintf(w, "Input %d:\n", index)
		for _, act := range actions {
			fmt.Fprintf(w, "  %s from %s", strings.ToUpper(act.Type), act.Source)
			if act.Reason != "" {
				fmt.Fprintf(w, ": %s", act.Reason)
			}
			fmt.Fprintln(w)
		}
		return nil
	case FormatJSON:
		out := map[string]any{
			"inputIndex": index,
			"input":      payload,
			"actions":    actionsToComparable(actions),
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	default:
		return flags.UnsupportedFormatError("--format", format, "text|json")
	}
}
