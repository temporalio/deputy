package cmd

import (
	"context"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"

	dependencyv1 "github.com/temporalio/deputy/gen/deputy/dependency/v1"
	policyv1 "github.com/temporalio/deputy/gen/deputy/policy/v1"
	vulnerabilityv1 "github.com/temporalio/deputy/gen/deputy/vulnerability/v1"
	"github.com/temporalio/deputy/internal/policy"
	"github.com/temporalio/deputy/internal/ui"
	"github.com/temporalio/deputy/internal/ui/repl"
	"github.com/spf13/cobra"
)

// newPolicyREPLCommand creates the `repl` subcommand for interactive policy evaluation.
func newPolicyREPLCommand() *cobra.Command {
	return &cobra.Command{
		Use:           "repl",
		Short:         "Interactive CEL policy playground",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long:          "Start an interactive REPL for experimenting with CEL expressions using mock data and all available helper functions.",
		RunE: func(cmd *cobra.Command, args []string) error {
			in := cmd.InOrStdin()
			out := cmd.OutOrStdout()
			return runPolicyREPL(cmd.Context(), in, out)
		},
	}
}

// runPolicyREPL starts the Read-Eval-Print Loop for CEL policies.
func runPolicyREPL(ctx context.Context, in io.Reader, out io.Writer) error {
	// Create new REPL engine with proto-driven completions
	engine := repl.NewEngine(in, out, nil)
	output := engine.Output()
	rl := engine.InteractiveReadLine()

	// Wire up tab completion
	rl.SetCompleter(func(line string, cursor int) []string {
		// Check if we're completing a :command
		if strings.HasPrefix(line, ":") {
			return completeREPLCommand(line, cursor)
		}

		completions := engine.Complete(line, cursor)
		if len(completions) == 0 {
			return nil
		}

		// Find the token start position (same logic as completion engine)
		tokenStart := cursor
		for tokenStart > 0 {
			r := rune(line[tokenStart-1])
			if !((r >= 'a' && r <= 'z') || (r >= 'A' && r <= 'Z') || (r >= '0' && r <= '9') || r == '_' || r == '.') {
				break
			}
			tokenStart--
		}

		result := make([]string, 0, len(completions))
		for _, c := range completions {
			// Build full line: prefix (before token) + completion + suffix (after cursor)
			result = append(result, line[:tokenStart]+c.Text+line[cursor:])
		}
		return result
	})

	output.Welcome(
		"CEL Policy REPL",
		"Evaluate CEL expressions with all Deputy helper functions.",
	)
	output.Hint("Type :help for commands, :example to load sample data")
	output.Blank()

	// Legacy output for command handling (will be phased out)
	legacyOutput := ui.NewREPLOutput(out)

	request := map[string]string{}
	entrypoint := "proxy"

	for {
		// Build prompt string: "proxy ›" - simple and clean
		t := engine.Config().Theme
		prompt := t.Context.Render(entrypoint) + " " + t.Prompt.Render(t.PromptSymbol) + " "

		line, err := rl.Read(ctx, prompt)
		if err != nil {
			if err == io.EOF {
				output.Goodbye()
				return nil
			}
			return err
		}
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}

		// Add to history
		rl.AddHistory(line)

		// Handle meta-commands
		if strings.HasPrefix(line, ":") {
			result, err := handleREPLCommandV2(line, request, &entrypoint, legacyOutput)
			if err != nil {
				if errors.Is(err, errReplExit) {
					output.Goodbye()
					return nil
				}
				output.Error(err.Error())
			} else if result != "" {
				output.Print(engine.Config().Theme.Info.Render(result) + "\n")
			}
			continue
		}

		// Build payload with default variables
		payload := buildREPLPayload(request, entrypoint)

		// Evaluate expression
		result, err := policy.Evaluate(ctx, line, payload)
		if err != nil {
			// Try to provide helpful hints for common errors
			hint := suggestFix(line, err.Error())
			if hint != "" {
				output.ErrorWithHint(err.Error(), hint)
			} else {
				output.Error(err.Error())
			}
			continue
		}

		// Show result with type info
		typeName := fmt.Sprintf("%T", result)
		output.Result(result, typeName)
	}
}

var errReplExit = errors.New("repl exit")

// handleREPLCommandV2 processes REPL meta-commands with styled output.
func handleREPLCommandV2(line string, request map[string]string, entrypoint *string, r *ui.REPLOutput) (string, error) {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return "", nil
	}

	switch parts[0] {
	case ":help", ":h":
		r.Section("Commands")
		r.CommandHelpAligned([]ui.CommandHelpRow{
			{":set key=value", "set request field"},
			{":unset key", "remove request field"},
			{":clear", "remove all request fields"},
			{":show", "display current context"},
			{":example", "load scan vulnerability example (lodash CVE-2021-23337)"},
			{":proxy", "load proxy request example (npm lodash download)"},
			{":vuln", "load Log4Shell example (CVE-2021-44228)"},
			{":graph", "load graph example data"},
			{":entrypoint NAME", "set entrypoint context"},
			{":functions", "list available helper functions"},
			{":vars", "list available variables"},
			{":severity", "show severity constants"},
			{":exit / :quit / :q", "exit the REPL"},
		})
		r.Blank()
		r.Section("Examples")
		r.CELExample(`vulnerability.severity == severity.HIGH`)
		r.CELExample(`vulnerability.isDirect && size(vulnerability.fixedVersions) > 0`)
		r.CELExample(`request.package == "lodash" && request.version == "4.17.20"`)
		r.CELExample(`severityAtLeast(vulnerability, "HIGH")`)
		r.Blank()
		return "", nil

	case ":set":
		if len(parts) < 2 {
			return "", fmt.Errorf(":set requires key=value")
		}
		kv := strings.Join(parts[1:], " ")
		idx := strings.Index(kv, "=")
		if idx <= 0 {
			return "", fmt.Errorf("invalid format, use key=value")
		}
		key := strings.TrimSpace(kv[:idx])
		value := strings.TrimSpace(kv[idx+1:])
		if key == "" {
			return "", fmt.Errorf("key cannot be empty")
		}
		request[key] = value
		return fmt.Sprintf("set request.%s = %q", key, value), nil

	case ":unset":
		if len(parts) < 2 {
			return "", fmt.Errorf(":unset requires key")
		}
		key := parts[1]
		delete(request, key)
		return fmt.Sprintf("unset request.%s", key), nil

	case ":clear":
		for k := range request {
			delete(request, k)
		}
		return "request cleared", nil

	case ":show":
		r.Section("Context: " + *entrypoint)
		r.FormatContext("request", toAnyMap(request))
		r.Blank()
		r.Section("Available Constants")
		r.KeyValue("severity", "CRITICAL, HIGH, MEDIUM, LOW, UNSPECIFIED")
		r.KeyValue("scope", "RUNTIME, DEV, TEST, BUILD, OPTIONAL, UNSPECIFIED")
		return "", nil

	case ":example":
		for k := range request {
			delete(request, k)
		}
		// Real-world example: lodash command injection vulnerability (CVE-2021-23337)
		// https://osv.dev/vulnerability/GHSA-35jh-r3h4-6jhm
		// CVSS 7.2 HIGH - Command Injection via template function
		request["id"] = "GHSA-35jh-r3h4-6jhm"
		request["cve"] = "CVE-2021-23337"
		request["severity"] = "HIGH"
		request["severityScore"] = "7.2"
		request["ecosystem"] = "npm"
		request["package"] = "lodash"
		request["version"] = "4.17.20"
		request["fixed_version"] = "4.17.21"
		request["license"] = "MIT"
		request["isDirect"] = "true"
		*entrypoint = "scan_vulnerability"
		return "loaded example: lodash@4.17.20 (CVE-2021-23337 command injection, CVSS 7.2)", nil

	case ":vuln":
		for k := range request {
			delete(request, k)
		}
		request["id"] = "CVE-2021-44228"
		request["severity"] = "CRITICAL"
		request["ecosystem"] = "maven"
		request["package"] = "org.apache.logging.log4j:log4j-core"
		request["version"] = "2.14.1"
		*entrypoint = "scan_vulnerability"
		return "loaded vulnerability: CVE-2021-44228 (Log4Shell)", nil

	case ":graph":
		for k := range request {
			delete(request, k)
		}
		request["node_count"] = "150"
		request["direct_count"] = "12"
		request["max_depth"] = "6"
		*entrypoint = "graph_report"
		return "loaded graph context with 150 nodes", nil

	case ":entrypoint":
		if len(parts) < 2 {
			r.Section("Available Entrypoints")
			entrypoints := []string{
				"proxy", "scan_report", "scan_vulnerability",
				"graph_report", "graph_node", "graph_edge",
				"dockerfile_report", "dockerfile_stage",
				"oci_artifact_request", "go_artifact_request",
				"npm_artifact_request", "pypi_artifact_request",
			}
			for _, ep := range entrypoints {
				r.Info("  " + ep)
			}
			return "", nil
		}
		*entrypoint = parts[1]
		return fmt.Sprintf("entrypoint set to %s", *entrypoint), nil

	case ":functions", ":funcs", ":fn":
		r.Section("Helper Functions")
		catalog := policy.HelperCatalog()
		for _, fn := range catalog {
			r.CommandHelp(fn.Name, fn.Doc)
		}
		return "", nil

	case ":vars", ":variables":
		r.Section("Available Variables")
		vars := policy.DefaultVariableNames()
		sort.Strings(vars)
		for _, v := range vars {
			r.Info("  " + v)
		}
		return "", nil

	case ":severity":
		r.Section("Severity Constants")
		r.Table([]ui.TableRow{
			{Label: "severity.CRITICAL", Value: "\"CRITICAL\""},
			{Label: "severity.HIGH", Value: "\"HIGH\""},
			{Label: "severity.MEDIUM", Value: "\"MEDIUM\""},
			{Label: "severity.LOW", Value: "\"LOW\""},
			{Label: "severity.UNSPECIFIED", Value: "\"UNSPECIFIED\""},
		})
		r.Blank()
		r.Section("Severity Functions")
		r.CommandHelp("severityAtLeast(vuln, level)", "Check if severity >= level")
		r.CommandHelp("isCritical(vuln)", "Shorthand for CRITICAL check")
		r.CommandHelp("isHighOrAbove(vuln)", "Shorthand for HIGH or CRITICAL")
		return "", nil

	case ":exit", ":quit", ":q":
		return "", errReplExit

	default:
		// Try to suggest a similar command
		if suggestion := suggestCommand(parts[0]); suggestion != "" {
			return "", fmt.Errorf("unknown command %s (did you mean %s?)", parts[0], suggestion)
		}
		return "", fmt.Errorf("unknown command %s (try :help)", parts[0])
	}
}

// replCommands is the list of valid REPL commands for suggestions.
var replCommands = []string{
	":help", ":h",
	":set", ":unset", ":clear", ":show",
	":example", ":vuln", ":graph",
	":entrypoint",
	":functions", ":funcs", ":fn",
	":vars", ":variables",
	":severity",
	":exit", ":quit", ":q",
}

// suggestCommand returns a similar command if one exists within edit distance 2.
func suggestCommand(input string) string {
	if !strings.HasPrefix(input, ":") {
		return ""
	}

	bestMatch := ""
	bestDist := 3 // Only suggest if distance <= 2

	for _, cmd := range replCommands {
		dist := levenshtein(input, cmd)
		if dist < bestDist {
			bestDist = dist
			bestMatch = cmd
		}
	}

	return bestMatch
}

// levenshtein calculates the edit distance between two strings.
func levenshtein(a, b string) int {
	if len(a) == 0 {
		return len(b)
	}
	if len(b) == 0 {
		return len(a)
	}

	// Create matrix
	matrix := make([][]int, len(a)+1)
	for i := range matrix {
		matrix[i] = make([]int, len(b)+1)
		matrix[i][0] = i
	}
	for j := range matrix[0] {
		matrix[0][j] = j
	}

	// Fill matrix
	for i := 1; i <= len(a); i++ {
		for j := 1; j <= len(b); j++ {
			cost := 1
			if a[i-1] == b[j-1] {
				cost = 0
			}
			matrix[i][j] = min(
				matrix[i-1][j]+1,      // deletion
				matrix[i][j-1]+1,      // insertion
				matrix[i-1][j-1]+cost, // substitution
			)
		}
	}

	return matrix[len(a)][len(b)]
}

// completeREPLCommand returns completions for REPL meta-commands.
func completeREPLCommand(line string, cursor int) []string {
	// Get the partial command (everything up to cursor)
	partial := line[:cursor]

	// Only complete the first word (the command itself)
	if strings.Contains(partial, " ") {
		return nil // Don't complete arguments
	}

	var matches []string
	for _, cmd := range replCommands {
		if strings.HasPrefix(cmd, partial) {
			matches = append(matches, cmd)
		}
	}

	// Sort by length (prefer shorter commands)
	sort.Slice(matches, func(i, j int) bool {
		return len(matches[i]) < len(matches[j])
	})

	return matches
}

// buildREPLPayload constructs the evaluation payload with all default variables.
// It uses proto types where applicable for type-safe CEL evaluation.
func buildREPLPayload(request map[string]string, entrypoint string) map[string]any {
	// Build env using proto type
	env := &policyv1.Environment{
		Command:    "repl",
		Entrypoint: entrypoint,
	}

	payload := map[string]any{
		"request": toAnyMap(request),
		"env":     env,
	}

	// Add vulnerability context for vulnerability entrypoints using proto types
	if strings.Contains(entrypoint, "vuln") {
		// Build advisory using proto
		advisory := &vulnerabilityv1.Advisory{
			Id:            request["id"],
			Cve:           request["cve"],
			FixedVersions: []string{},
		}
		if fv := request["fixed_version"]; fv != "" {
			advisory.FixedVersions = []string{fv}
		}

		// Map severity string to proto enum
		severityLevel := vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_UNSPECIFIED
		switch strings.ToUpper(request["severity"]) {
		case "CRITICAL":
			severityLevel = vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_CRITICAL
		case "HIGH":
			severityLevel = vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_HIGH
		case "MEDIUM":
			severityLevel = vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_MEDIUM
		case "LOW":
			severityLevel = vulnerabilityv1.SeverityLevel_SEVERITY_LEVEL_LOW
		}
		advisory.Severity = &vulnerabilityv1.Severity{
			Level: severityLevel,
			Raw:   request["severity"],
		}

		// Build package using proto
		pkg := &dependencyv1.Package{
			Name:      request["package"],
			Version:   request["version"],
			Ecosystem: request["ecosystem"],
			Direct:    request["isDirect"] == "true",
		}
		if license := request["license"]; license != "" {
			pkg.Licenses = []string{license}
		}

		// Build finding using proto
		finding := &vulnerabilityv1.Finding{
			AdvisoryId: request["id"],
			Package:    pkg,
			Advisory:   advisory,
			Affected:   true,
		}

		// Also provide map-based versions for backward compatibility with existing policies
		// that use string-based severity checks like vulnerability.severity == "HIGH"
		vulnMap := map[string]any{
			"id":            request["id"],
			"severity":      request["severity"],
			"fixedVersions": advisory.FixedVersions,
			"isDirect":      pkg.Direct,
		}
		if cve := request["cve"]; cve != "" {
			vulnMap["cve"] = cve
		}

		payload["vulnerability"] = vulnMap
		payload["vulnerabilities"] = []any{vulnMap}
		// Also provide proto-based finding for policies
		payload["finding"] = finding
		payload["pkg"] = pkg
	}

	// Add pkg context for package-related entrypoints using proto
	if request["package"] != "" || request["ecosystem"] != "" {
		pkg := &dependencyv1.Package{
			Name:      request["package"],
			Version:   request["version"],
			Ecosystem: request["ecosystem"],
			Direct:    request["isDirect"] == "true",
		}
		if license := request["license"]; license != "" {
			pkg.Licenses = []string{license}
		}
		payload["pkg"] = pkg
	}

	// Add graph context for graph entrypoints
	if strings.Contains(entrypoint, "graph") {
		payload["stats"] = &vulnerabilityv1.Stats{
			Total:       int32(parseIntOrZero(request["node_count"])),
			DirectDeps:  int32(parseIntOrZero(request["direct_count"])),
			IndirectDeps: int32(parseIntOrZero(request["node_count"]) - parseIntOrZero(request["direct_count"])),
		}
		payload["nodes"] = []*dependencyv1.Package{}
		payload["edges"] = []any{}
		payload["roots"] = []string{}
	}

	// Add jwt using proto type
	payload["jwt"] = &policyv1.JWTClaims{
		Anonymous: true,
	}

	return payload
}

// toAnyMap converts map[string]string to map[string]any.
func toAnyMap(m map[string]string) map[string]any {
	result := make(map[string]any, len(m))
	for k, v := range m {
		result[k] = v
	}
	return result
}

// parseIntOrZero parses an int or returns 0.
func parseIntOrZero(s string) int {
	var n int
	fmt.Sscanf(s, "%d", &n)
	return n
}

// suggestFix returns a hint for common CEL errors.
func suggestFix(expr, errMsg string) string {
	// Check for common mistakes
	switch {
	case strings.Contains(errMsg, "undeclared reference"):
		if strings.Contains(expr, "severity.") && !strings.Contains(errMsg, "severity") {
			return "severity constants are available: severity.CRITICAL, severity.HIGH, etc."
		}
		if strings.Contains(expr, ".") {
			parts := strings.Split(expr, ".")
			if len(parts) > 0 {
				return fmt.Sprintf("'%s' may not be defined. Try :show to see available context.", parts[0])
			}
		}
	case strings.Contains(errMsg, "found no matching overload"):
		return "function signature mismatch. Try :functions to see available helpers."
	case strings.Contains(errMsg, "Syntax error"):
		if strings.Count(expr, "(") != strings.Count(expr, ")") {
			return "check for unbalanced parentheses"
		}
		if strings.Count(expr, "\"")%2 != 0 {
			return "check for unclosed string quotes"
		}
	}
	return ""
}
