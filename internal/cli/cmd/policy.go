package cmd

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/google/go-cmp/cmp"
	"github.com/picatz/deputy/internal/policy"
	"github.com/spf13/cobra"
)

// AddPolicyCommand registers the `deputy policy` command tree.
func AddPolicyCommand(root *cobra.Command) {
	cmd := &cobra.Command{
		Use:   "policy",
		Short: "Work with Deputy CEL policies",
		Long:  "Evaluate and validate Deputy CEL policies against JSON inputs.",
	}
	cmd.AddCommand(newPolicyEvalCommand())
	cmd.AddCommand(newPolicyLintCommand())
	cmd.AddCommand(newPolicyTestCommand())
	cmd.AddCommand(newPolicyBundleCommand())
	cmd.AddCommand(newPolicyInspectCommand())
	cmd.AddCommand(newPolicySimulateCommand())
	root.AddCommand(cmd)
}

func newPolicyEvalCommand() *cobra.Command {
	var policyPath string
	var inputPath string
	var format string
	cmd := &cobra.Command{
		Use:   "eval --policy policy.cel --input input.json",
		Short: "Evaluate a CEL policy against JSON input",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(policyPath) == "" {
				return errors.New("missing --policy path")
			}
			if strings.TrimSpace(inputPath) == "" {
				return errors.New("missing --input path")
			}
			policyBytes, err := readPathOrStdin(cmd.InOrStdin(), policyPath)
			if err != nil {
				return fmt.Errorf("read policy %q: %w", policyPath, err)
			}
			inputBytes, err := readPathOrStdin(cmd.InOrStdin(), inputPath)
			if err != nil {
				return fmt.Errorf("read input %q: %w", inputPath, err)
			}
			var payload map[string]any
			if err := json.Unmarshal(inputBytes, &payload); err != nil {
				return fmt.Errorf("parse input JSON: %w", err)
			}
			result, err := policy.Evaluate(cmd.Context(), string(policyBytes), payload)
			if err != nil {
				return fmt.Errorf("evaluate policy: %w", err)
			}
			return writePolicyEvalOutput(cmd.OutOrStdout(), result, format)
		},
	}
	cmd.Flags().StringVar(&policyPath, "policy", "", "Path to CEL policy source (use '-' for stdin)")
	cmd.Flags().StringVar(&inputPath, "input", "", "Path to JSON input (use '-' for stdin)")
	cmd.Flags().StringVar(&format, "format", "json", "Output format: json or text")
	return cmd
}

func newPolicyLintCommand() *cobra.Command {
	var extraVars []string
	cmd := &cobra.Command{
		Use:   "lint <policy.cel> [policy2.cel ...]",
		Short: "Lint CEL policies for syntax/type issues",
		Args:  cobra.MinimumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			stdinUsed := false
			for _, path := range args {
				data, err := readPathOrStdinOnce(cmd.InOrStdin(), path, &stdinUsed)
				if err != nil {
					return fmt.Errorf("read %q: %w", path, err)
				}
				if err := policy.Compile(string(data), extraVars); err != nil {
					return fmt.Errorf("%s: %w", path, err)
				}
				fmt.Fprintf(cmd.OutOrStdout(), "%s OK\n", labelPath(path))
			}
			return nil
		},
	}
	cmd.Flags().StringArrayVar(&extraVars, "var", nil, "Additional variable names to declare while linting (repeatable)")
	return cmd
}

func readPathOrStdin(stdin io.Reader, path string) ([]byte, error) {
	if path == "-" {
		return io.ReadAll(stdin)
	}
	return os.ReadFile(path)
}

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

func writePolicyEvalOutput(w io.Writer, value any, format string) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "json":
		data, err := json.MarshalIndent(value, "", "  ")
		if err != nil {
			return fmt.Errorf("marshal evaluation result: %w", err)
		}
		_, err = w.Write(append(data, '\n'))
		return err
	case "text":
		_, err := fmt.Fprintf(w, "%v\n", value)
		return err
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}

func labelPath(path string) string {
	if path == "-" {
		return "stdin"
	}
	return path
}

func newPolicyTestCommand() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "test <case.policytest.json|dir> [more...]",
		Short: "Execute policy tests defined in JSON fixtures",
		Args:  cobra.MinimumNArgs(1),
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

func newPolicyBundleCommand() *cobra.Command {
	var outPath string
	cmd := &cobra.Command{
		Use:   "bundle --out bundle.json <policy.cel> [policy2.cel ...]",
		Short: "Compile CEL policies into a reusable bundle",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(outPath) == "" {
				return errors.New("missing --out path for bundle")
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
	cmd.Flags().StringVar(&outPath, "out", "", "Destination bundle file (use '-' for stdout)")
	return cmd
}

func newPolicyInspectCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "inspect <policy-or-bundle> [more...]",
		Short: "Inspect CEL policies or bundles",
		Args:  cobra.MinimumNArgs(1),
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

func newPolicySimulateCommand() *cobra.Command {
	var policies []string
	var inputs []string
	var format string
	cmd := &cobra.Command{
		Use:   "simulate --policy policy.cel --input input.json",
		Short: "Run policies against recorded JSON inputs",
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
				actions, err := policy.EvaluateAll(cmd.Context(), sources, payload)
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

type policyTestCase struct {
	Name      string           `json:"name"`
	Policy    string           `json:"policy,omitempty"`
	Policies  []string         `json:"policies,omitempty"`
	Input     string           `json:"input"`
	InputJSON map[string]any   `json:"input_json,omitempty"`
	Want      []map[string]any `json:"want"`
	Metadata  map[string]any   `json:"metadata,omitempty"`
}

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
	sort.Strings(files)
	return files, nil
}

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

func executePolicyTestCase(ctx context.Context, baseDir, file string, tc *policyTestCase, cmd *cobra.Command) error {
	name := tc.Name
	if name == "" {
		name = file
	}
	var policyPaths []string
	if len(tc.Policies) > 0 {
		policyPaths = append(policyPaths, tc.Policies...)
	} else if tc.Policy != "" {
		policyPaths = append(policyPaths, tc.Policy)
	} else {
		return fmt.Errorf("%s: test %q missing policy path", file, name)
	}
	for i, p := range policyPaths {
		if !filepath.IsAbs(p) {
			policyPaths[i] = filepath.Join(baseDir, p)
		}
	}
	inputMap := map[string]any{}
	if tc.InputJSON != nil {
		inputMap = tc.InputJSON
	} else if strings.TrimSpace(tc.Input) != "" {
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
	actions, err := policy.EvaluateAll(ctx, sources, inputMap)
	if err != nil {
		return fmt.Errorf("%s (%s): %w", name, file, err)
	}
	actual := actionsToComparable(actions)
	if diff := cmp.Diff(tc.Want, actual); diff != "" {
		return fmt.Errorf("%s (%s): unexpected actions (-want +got):\n%s", name, file, diff)
	}
	fmt.Fprintf(cmd.OutOrStdout(), "✓ %s\n", name)
	return nil
}

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

func inspectPolicyPath(w io.Writer, path string) error {
	data, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if bundle, ok := policy.ParseBundle(data); ok {
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
	meta := policy.ExtractMetadata(string(data))
	fmt.Fprintf(w, "Policy: %s\n", path)
	if name := meta["policy.name"]; name != "" {
		fmt.Fprintf(w, "  Name: %s\n", name)
	}
	if desc := meta["policy.description"]; desc != "" {
		fmt.Fprintf(w, "  Description: %s\n", desc)
	}
	if entry := meta["policy.entrypoints"]; entry != "" {
		fmt.Fprintf(w, "  Entrypoints: %s\n", entry)
	}
	if actions := meta["policy.actions"]; actions != "" {
		fmt.Fprintf(w, "  Declared actions: %s\n", actions)
	}
	return nil
}

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

func writeSimulationResult(w io.Writer, format string, index int, payload map[string]any, actions []policy.Action) error {
	switch strings.ToLower(strings.TrimSpace(format)) {
	case "", "text":
		fmt.Fprintf(w, "Input %d:\n", index)
		for _, act := range actions {
			fmt.Fprintf(w, "  %s from %s", strings.ToUpper(act.Type), act.Source)
			if act.Reason != "" {
				fmt.Fprintf(w, " — %s", act.Reason)
			}
			fmt.Fprintln(w)
		}
		return nil
	case "json":
		out := map[string]any{
			"inputIndex": index,
			"actions":    actionsToComparable(actions),
		}
		enc := json.NewEncoder(w)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
	default:
		return fmt.Errorf("unsupported format %q", format)
	}
}
