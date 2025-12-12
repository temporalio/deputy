package cmd

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"io"
	"strings"

	"github.com/picatz/deputy/internal/policy"
	"github.com/spf13/cobra"
)

// newPolicyREPLCommand creates the `repl` subcommand for interactive policy evaluation.
func newPolicyREPLCommand() *cobra.Command {
	return &cobra.Command{
		Use:           "repl",
		Short:         "Interactive CEL policy playground",
		SilenceErrors: true,
		SilenceUsage:  true,
		Long:          "Start an interactive REPL for experimenting with CEL expressions using a mock proxy request map (request.*).",
		RunE: func(cmd *cobra.Command, args []string) error {
			in := cmd.InOrStdin()
			out := cmd.OutOrStdout()
			return runPolicyREPL(cmd.Context(), in, out)
		},
	}
}

// runPolicyREPL starts the Read-Eval-Print Loop for CEL policies.
func runPolicyREPL(ctx context.Context, in io.Reader, out io.Writer) error {
	fmt.Fprintln(out, "CEL Policy Expression REPL")
	fmt.Fprintln(out, "Type :help for commands or enter CEL expressions to evaluate against the 'request' map.")
	fmt.Fprintln(out, "Example: request.package == \"github.com/acme/payment\"")

	scanner := bufio.NewScanner(in)
	request := map[string]string{}

	for {
		fmt.Fprint(out, "> ")
		if !scanner.Scan() {
			if err := scanner.Err(); err != nil {
				return err
			}
			fmt.Fprintln(out, "Goodbye!")
			return nil
		}
		line := strings.TrimSpace(scanner.Text())
		if line == "" {
			continue
		}
		if strings.HasPrefix(line, ":") {
			if err := handleREPLCommand(line, request, out); err != nil {
				if errors.Is(err, errReplExit) {
					fmt.Fprintln(out, "Goodbye!")
					return nil
				}
				fmt.Fprintf(out, "Error: %v\n", err)
			}
			continue
		}

		payload := map[string]any{"request": map[string]string{}}
		for k, v := range request {
			payload["request"].(map[string]string)[k] = v
		}
		result, err := policy.Evaluate(ctx, line, payload)
		if err != nil {
			fmt.Fprintf(out, "Evaluation error: %v\n", err)
			continue
		}
		fmt.Fprintf(out, "Result: %v\n", result)
	}
}

var errReplExit = errors.New("repl exit")

// handleREPLCommand processes REPL meta-commands (starting with :).
func handleREPLCommand(line string, request map[string]string, out io.Writer) error {
	parts := strings.Fields(line)
	if len(parts) == 0 {
		return nil
	}
	switch parts[0] {
	case ":help":
		fmt.Fprintln(out, ":set key=value  - set request field")
		fmt.Fprintln(out, ":unset key      - remove request field")
		fmt.Fprintln(out, ":clear          - remove all request fields")
		fmt.Fprintln(out, ":show           - display request object")
		fmt.Fprintln(out, ":example        - load example package metadata")
		fmt.Fprintln(out, ":exit / :quit   - exit the REPL")
	case ":set":
		if len(parts) < 2 {
			return fmt.Errorf(":set requires key=value")
		}
		kv := strings.Join(parts[1:], " ")
		idx := strings.Index(kv, "=")
		if idx <= 0 {
			return fmt.Errorf("invalid format, use key=value")
		}
		key := strings.TrimSpace(kv[:idx])
		value := strings.TrimSpace(kv[idx+1:])
		if key == "" {
			return fmt.Errorf("key cannot be empty")
		}
		request[key] = value
		fmt.Fprintf(out, "set request.%s = %s\n", key, value)
	case ":unset":
		if len(parts) < 2 {
			return fmt.Errorf(":unset requires key")
		}
		key := parts[1]
		delete(request, key)
		fmt.Fprintf(out, "unset request.%s\n", key)
	case ":clear":
		for k := range request {
			delete(request, k)
		}
		fmt.Fprintln(out, "request cleared")
	case ":show":
		if len(request) == 0 {
			fmt.Fprintln(out, "(request is empty)")
			return nil
		}
		for k, v := range request {
			fmt.Fprintf(out, "  request.%s = %s\n", k, v)
		}
	case ":example":
		for k := range request {
			delete(request, k)
		}
		request["ecosystem"] = "npm"
		request["package"] = "@acme/payment"
		request["version"] = "1.2.3"
		request["license"] = "Apache-2.0"
		request["severity"] = "CRITICAL"
		fmt.Fprintln(out, "loaded example request data (npm @acme/payment@1.2.3)")
	case ":exit", ":quit":
		return errReplExit
	default:
		return fmt.Errorf("unknown command %s", parts[0])
	}
	return nil
}
