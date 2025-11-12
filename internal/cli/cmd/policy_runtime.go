package cmd

import (
	"context"
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/picatz/deputy/internal/policy"
)

func evaluatePoliciesForCommand(ctx context.Context, policyPaths []string, payload map[string]any, command, entrypoint string, errW io.Writer) error {
	if len(policyPaths) == 0 {
		return nil
	}
	if errW == nil {
		errW = os.Stderr
	}
	if payload == nil {
		payload = map[string]any{}
	}
	env := map[string]any{
		"command": command,
	}
	if entrypoint != "" {
		env["entrypoint"] = entrypoint
	}
	if existing, ok := payload["env"].(map[string]any); ok {
		for k, v := range existing {
			env[k] = v
		}
	}
	payload["env"] = env

	sources, err := policy.LoadSources(policyPaths)
	if err != nil {
		return err
	}
	actions, err := policy.EvaluateAll(ctx, sources, payload)
	if err != nil {
		return err
	}
	for _, act := range actions {
		switch act.Type {
		case "deny":
			msg := firstNonEmpty(act.Reason, act.Message, "policy denied execution")
			return fmt.Errorf("policy %s denied command: %s", act.Source, msg)
		case "warn":
			msg := firstNonEmpty(act.Reason, act.Message, "policy warning")
			fmt.Fprintf(errW, "policy warning (%s): %s\n", act.Source, msg)
		case "allow", "":
			continue
		default:
			msg := firstNonEmpty(act.Reason, act.Message, "")
			if msg != "" {
				fmt.Fprintf(errW, "policy %s reported %s: %s\n", act.Source, act.Type, msg)
			}
		}
	}
	return nil
}

func firstNonEmpty(values ...string) string {
	for _, v := range values {
		if v = strings.TrimSpace(v); v != "" {
			return v
		}
	}
	return ""
}

func structToMap(v any) (map[string]any, error) {
	if v == nil {
		return map[string]any{}, nil
	}
	if m, ok := v.(map[string]any); ok {
		return m, nil
	}
	return policy.StructToMap(v)
}
