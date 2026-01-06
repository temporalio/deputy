package cmd

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"
	"strings"
	"time"

	deperrors "github.com/picatz/deputy/internal/errors"
	ui "github.com/picatz/deputy/internal/ui"
)

const anthropicAPIURL = "https://api.anthropic.com/v1/messages"

// runClaudeAgent executes the Claude AI agent to generate remediation suggestions.
// It constructs a request to the Anthropic API and prints the response.
func runClaudeAgent(ctx context.Context, prompt string, repoPath string, opts agentInvocationOptions, out, errW io.Writer) error {
	apiKey := strings.TrimSpace(os.Getenv("ANTHROPIC_API_KEY"))
	if apiKey == "" {
		return deperrors.Suggest(
			errors.New("ANTHROPIC_API_KEY is not set"),
			"Set the ANTHROPIC_API_KEY environment variable with your API key from https://console.anthropic.com/",
		)
	}
	model := strings.TrimSpace(opts.Model)
	if model == "" {
		model = "claude-3-5-sonnet-20241022"
	}
	reqBody := map[string]any{
		"model":      model,
		"max_tokens": 1024,
		"messages": []map[string]string{
			{"role": "user", "content": prompt},
		},
	}
	payload, err := json.Marshal(reqBody)
	if err != nil {
		return fmt.Errorf("encode claude request: %w", err)
	}
	request, err := http.NewRequestWithContext(ctx, http.MethodPost, anthropicAPIURL, bytes.NewReader(payload))
	if err != nil {
		return fmt.Errorf("build claude request: %w", err)
	}
	request.Header.Set("content-type", "application/json")
	request.Header.Set("x-api-key", apiKey)
	request.Header.Set("anthropic-version", "2023-06-01")

	client := &http.Client{Timeout: 2 * time.Minute}
	resp, err := client.Do(request)
	if err != nil {
		return fmt.Errorf("call claude: %w", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode >= 300 {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("claude request failed: %s", strings.TrimSpace(string(body)))
	}
	var raw struct {
		Content []struct {
			Text string `json:"text"`
		} `json:"content"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&raw); err != nil {
		return fmt.Errorf("decode claude response: %w", err)
	}
	if len(raw.Content) == 0 {
		return errors.New("claude returned no content")
	}
	fmt.Fprintf(out, "%s %s\n", ui.StyleManager.Render("claude"), strings.TrimSpace(raw.Content[0].Text))
	return nil
}
