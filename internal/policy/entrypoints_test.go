package policy

import "testing"

func TestAllowedEntrypoints(t *testing.T) {
	for _, ep := range AllEntrypoints {
		if !IsAllowedEntrypoint(ep) {
			t.Fatalf("expected %s to be allowed", ep)
		}
	}
	if IsAllowedEntrypoint("bogus_entrypoint") {
		t.Fatalf("expected bogus_entrypoint to be rejected")
	}
}

func TestAllowedCommands(t *testing.T) {
	for _, cmd := range []string{"proxy", "scan", "diff", "sbom", "fix", "triage"} {
		if !IsAllowedCommand(cmd) {
			t.Fatalf("expected %s to be allowed", cmd)
		}
	}
	if IsAllowedCommand("unknown_cmd") {
		t.Fatalf("expected unknown_cmd to be rejected")
	}
}

func TestStructuredEntrypointValidation(t *testing.T) {
	yaml := `policies:
  - name: bad-entrypoint
    entrypoints: ["not_real"]
    rules:
      - action: deny
        when: true
`
	if _, ok, err := tryParseStructuredBundle([]byte(yaml), "inline"); err == nil || ok {
		t.Fatalf("expected error for invalid entrypoint")
	}

	yamlCmd := `policies:
  - name: bad-command
    commands: ["not_real"]
    rules:
      - action: deny
        when: true
`
	if _, ok, err := tryParseStructuredBundle([]byte(yamlCmd), "inline"); err == nil || ok {
		t.Fatalf("expected error for invalid command")
	}
}
