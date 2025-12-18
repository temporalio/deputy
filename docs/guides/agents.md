# Agents & automation

Deputy can delegate some workflows to external agents to reduce manual toil.

## Where agents fit

```mermaid
sequenceDiagram
  participant Dev as Developer
  participant Deputy as deputy
  participant Agent

  rect rgb(232, 245, 233)
    Note over Dev,Deputy: Manual workflow
    Dev->>Deputy: deputy fix --format json
    activate Deputy
    Deputy-->>Dev: remediation plan (JSON)
    deactivate Deputy
  end

  rect rgb(227, 242, 253)
    Note over Dev,Agent: Agent-assisted workflow
    Dev->>Deputy: deputy fix --agent codex
    activate Deputy
    Deputy->>Agent: plan + context
    activate Agent
    Agent-->>Deputy: proposed edits / guidance
    deactivate Agent
    Deputy-->>Dev: results + next steps
    deactivate Deputy
  end
```

## Safety checklist

- Prefer `--agent-sandbox read-only` when you only need analysis.
- Use `workspace-write` when the agent needs to edit files and run tests.
- Avoid `--agent-full-auto` unless you’re comfortable with unattended changes.
- Generate plans with `--format json` first so humans can review.

## Code pointers

- Agent integrations: [`internal/cli/cmd/fix.go`](../../internal/cli/cmd/fix.go), [`internal/cli/cmd/triage.go`](../../internal/cli/cmd/triage.go)
