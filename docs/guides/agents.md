# Agents & Automation

Deputy can delegate workflows to external AI agents to reduce manual toil.

## Overview

```mermaid
sequenceDiagram
  participant Dev as Developer
  participant Deputy as deputy
  participant Agent as AI Agent

  rect rgb(232, 245, 233)
    Note over Dev,Deputy: Manual workflow
    Dev->>Deputy: deputy fix --format json
    activate Deputy
    Deputy-->>Dev: remediation plan (JSON)
    deactivate Deputy
  end

  rect rgb(227, 242, 253)
    Note over Dev,Agent: Agent-assisted workflow
    Dev->>Deputy: deputy fix --agent claude
    activate Deputy
    Deputy->>Agent: plan + context
    activate Agent
    Agent-->>Deputy: proposed edits / guidance
    deactivate Agent
    Deputy-->>Dev: results + next steps
    deactivate Deputy
  end
```

## Agent-Enabled Commands

| Command | Agent Use | Description |
| --- | --- | --- |
| `deputy fix` | Implement upgrades | Agent applies dependency changes |
| `deputy triage` | Prioritize vulns | Agent analyzes and recommends actions |

---

## Agent Modes

### Sandbox Levels

| Mode | Flag | What Agent Can Do |
| --- | --- | --- |
| Read-only | `--agent-sandbox read-only` | Analyze files, suggest changes |
| Workspace write | `--agent-sandbox workspace-write` | Edit files, run tests |
| Full auto | `--agent-full-auto` | Unattended changes, commits |

### Choosing a Mode

```console
# Safe: agent can only analyze
$ deputy triage --agent claude --agent-sandbox read-only

# Productive: agent can edit files
$ deputy fix --agent claude --agent-sandbox workspace-write

# Autonomous: agent works independently (use with caution)
$ deputy fix --agent claude --agent-full-auto
```

---

## Practical Examples

### AI-Assisted Triage

```console
# Get AI prioritization of vulnerabilities
$ deputy triage --agent claude

# Interactive session
Deputy: Found 15 vulnerabilities. Starting triage...

Agent Analysis:
  Priority 1 (Immediate):
    CVE-2024-1234 in github.com/example/pkg
    - Severity: CRITICAL
    - Exploited in wild: Yes
    - Fix available: v1.2.3
    
  Priority 2 (This sprint):
    CVE-2024-5678 in lodash
    - Severity: HIGH
    - Direct dependency
    - Fix: npm update lodash@4.17.21
    
  Priority 3 (Backlog):
    CVE-2024-9999 in indirect-dep
    - Severity: MEDIUM
    - Transitive, no direct exposure

Recommended action: Start with CVE-2024-1234
Proceed? [y/n]
```

### AI-Assisted Fix

```console
# Let agent implement the fix
$ deputy fix --agent claude --agent-sandbox workspace-write

Agent: Analyzing remediation plan...

Step 1/3: Upgrading github.com/example/pkg v1.0.0 → v1.2.3
  - Modified go.mod
  - Running go mod tidy
  - Running tests... ✓ All pass

Step 2/3: Upgrading lodash 4.17.20 → 4.17.21
  - Modified package.json
  - Running npm install
  - Running tests... ✓ All pass

Step 3/3: Verifying no new vulnerabilities introduced
  - Running deputy scan... ✓ Clean

Summary:
  ✓ 2 packages upgraded
  ✓ All tests passing
  ✓ No new vulnerabilities

Review changes with: git diff
```

---

## Safety Guidelines

### Before Using Agents

1. **Review the plan first**
   ```console
   # Generate plan without agent
   $ deputy fix --format json > plan.json
   
   # Review it
   $ cat plan.json | jq '.steps'
   
   # Then run with agent
   $ deputy fix --agent claude
   ```

2. **Start with read-only**
   ```console
   $ deputy triage --agent claude --agent-sandbox read-only
   ```

3. **Use workspace-write for edits**
   ```console
   $ deputy fix --agent claude --agent-sandbox workspace-write
   ```

### Safety Checklist

| ✓ | Check |
| --- | --- |
| ☐ | Working in a feature branch |
| ☐ | Tests exist and pass before running |
| ☐ | CI will validate changes |
| ☐ | Using appropriate sandbox level |
| ☐ | Reviewed the remediation plan |

### What to Avoid

```console
# ❌ Don't run full-auto on main branch
$ git checkout main
$ deputy fix --agent-full-auto  # Risky!

# ✓ Do use a feature branch
$ git checkout -b security-updates
$ deputy fix --agent claude --agent-sandbox workspace-write
```

---

## Agent Configuration

### Config File (`.deputy.yaml`)

```yaml
ai:
  # Default provider when --agent flag is omitted
  default_provider: claude

  # Approval settings
  approval:
    required: false     # Require approval for all operations
    commands: true      # Require approval for shell commands (default)
    file_writes: false  # Require approval for file modifications
    high_risk: true     # Always approve dangerous operations (rm -rf, sudo, etc.)

  # Per-provider configuration
  providers:
    claude:
      model: claude-3-5-sonnet-20241022
      api_key: ${ANTHROPIC_API_KEY}
      sandbox: workspace-write
    codex:
      sandbox: workspace-write
```

### Environment Variables

```bash
# Claude
export ANTHROPIC_API_KEY=sk-...

# OpenAI / Codex
export OPENAI_API_KEY=sk-...

# Custom endpoint
export DEPUTY_AGENT_ENDPOINT=https://my-llm.internal/v1
```

### Supported Agents

| Agent | Flag | Notes |
| --- | --- | --- |
| Claude | `--agent claude` | Anthropic API |
| Codex | `--agent codex` | OpenAI Codex |
| Custom | `--agent-endpoint URL` | Any compatible API |

### Approval Policy

Deputy enforces safety by default. Operations require approval unless explicitly disabled:

| Setting | Default | Description |
| --- | --- | --- |
| `commands` | `true` | Shell commands need approval |
| `file_writes` | `false` | File modifications proceed |
| `high_risk` | `true` | Dangerous ops always need approval |

High-risk operations detected automatically:
- `rm -rf /`, `sudo`, `chmod 777`
- Writes to `/etc/`, `~/.ssh/`, `.env`
- `git push --force`, `git reset --hard`

```console
# Override approval with --agent-full-auto (dangerous!)
$ deputy fix --agent claude --agent-full-auto

WARNING: Full-auto mode enabled: commands and file writes will execute without approval
```

---

## Output Formats

### JSON for Custom Agents

```console
# Get structured output for your own automation
$ deputy triage --format json | my-custom-agent

# Or pipe to fix
$ deputy fix --format json | custom-remediation-bot
```

### Agent Response Schema

```json
{
  "analysis": {
    "priority": "high",
    "reasoning": "...",
    "recommended_action": "upgrade"
  },
  "steps": [
    {
      "package": "example/pkg",
      "action": "upgrade",
      "from": "v1.0.0",
      "to": "v1.2.3"
    }
  ]
}
```

---

## Troubleshooting

### Agent Not Responding

```console
# Check API key
$ echo $ANTHROPIC_API_KEY | head -c 10

# Test with verbose
$ deputy triage --agent claude --verbose
```

### Agent Making Wrong Changes

```console
# Reset and try read-only first
$ git checkout -- .
$ deputy fix --agent claude --agent-sandbox read-only

# Review suggestions before applying
```

### Rate Limits

```console
# Add delays between operations
$ deputy fix --agent claude --agent-rate-limit 1s
```

---

## See Also

- [Fix command reference](../commands/fix.md)
- [Triage command reference](../commands/triage.md)
- Code: [`internal/cli/cmd/fix.go`](../../internal/cli/cmd/fix.go)
