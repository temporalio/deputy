# Agents

Deputy integrates AI agents to enhance vulnerability analysis and remediation workflows.

## Overview

Deputy uses the `--agent` flag consistently across commands to delegate tasks to AI agents (Claude Code or Codex). The key difference between commands is the **default sandbox level**:

| Command | Default Sandbox | Purpose |
| --- | --- | --- |
| `deputy explain --agent` | `read-only` | Analysis only, no modifications |
| `deputy triage --agent` | `read-only` | Prioritization and recommendations |
| `deputy fix --agent` | `workspace-write` | Apply dependency upgrades |

## Agent-Enabled Commands

```console
# Explain: agent analyzes the vulnerability (read-only)
$ deputy explain --agent claude CVE-2021-44228

# Triage: agent prioritizes vulnerabilities (read-only)
$ deputy triage --agent claude

# Fix: agent implements remediation (workspace-write)
$ deputy fix --agent claude
```

---

## Sandbox Levels

Agents operate within a sandbox that controls what they can do:

| Sandbox | Description | Use Case |
| --- | --- | --- |
| `read-only` | Analyze files, no modifications | Explain, triage |
| `workspace-write` | Edit files in workspace, run tests | Fix, remediation |
| `full-access` | Unrestricted (dangerous) | Automated pipelines |

### Override Sandbox

```console
# Make explain able to write notes
$ deputy explain --agent claude --agent-sandbox workspace-write CVE-2021-44228

# Make fix read-only (dry run)
$ deputy fix --agent claude --agent-sandbox read-only
```

---

## Workflow Diagram

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

---

## Practical Examples

### Agent-Assisted Explain

```console
# Get agent analysis of a vulnerability
$ deputy explain --agent claude CVE-2021-44228

CVE-2021-44228 [CRITICAL] 10.0 v3.1
  ...standard output...

Agent Analysis

**What This Means**

Log4Shell is a critical remote code execution vulnerability...

**Impact**
- Severity: Maximum (10.0 CVSS)
- Exploitability: Trivial - single HTTP request can trigger
...
```

### Agent-Assisted Triage

```console
# Get agent prioritization of vulnerabilities
$ deputy triage --agent claude

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

Recommended action: Start with CVE-2024-1234
```

### Agent-Assisted Fix

```console
# Let agent implement the fix
$ deputy fix --agent claude

Agent: Analyzing remediation plan...

Step 1/3: Upgrading github.com/example/pkg v1.0.0 → v1.2.3
  - Modified go.mod
  - Running go mod tidy
  - Running tests... ✓ All pass

Step 2/3: Upgrading lodash 4.17.20 → 4.17.21
  - Modified package.json
  - Running npm install
  - Running tests... ✓ All pass

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
   $ deputy fix --agent claude --agent-sandbox read-only
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
  # Default provider when --agent is used without a value
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
```

### Supported Agents

| Agent | Flag | Installation |
| --- | --- | --- |
| Claude | `--agent claude` | `npm install -g @anthropic-ai/claude-code` |
| Codex | `--agent codex` | `npm install -g @openai/codex` |

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
# Check Claude CLI is installed
$ claude --version

# Check Codex CLI is installed
$ codex --version

# Enable debug logging
$ DEPUTY_LOG_LEVEL=debug deputy explain --agent claude CVE-2021-44228
```

### Agent Making Wrong Changes

```console
# Reset and try read-only first
$ git checkout -- .
$ deputy fix --agent claude --agent-sandbox read-only

# Review suggestions before applying
```

---

## See Also

- [Explain command reference](../commands/explain.md) — Agent-assisted vulnerability analysis
- [Fix command reference](../commands/fix.md) — Agent-assisted remediation
- [Triage command reference](../commands/triage.md) — Agent-assisted prioritization
- Code: [`internal/cli/cmd/explain.go`](../../internal/cli/cmd/explain.go)
- Code: [`internal/cli/cmd/fix.go`](../../internal/cli/cmd/fix.go)
- Code: [`internal/ai/render/render.go`](../../internal/ai/render/render.go)
