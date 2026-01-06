# `deputy completion`

Generate shell autocompletion scripts for Deputy commands.

## Synopsis

```
deputy completion <shell>
deputy completion bash
deputy completion zsh
deputy completion fish
deputy completion powershell
```

## Description

Generates shell completion scripts that enable tab completion for Deputy commands, flags, and arguments. This makes the CLI faster to use and helps discover available options.

## Supported Shells

| Shell | Command |
|-------|---------|
| Bash | `deputy completion bash` |
| Zsh | `deputy completion zsh` |
| Fish | `deputy completion fish` |
| PowerShell | `deputy completion powershell` |

## Installation

### Bash

Requires the `bash-completion` package.

```bash
# Linux
deputy completion bash > /etc/bash_completion.d/deputy

# macOS (with Homebrew)
deputy completion bash > $(brew --prefix)/etc/bash_completion.d/deputy

# Current session only
source <(deputy completion bash)
```

### Zsh

```bash
# Ensure completion is enabled
echo "autoload -U compinit; compinit" >> ~/.zshrc

# Linux
deputy completion zsh > "${fpath[1]}/_deputy"

# macOS (with Homebrew)
deputy completion zsh > $(brew --prefix)/share/zsh/site-functions/_deputy

# Current session only
source <(deputy completion zsh)
```

### Fish

```bash
deputy completion fish > ~/.config/fish/completions/deputy.fish
```

### PowerShell

```powershell
# Current session
deputy completion powershell | Out-String | Invoke-Expression

# Permanent (add to profile)
deputy completion powershell >> $PROFILE
```

## Flags

| Flag | Description |
|------|-------------|
| `--no-descriptions` | Disable completion descriptions (shorter output) |

## What Gets Completed

- Command names (`scan`, `fix`, `diff`, etc.)
- Subcommands (`policy lint`, `proxy go`, etc.)
- Flag names (`--format`, `--policy`, etc.)
- Flag values (where applicable)

## Troubleshooting

### Completions not working after install

Start a new shell session, or source your shell's config file:

```bash
# Bash
source ~/.bashrc

# Zsh
source ~/.zshrc
```

### "command not found: compinit" (Zsh)

Enable the completion system:

```bash
autoload -U compinit && compinit
```

### Outdated completions after Deputy upgrade

Regenerate the completion script after upgrading Deputy to get completions for new commands and flags.

## See Also

- [Getting Started](../getting-started.md)
- [Command Reference](README.md)
