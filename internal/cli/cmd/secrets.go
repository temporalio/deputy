package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"time"

	"connectrpc.com/connect"
	git "github.com/go-git/go-git/v5"

	"github.com/spf13/cobra"

	secretsv1 "github.com/temporalio/deputy/gen/deputy/secrets/v1"
	"github.com/temporalio/deputy/internal/container/image"
	deputyerrors "github.com/temporalio/deputy/internal/errors"
	gitx "github.com/temporalio/deputy/internal/gitutil"
	"github.com/temporalio/deputy/internal/globmatch"
	internalproto "github.com/temporalio/deputy/internal/proto"
	"github.com/temporalio/deputy/internal/secrets"
	"github.com/temporalio/deputy/internal/services"
	"github.com/temporalio/deputy/internal/targets"
	"github.com/temporalio/deputy/internal/targets/providers"
	ui "github.com/temporalio/deputy/internal/ui"
)

// SecretsResult is the structured output of a secrets scan.
type SecretsResult struct {
	// Target is the file or directory that was scanned.
	Target string `json:"target"`
	// Generated is the ISO 8601 timestamp when the scan was performed.
	Generated string `json:"generated"`
	// FilesScanned is the number of files analyzed.
	FilesScanned int `json:"filesScanned"`
	// SecretsFound is the total number of secrets detected.
	SecretsFound int `json:"secretsFound"`
	// HighConfidenceCount is the number of findings with >= 90% confidence.
	HighConfidenceCount int `json:"highConfidenceCount"`
	// Findings contains detected secrets.
	Findings []secrets.Finding `json:"findings"`
	// Stats provides aggregate counts by secret type.
	Stats map[secrets.SecretType]int `json:"stats"`
}

// AddSecretsCommand registers the secrets subcommand with the root command.
func AddSecretsCommand(root *cobra.Command, c *services.Clients) {
	var (
		formatFlag     string
		includeGlob    string
		excludeGlob    string
		noRedact       bool
		verifyFlag     bool
		alwaysExitZero bool
		historyFlag    bool
		maxCommits     int
		sinceFlag      string
		untilFlag      string
		branchFlag     string
		pathFilter     string
		includeRemoved bool
		diffMode       bool
		deepScan       bool
		baselinePath   string
	)

	secretsCmd := &cobra.Command{
		Use:     "secrets [target] [base-ref] [target-ref]",
		Aliases: []string{"secret"},
		Short:   "Scan for leaked secrets and credentials",
		Long: `Scan files for leaked secrets, credentials, API keys, and tokens.

Deputy's secret scanner combines Google's Veles detector (from OSV-SCALIBR) with
pattern-based detection to identify a wide range of credential types.

SUPPORTED SECRET TYPES:
• Cloud credentials: GCP API keys, GCP service account keys, AWS access keys
• Platform tokens: GitHub, GitLab, Slack, Discord, Telegram, npm, PyPI
• Payment keys: Stripe, SendGrid
• Infrastructure: Heroku, Mailgun, Twilio, RubyGems
• Generic: Private keys, JWTs, high-entropy strings, API key patterns

VERIFICATION (--verify):
When enabled, Deputy will attempt to verify if detected secrets are still active
by making API calls to the respective services (GitHub, Slack, Stripe, etc.).
This helps prioritize remediation by identifying which secrets are actually valid.

HISTORICAL ANALYSIS (--history):
Scan git history to find secrets that may have been committed and later removed.
Secrets in git history remain accessible even after deletion and should be rotated.
Supports the same Git reference types as 'deputy diff':
• Branch names: main, develop, feature-branch
• Tags: v1.0.0, release-2023
• Commit SHAs: 1a2b3c4, abc123def
• Remote refs: origin/main, upstream/develop
• Time-based refs: HEAD@{yesterday}, main@{1.week.ago}, HEAD@{2024-01-15}
• Relative refs: HEAD~3, main^

DIFF MODE (--diff):
Scan only the changes between two Git refs to find newly introduced secrets.
Ideal for CI/CD pipelines to catch secrets in pull requests before merge.
Similar to how 'deputy diff' compares dependencies between refs.

CONTAINER IMAGE SCANNING:
Scan container images for secrets in configuration and layer content:
• Environment variables (API keys, passwords in ENV instructions)
• Build history (secrets in RUN commands that remain in history)
• Labels and metadata
• Entrypoint/CMD arguments

Deep layer scanning (--deep) extracts and scans files within each layer:
• Scans config files (.env, .yaml, .json, etc.) in all layers
• Identifies which layer introduced each secret
• Distinguishes base image vs application layer secrets
• Uses OSV-SCALIBR for efficient filesystem access

Bare image references like 'nginx:1.25' or 'ghcr.io/owner/app:v1' are detected
automatically. Explicit transport schemes are also supported:
• docker://image:tag (remote registries, default)
• docker-daemon://image:tag (local Docker daemon)
• oci://image:tag (OCI registries)
• tarball:///path/to/image.tar (exported tarballs)

ARCHIVE FILE SCANNING:
Scan archive files (zip, tar, tar.gz, tar.bz2, tar.xz) for secrets:
• Automatically detects archive format by magic bytes or extension
• Scans nested archives up to 3 levels deep
• Extracts and scans text files matching sensitive patterns
• Safe extraction with path traversal protection

With --deep flag, also scans binary files for embedded strings:
• Extracts readable strings from ELF, Mach-O, and PE binaries
• Scans read-only data sections (.rodata, .rdata, __DATA)
• Useful for finding hardcoded secrets in compiled applications

Supported formats: .zip, .jar, .war, .tar, .tar.gz, .tgz, .tar.bz2, .tar.xz

VM AND ROOTFS IMAGE SCANNING:
Scan virtual machine disk images and rootfs images for secrets:
• Supports qcow2, vmdk, vhd, vhdx, vdi, and raw disk formats
• Parses GPT/MBR partition tables to find root filesystem
• Reads ext4 filesystems directly without mounting
• Identifies secrets in /etc, /home, /root, and application directories

VM image targets are detected by file extension or scheme:
• vm:///path/to/disk.qcow2 (explicit VM scheme)
• rootfs:///path/to/rootfs.ext4 (explicit rootfs scheme)
• /path/to/disk.qcow2, disk.vmdk, disk.vhd (by extension)

Common secrets found in VM images:
• SSH keys and authorized_keys
• Cloud provider credentials
• Database connection strings
• API tokens in config files

OUTPUT MODES:
• text: Human-readable output with redacted secrets (default)
• json: Machine-readable output for CI/CD integration
• sarif: SARIF format for GitHub Code Scanning integration

AGENT SECRET MASKING:
The secrets engine also powers agent secret masking for AI-assisted workflows.
When using 'deputy fix --agent' or 'deputy triage --agent', detected secrets
are automatically redacted before being sent to AI providers.`,
		Example: `BASIC USAGE:
  # Scan current directory for secrets
  deputy secrets

  # Scan a specific directory
  deputy secrets /path/to/project

  # Scan and verify if secrets are active
  deputy secrets --verify

  # Output as JSON for CI/CD
  deputy secrets --format json

  # Output as SARIF for GitHub Code Scanning
  deputy secrets --format sarif > secrets.sarif

HISTORICAL ANALYSIS:
  # Scan git history for leaked secrets
  deputy secrets --history

  # Scan last 100 commits only
  deputy secrets --history --max-commits 100

  # Scan commits from the last month
  deputy secrets --history --since "1 month ago"

  # Scan commits between two dates
  deputy secrets --history --since "2024-01-01" --until "2024-06-01"

  # Scan a specific branch's history
  deputy secrets --history --branch develop

  # Include secrets that were later removed
  deputy secrets --history --include-removed

  # Filter to specific file patterns
  deputy secrets --history --path-filter "*.env,*.yaml,config/*"

GIT REF COMPARISONS (like deputy diff):
  # Scan for new secrets between two branches
  deputy secrets --diff main feature-branch

  # Scan for secrets introduced since last release
  deputy secrets --diff v1.0.0 HEAD

  # Scan for secrets in a PR (base to HEAD)
  deputy secrets --diff origin/main HEAD

  # Time-based comparison
  deputy secrets --diff "main@{1.week.ago}" main

CI/CD WORKFLOWS:
  # Check for new secrets in PR (exit non-zero if found)
  deputy secrets --diff $BASE_SHA $HEAD_SHA --format json

  # Scan full history in initial audit (report only, do not fail the step)
  deputy secrets --history --include-removed --format json --always-exit-zero > secrets-audit.json

GITHUB ACTIONS INTEGRATION:
  # Fail the job as soon as a secret is found
  - name: Scan for secrets
    run: deputy secrets

  # Or report first and gate later: --always-exit-zero keeps the upload reachable
  - name: Scan for secrets (report)
    run: deputy secrets --format sarif --always-exit-zero > secrets.sarif
  - name: Upload SARIF
    uses: github/codeql-action/upload-sarif@v3
    with:
      sarif_file: secrets.sarif

CONTAINER IMAGE SCANNING:
  # Scan a container image (auto-detects as remote registry)
  deputy secrets nginx:1.25
  deputy secrets alpine:3.19

  # Scan from a private registry
  deputy secrets ghcr.io/owner/app:v1.0

  # Deep layer scanning (extracts and scans files within layers)
  deputy secrets nginx:1.25 --deep
  deputy secrets ghcr.io/owner/app:v1.0 --deep

  # Explicit transport schemes
  deputy secrets docker://nginx:1.25
  deputy secrets docker-daemon://myapp:latest
  deputy secrets tarball:///path/to/image.tar

  # JSON output for CI/CD pipelines
  deputy secrets nginx:1.25 --format json

VM AND ROOTFS IMAGES:
  # Scan a VM disk image for secrets
  deputy secrets vm:///path/to/disk.qcow2
  deputy secrets /path/to/disk.vmdk

  # Scan a rootfs image
  deputy secrets rootfs:///path/to/rootfs.ext4

  # JSON output for CI/CD
  deputy secrets vm:///path/to/disk.qcow2 --format json

FILTERING:
  # Scan only specific file types
  deputy secrets --include "*.yaml,*.json,*.env"

  # Show actual secret values (use with caution)
  deputy secrets --no-redact`,
		Args: cobra.MaximumNArgs(3),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()
			out := cmd.OutOrStdout()
			errW := cmd.ErrOrStderr()

			// Handle diff mode: scan for new secrets between two refs
			if diffMode {
				// In diff mode, arguments are git refs, not directories
				target := "."
				var baseRef, targetRef string
				switch len(args) {
				case 0:
					return fmt.Errorf("--diff requires at least one git reference argument")
				case 1:
					// Single ref: compare default branch to this ref
					baseRef = "" // Will be resolved to default branch
					targetRef = args[0]
				case 2:
					// Two refs: base and target
					baseRef = args[0]
					targetRef = args[1]
				case 3:
					// Target directory + two refs
					target = args[0]
					baseRef = args[1]
					targetRef = args[2]
				}
				found, err := runDiffSecretsScan(ctx, out, errW, target, baseRef, targetRef, formatFlag, noRedact, pathFilter)
				return secretsExit(found, err, alwaysExitZero)
			}

			// Default to current directory for non-diff modes
			target := "."
			if len(args) > 0 {
				target = args[0]
			}

			// Handle historical analysis mode
			if historyFlag {
				historyOpts := historyScanOptions{
					target:         target,
					format:         formatFlag,
					noRedact:       noRedact,
					maxCommits:     maxCommits,
					since:          sinceFlag,
					until:          untilFlag,
					branch:         branchFlag,
					pathFilter:     pathFilter,
					includeRemoved: includeRemoved,
				}
				found, err := runHistoricalSecretsScan(ctx, out, errW, historyOpts)
				return secretsExit(found, err, alwaysExitZero)
			}

			// Check if target is a VM/rootfs image
			if isVMImageTarget(target) {
				found, err := runVMImageSecretsScan(ctx, out, errW, target, formatFlag, noRedact, includeGlob, excludeGlob)
				return secretsExit(found, err, alwaysExitZero)
			}

			// Check if target is a container image reference
			if isImageTargetScheme(target) || looksLikeContainerReference(target) {
				found, err := runContainerSecretsScan(ctx, out, errW, target, formatFlag, noRedact, deepScan)
				return secretsExit(found, err, alwaysExitZero)
			}

			// Check if target is a remote Git URL (e.g., github.com/owner/repo)
			// This must be checked before os.Stat() since remote URLs don't exist locally
			isRemoteGit := gitx.ToHTTPSGitURL(target) != "" || strings.HasPrefix(target, "git@")

			// Determine if target is a file or directory
			info, err := os.Stat(target)
			if err != nil {
				// If target doesn't exist locally and looks like a Git URL, pass to service
				if isRemoteGit {
					fmt.Fprintln(errW, ui.StyleMeta.Render("Cloning remote repository..."))
					// Build scan options
					scanOpts := &secretsv1.ScanOptions{}
					if includeGlob != "" {
						scanOpts.IncludePatterns = strings.Split(includeGlob, ",")
					}
					if excludeGlob != "" {
						scanOpts.ExcludePatterns = strings.Split(excludeGlob, ",")
					}

					// Call the secrets service which will handle cloning
					resp, err := c.Secrets.Scan(ctx, connect.NewRequest(&secretsv1.ScanRequest{
						Target:  target,
						Options: scanOpts,
					}))
					if err != nil {
						return fmt.Errorf("scanning remote repository: %w", err)
					}

					// Convert proto findings back to internal types for rendering
					findings := internalproto.SecretsFindingsFromProto(resp.Msg.Findings)
					filesScanned := 0
					if resp.Msg.Stats != nil {
						filesScanned = int(resp.Msg.Stats.FilesScanned)
					}

					// Build result and render
					stats := make(map[secrets.SecretType]int)
					highConfCount := 0
					for _, f := range findings {
						stats[f.Type]++
						if f.Confidence >= 0.9 {
							highConfCount++
						}
					}

					result := SecretsResult{
						Target:              target,
						Generated:           time.Now().UTC().Format(time.RFC3339),
						FilesScanned:        filesScanned,
						SecretsFound:        len(findings),
						HighConfidenceCount: highConfCount,
						Findings:            findings,
						Stats:               stats,
					}

					var renderErr error
					switch formatFlag {
					case "json":
						renderErr = outputSecretsProtoJSON(out, resp.Msg)
					case "sarif":
						renderErr = renderSecretsSARIF(out, result, target)
					default:
						renderErr = renderSecretsTextWithVerification(out, result, noRedact, nil)
					}
					return secretsExit(len(findings), renderErr, alwaysExitZero)
				}
				return fmt.Errorf("accessing target: %w", err)
			}

			// Check if target is an archive file
			if !info.IsDir() {
				format, _ := secrets.DetectArchiveFormat(target)
				if format != secrets.FormatUnknown {
					found, err := runArchiveSecretsScan(ctx, out, errW, target, format, formatFlag, noRedact, deepScan)
					return secretsExit(found, err, alwaysExitZero)
				}
			}

			// Use service client for regular file/directory scanning
			// This enables transparent switching between in-process and remote modes
			var findings []secrets.Finding
			var filesScanned int

			// Build scan options
			scanOpts := &secretsv1.ScanOptions{}
			if includeGlob != "" {
				scanOpts.IncludePatterns = strings.Split(includeGlob, ",")
			}
			if excludeGlob != "" {
				scanOpts.ExcludePatterns = strings.Split(excludeGlob, ",")
			}

			// Call the secrets service via client
			resp, err := c.Secrets.Scan(ctx, connect.NewRequest(&secretsv1.ScanRequest{
				Target:  target,
				Options: scanOpts,
			}))
			if err != nil {
				return fmt.Errorf("scanning for secrets: %w", err)
			}

			// Convert proto findings back to internal types for rendering
			findings = internalproto.SecretsFindingsFromProto(resp.Msg.Findings)
			if resp.Msg.Stats != nil {
				filesScanned = int(resp.Msg.Stats.FilesScanned)
			}

			// Filter against baseline if provided
			if baselinePath != "" {
				baseline, err := secrets.LoadBaseline(baselinePath)
				if err != nil {
					return fmt.Errorf("loading baseline: %w", err)
				}
				originalCount := len(findings)
				findings = baseline.Filter(findings)
				if originalCount != len(findings) {
					fmt.Fprintf(errW, "%s\n", ui.StyleMeta.Render(fmt.Sprintf("Filtered %d known secrets from baseline", originalCount-len(findings))))
				}
			}

			// Verify secrets if requested
			var verificationResults map[int]secrets.VerificationResult
			if verifyFlag && len(findings) > 0 {
				fmt.Fprintln(errW, ui.StyleMeta.Render("Verifying secrets..."))
				verifier := secrets.NewVerificationEngine(nil)
				verificationResults = verifier.VerifyBatch(ctx, findings)
			}

			// Compute stats and high confidence count
			stats := make(map[secrets.SecretType]int)
			highConfCount := 0
			for _, f := range findings {
				stats[f.Type]++
				if f.Confidence >= 0.9 {
					highConfCount++
				}
			}

			result := SecretsResult{
				Target:              target,
				Generated:           time.Now().UTC().Format(time.RFC3339),
				FilesScanned:        filesScanned,
				SecretsFound:        len(findings),
				HighConfidenceCount: highConfCount,
				Findings:            findings,
				Stats:               stats,
			}

			var renderErr error
			switch formatFlag {
			case "json":
				// JSON output when no post-processing was needed
				if baselinePath == "" && !verifyFlag {
					renderErr = outputSecretsProtoJSON(out, resp.Msg)
				} else {
					renderErr = renderSecretsJSONWithVerification(out, result, verificationResults)
				}
			case "sarif":
				renderErr = renderSecretsSARIF(out, result, target)
			default:
				renderErr = renderSecretsTextWithVerification(out, result, noRedact, verificationResults)
			}
			return secretsExit(len(findings), renderErr, alwaysExitZero)
		},
	}

	secretsCmd.Flags().StringVarP(&formatFlag, "format", "f", "text", "Output format: text, json, sarif")
	secretsCmd.Flags().StringVar(&includeGlob, "include", "", "Comma-separated globs to include (e.g., '*.yaml,*.json')")
	secretsCmd.Flags().StringVar(&excludeGlob, "exclude", "", "Comma-separated globs to exclude (e.g., 'vendor/**,node_modules/**')")
	secretsCmd.Flags().BoolVar(&noRedact, "no-redact", false, "Show actual secret values (use with caution)")
	secretsCmd.Flags().BoolVar(&verifyFlag, "verify", false, "Verify if detected secrets are still active")
	secretsCmd.Flags().BoolVar(&alwaysExitZero, "always-exit-zero", false, "Exit 0 even when secrets are found (report without failing)")

	// History scanning flags
	secretsCmd.Flags().BoolVar(&historyFlag, "history", false, "Scan git history for secrets")
	secretsCmd.Flags().IntVar(&maxCommits, "max-commits", 0, "Maximum commits to scan (0 = all)")
	secretsCmd.Flags().StringVar(&sinceFlag, "since", "", "Only scan commits after this time (e.g., '1 month ago', '2024-01-15')")
	secretsCmd.Flags().StringVar(&untilFlag, "until", "", "Only scan commits before this time")
	secretsCmd.Flags().StringVar(&branchFlag, "branch", "", "Branch to scan (default: current HEAD)")
	secretsCmd.Flags().StringVar(&pathFilter, "path-filter", "", "Comma-separated path patterns to scan (e.g., '*.env,config/*')")
	secretsCmd.Flags().BoolVar(&includeRemoved, "include-removed", false, "Include secrets that were later removed from the codebase")

	// Diff mode flags
	secretsCmd.Flags().BoolVar(&diffMode, "diff", false, "Scan only changes between two git refs (for PR/CI workflows)")

	// Container deep scanning flags
	secretsCmd.Flags().BoolVar(&deepScan, "deep", false, "Deep scan container layers for secrets in files")

	// Baseline flags
	secretsCmd.Flags().StringVar(&baselinePath, "baseline", "", "Path to baseline file for incremental scanning")

	root.AddCommand(secretsCmd)

	// Add subcommands
	AddSecretsHookCommand(secretsCmd)
	AddSecretsBaselineCommand(secretsCmd)
}

// secretScanFilters compiles include and exclude path matchers for a secrets
// scan walk. Patterns use globmatch's gitignore-flavored semantics, so a single
// MatchPath call replaces the old full-path + basename filepath.Match loops and
// recursive "dir/**" patterns match the whole subtree. It compiles once per
// scan operation; callers reuse the returned matchers for the entire walk.
func secretScanFilters(includePatterns, excludePatterns []string) (excl, incl *globmatch.Matcher, err error) {
	excl, err = globmatch.Compile(excludePatterns)
	if err != nil {
		return nil, nil, fmt.Errorf("compiling exclude patterns: %w", err)
	}
	incl, err = globmatch.Compile(includePatterns)
	if err != nil {
		return nil, nil, fmt.Errorf("compiling include patterns: %w", err)
	}
	return excl, incl, nil
}

// scanDirectory recursively scans a directory for secrets.
// This function works for any directory (git repos, plain directories, system paths).
func scanDirectory(ctx context.Context, engine *secrets.Engine, dir, includeGlob, excludeGlob string) ([]secrets.Finding, int, error) {
	var findings []secrets.Finding
	var filesScanned int

	// Parse include/exclude patterns
	var includePatterns, excludePatterns []string
	if includeGlob != "" {
		includePatterns = strings.Split(includeGlob, ",")
		for i := range includePatterns {
			includePatterns[i] = strings.TrimSpace(includePatterns[i])
		}
	}
	if excludeGlob != "" {
		excludePatterns = strings.Split(excludeGlob, ",")
		for i := range excludePatterns {
			excludePatterns[i] = strings.TrimSpace(excludePatterns[i])
		}
	}

	// Default exclusions for common non-source directories and binary files
	defaultExcludes := []string{
		// Version control
		".git/**",
		".svn/**",
		".hg/**",
		// Dependencies
		"node_modules/**",
		"vendor/**",
		"__pycache__/**",
		".venv/**",
		"venv/**",
		".tox/**",
		".nox/**",
		"target/**", // Rust/Maven
		"dist/**",
		"build/**",
		// IDE and editor
		".idea/**",
		".vscode/**",
		"*.swp",
		"*.swo",
		// Binary extensions
		"*.exe",
		"*.dll",
		"*.so",
		"*.dylib",
		"*.a",
		"*.o",
		"*.obj",
		"*.class",
		"*.pyc",
		"*.pyo",
		// Media files
		"*.png",
		"*.jpg",
		"*.jpeg",
		"*.gif",
		"*.ico",
		"*.svg",
		"*.webp",
		"*.bmp",
		"*.mp3",
		"*.mp4",
		"*.wav",
		"*.avi",
		"*.mov",
		// Documents
		"*.pdf",
		"*.doc",
		"*.docx",
		"*.xls",
		"*.xlsx",
		"*.ppt",
		"*.pptx",
		// Archives
		"*.zip",
		"*.tar",
		"*.gz",
		"*.bz2",
		"*.xz",
		"*.7z",
		"*.rar",
		"*.jar",
		"*.war",
		// Database and data files
		"*.db",
		"*.sqlite",
		"*.sqlite3",
		"*.dat",
		"*.bin",
		// Fonts
		"*.ttf",
		"*.otf",
		"*.woff",
		"*.woff2",
		"*.eot",
	}
	excludePatterns = append(excludePatterns, defaultExcludes...)

	// Compile path matchers once; reused across the whole walk.
	excl, incl, err := secretScanFilters(includePatterns, excludePatterns)
	if err != nil {
		return nil, 0, err
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		return nil, 0, err
	}
	defer root.Close()
	rootFS := root.FS()

	err = fs.WalkDir(rootFS, ".", func(path string, d fs.DirEntry, err error) error {
		// Check context cancellation periodically
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Skip inaccessible files
		}

		relPath := filepath.FromSlash(path)

		// Skip directories
		if d.IsDir() {
			// Skip excluded directories early (whole subtree).
			if excl.MatchPath(path) {
				return fs.SkipDir
			}
			return nil
		}

		// Check exclude patterns
		if excl.MatchPath(path) {
			return nil
		}

		// Check include patterns (if specified)
		if !incl.Empty() && !incl.MatchPath(path) {
			return nil
		}

		// Skip large files (> 1MB)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > 1<<20 {
			return nil
		}

		// Skip symlinks to prevent infinite loops and security issues
		if d.Type()&os.ModeSymlink != 0 {
			return nil
		}

		// Read file content
		content, err := fs.ReadFile(rootFS, path)
		if err != nil {
			return nil // Skip unreadable files
		}

		// Skip binary files by checking content (null bytes in first 512 bytes)
		if isBinaryContent(content) {
			return nil
		}

		fileFindings, err := engine.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil // Skip files that error during scan
		}

		findings = append(findings, fileFindings...)
		filesScanned++

		return nil
	})

	return findings, filesScanned, err
}

// isBinaryContent checks if content appears to be binary by examining the first bytes.
func isBinaryContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	// Check first 512 bytes for null bytes (common indicator of binary)
	checkLen := min(512, len(content))
	for i := range checkLen {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// secretsExit maps a completed secrets scan onto the command's exit status.
// Finding a secret is a failure condition: the documented contract is exit 1
// so CI gates catch leaked credentials, and --always-exit-zero opts out for
// report-only runs (for example generating SARIF for later upload).
//
// Scan errors take precedence and are returned unchanged. A findings exit
// carries no message because the findings themselves were already rendered.
func secretsExit(found int, err error, alwaysExitZero bool) error {
	if err != nil {
		return err
	}
	if found > 0 && !alwaysExitZero {
		return deputyerrors.Silent(deputyerrors.WithExitCode(nil, 1))
	}
	return nil
}

// outputSecretsProtoJSON writes a secrets response as JSON using protojson.
func outputSecretsProtoJSON(w io.Writer, resp *secretsv1.ScanResponse) error {
	opts := internalproto.CLIJSONMarshalOptions()
	data, err := opts.Marshal(resp)
	if err != nil {
		return fmt.Errorf("marshal proto to JSON: %w", err)
	}
	if _, err := w.Write(data); err != nil {
		return err
	}
	_, err = w.Write([]byte("\n"))
	return err
}

// renderSecretsSARIF outputs the result as SARIF for GitHub Code Scanning.
func renderSecretsSARIF(out io.Writer, result SecretsResult, baseURI string) error {
	opts := secrets.DefaultSARIFOptions()
	opts.BaseURI = baseURI
	report := secrets.NewSARIFReport(opts)
	return report.Write(out, result.Findings)
}

// confidenceLabel returns a styled confidence indicator like severity labels.
func confidenceLabel(confidence float64) string {
	switch {
	case confidence >= 0.95:
		return ui.StyleRemoved.Render("[HIGH]")
	case confidence >= 0.85:
		return ui.StyleDowngraded.Render("[MED]")
	default:
		return ui.StyleVersion.Render("[LOW]")
	}
}

// secretTypeDisplay returns a human-readable display name for a secret type.
func secretTypeDisplay(t secrets.SecretType) string {
	// Map to more readable names
	display := map[secrets.SecretType]string{
		secrets.TypeGCPAPIKey:            "GCP API Key",
		secrets.TypeGCPServiceAccountKey: "GCP Service Account Key",
		secrets.TypeRubyGemsAPIKey:       "RubyGems API Key",
		secrets.TypeAWSAccessKey:         "AWS Access Key",
		secrets.TypeAWSSecretKey:         "AWS Secret Key",
		secrets.TypeGitHubToken:          "GitHub Token",
		secrets.TypeGitHubFineGrain:      "GitHub Fine-Grained Token",
		secrets.TypeGenericAPIKey:        "Generic API Key",
		secrets.TypePrivateKey:           "Private Key",
		secrets.TypeJWT:                  "JWT",
		secrets.TypeSlackToken:           "Slack Token",
		secrets.TypeStripeKey:            "Stripe Key",
		secrets.TypeSendGridKey:          "SendGrid Key",
		secrets.TypeNpmToken:             "npm Token",
		secrets.TypePyPIToken:            "PyPI Token",
		secrets.TypeDiscordToken:         "Discord Token",
		secrets.TypeTelegramToken:        "Telegram Token",
		secrets.TypeHerokuAPIKey:         "Heroku API Key",
		secrets.TypeMailgunKey:           "Mailgun Key",
		secrets.TypeTwilioKey:            "Twilio Key",
		secrets.TypeHighEntropy:          "High-Entropy String",
		secrets.TypeSensitiveEnvVar:      "Sensitive Env Var",
	}

	if name, ok := display[t]; ok {
		return ui.StyleSymbol.Render(name)
	}
	return ui.StyleSymbol.Render(string(t))
}

// historyScanOptions consolidates all options for historical secret scanning.
type historyScanOptions struct {
	target         string
	format         string
	noRedact       bool
	maxCommits     int
	since          string
	until          string
	branch         string
	pathFilter     string
	includeRemoved bool
}

// runHistoricalSecretsScan performs git history scanning for secrets.
func runHistoricalSecretsScan(ctx context.Context, out io.Writer, errW io.Writer, opts historyScanOptions) (int, error) {
	// Parse since time if provided
	var sinceTime *time.Time
	if opts.since != "" {
		t, err := parseRelativeTime(opts.since)
		if err != nil {
			return 0, fmt.Errorf("invalid --since value: %w", err)
		}
		sinceTime = &t
	}

	// Parse until time if provided
	var untilTime *time.Time
	if opts.until != "" {
		t, err := parseRelativeTime(opts.until)
		if err != nil {
			return 0, fmt.Errorf("invalid --until value: %w", err)
		}
		untilTime = &t
	}

	// Parse path filter patterns
	var pathPatterns []string
	if opts.pathFilter != "" {
		for p := range strings.SplitSeq(opts.pathFilter, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				pathPatterns = append(pathPatterns, p)
			}
		}
	}

	config := secrets.HistoryScanConfig{
		MaxCommits:     opts.maxCommits,
		Since:          sinceTime,
		Until:          untilTime,
		Branch:         opts.branch,
		PathFilter:     pathPatterns,
		IncludeRemoved: opts.includeRemoved,
	}

	scanner, err := secrets.NewHistoryScanner(config)
	if err != nil {
		return 0, fmt.Errorf("initializing history scanner: %w", err)
	}

	// Build progress message
	progressMsg := "Scanning git history for secrets"
	if opts.branch != "" {
		progressMsg += fmt.Sprintf(" (branch: %s)", opts.branch)
	}
	if opts.maxCommits > 0 {
		progressMsg += fmt.Sprintf(" (max %d commits)", opts.maxCommits)
	}
	fmt.Fprintln(errW, ui.StyleMeta.Render(progressMsg+"..."))

	result, err := scanner.ScanRepository(ctx, opts.target)
	if err != nil {
		return 0, fmt.Errorf("scanning repository history: %w", err)
	}

	found := len(result.Findings)
	if opts.format == "json" {
		return found, renderHistoricalSecretsJSON(out, result)
	}
	return found, renderHistoricalSecretsText(out, result, opts.noRedact)
}

// runDiffSecretsScan scans for secrets introduced between two git refs.
// This is ideal for CI/CD pipelines to detect new secrets in PRs.
func runDiffSecretsScan(ctx context.Context, out io.Writer, errW io.Writer, repoPath, baseRef, targetRef, format string, noRedact bool, pathFilter string) (int, error) {
	// Open repository
	repo, err := git.PlainOpen(repoPath)
	if err != nil {
		return 0, fmt.Errorf("opening git repository: %w", err)
	}

	// Resolve base ref (use default branch if empty)
	if baseRef == "" {
		defaultBranch, err := gitx.GetDefaultBranch(repo)
		if err != nil {
			return 0, fmt.Errorf("determining default branch: %w", err)
		}
		baseRef = defaultBranch
	}

	// Resolve and validate refs using Deputy's enhanced resolver
	baseHash, err := gitx.ResolveRevisionEnhanced(repo, baseRef)
	if err != nil {
		suggestions := gitx.GetReferenceSuggestions(repo, baseRef)
		if len(suggestions) > 0 {
			return 0, fmt.Errorf("invalid base reference %q: %v\nDid you mean one of these?\n  %s", baseRef, err, strings.Join(suggestions, "\n  "))
		}
		return 0, fmt.Errorf("invalid base reference %q: %w", baseRef, err)
	}

	targetHash, err := gitx.ResolveRevisionEnhanced(repo, targetRef)
	if err != nil {
		suggestions := gitx.GetReferenceSuggestions(repo, targetRef)
		if len(suggestions) > 0 {
			return 0, fmt.Errorf("invalid target reference %q: %v\nDid you mean one of these?\n  %s", targetRef, err, strings.Join(suggestions, "\n  "))
		}
		return 0, fmt.Errorf("invalid target reference %q: %w", targetRef, err)
	}

	fmt.Fprintf(errW, "%s\n", ui.StyleMeta.Render(fmt.Sprintf("Scanning for new secrets: %s → %s", baseRef, targetRef)))

	// Create history scanner for diff operation
	config := secrets.HistoryScanConfig{}
	if pathFilter != "" {
		for p := range strings.SplitSeq(pathFilter, ",") {
			p = strings.TrimSpace(p)
			if p != "" {
				config.PathFilter = append(config.PathFilter, p)
			}
		}
	}

	scanner, err := secrets.NewHistoryScanner(config)
	if err != nil {
		return 0, fmt.Errorf("initializing scanner: %w", err)
	}

	// Scan for secrets in the diff
	findings, err := scanner.ScanDiff(ctx, repoPath, baseHash.String(), targetHash.String())
	if err != nil {
		return 0, fmt.Errorf("scanning diff: %w", err)
	}

	// Build result
	result := SecretsDiffResult{
		Repository: repoPath,
		BaseRef:    baseRef,
		TargetRef:  targetRef,
		BaseHash:   baseHash.String()[:7],
		TargetHash: targetHash.String()[:7],
		Generated:  time.Now().UTC().Format(time.RFC3339),
		NewSecrets: len(findings),
		Findings:   findings,
	}

	found := len(findings)
	if format == "json" {
		return found, renderDiffSecretsJSON(out, result)
	}
	return found, renderDiffSecretsText(out, result, noRedact)
}

// SecretsDiffResult contains results from a diff-based secret scan.
type SecretsDiffResult struct {
	Repository string            `json:"repository"`
	BaseRef    string            `json:"baseRef"`
	TargetRef  string            `json:"targetRef"`
	BaseHash   string            `json:"baseHash"`
	TargetHash string            `json:"targetHash"`
	Generated  string            `json:"generated"`
	NewSecrets int               `json:"newSecrets"`
	Findings   []secrets.Finding `json:"findings"`
}

// renderDiffSecretsJSON outputs diff results as JSON using protojson.
func renderDiffSecretsJSON(out io.Writer, result SecretsDiffResult) error {
	// Convert to proto for consistent JSON output
	resp := &secretsv1.ScanDiffResponse{
		BaseRef:       result.BaseRef,
		TargetRef:     result.TargetRef,
		AddedFindings: internalproto.SecretsFindingsToProto(result.Findings),
		Stats: &secretsv1.Stats{
			Total: int32(result.NewSecrets),
		},
	}
	return outputSecretsProtoJSON(out, &secretsv1.ScanResponse{
		Findings: resp.AddedFindings,
		Stats:    resp.Stats,
	})
}

// renderDiffSecretsText outputs diff results as human-readable text.
func renderDiffSecretsText(out io.Writer, result SecretsDiffResult, noRedact bool) error {
	// Header
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Secrets Diff Scan:"))
	fmt.Fprintf(out, "  Base: %s (%s)\n", ui.StylePackageName.Render(result.BaseRef), ui.StyleVersion.Render(result.BaseHash))
	fmt.Fprintf(out, "  Target: %s (%s)\n", ui.StylePackageName.Render(result.TargetRef), ui.StyleVersion.Render(result.TargetHash))

	if len(result.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No new secrets detected in changes"))
		return nil
	}

	// Section header for new secrets
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleRemoved.Render("!"),
		ui.StyleHeader.Render(fmt.Sprintf("New Secrets Detected (%d):", len(result.Findings))))

	// Group by file
	byFile := make(map[string][]secrets.Finding)
	var fileOrder []string
	for _, f := range result.Findings {
		file := f.File
		if file == "" {
			file = "(inline)"
		}
		if _, seen := byFile[file]; !seen {
			fileOrder = append(fileOrder, file)
		}
		byFile[file] = append(byFile[file], f)
	}

	for _, file := range fileOrder {
		fileFindings := byFile[file]
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StylePackageName.Render(file),
			ui.StyleVersion.Render(fmt.Sprintf("[%d]", len(fileFindings))))

		for _, f := range fileFindings {
			location := ""
			if f.Line > 0 {
				location = fmt.Sprintf(":%d", f.Line)
				if f.Column > 0 {
					location += fmt.Sprintf(":%d", f.Column)
				}
			}

			confLabel := confidenceLabel(f.Confidence)
			typeDisplay := secretTypeDisplay(f.Type)

			fmt.Fprintf(out, "  %s %s %s%s\n",
				ui.StyleVersion.Render("•"),
				typeDisplay,
				confLabel,
				ui.StyleMeta.Render(location))

			value := f.Redacted
			if noRedact && f.Value != "" {
				value = f.Value
			}
			fmt.Fprintf(out, "    %s\n", ui.StyleDim.Render(value))
		}
	}

	// Recommendations
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Action Required:"))
	fmt.Fprintf(out, "  %s %s\n",
		ui.StyleRemoved.Render("!"),
		ui.StyleSymbol.Render("New secrets detected - do not merge until resolved"))
	fmt.Fprintf(out, "  1. %s\n", ui.StyleSymbol.Render("Remove secrets from the changeset"))
	fmt.Fprintf(out, "  2. %s\n", ui.StyleSymbol.Render("If already pushed, rotate the credentials immediately"))
	fmt.Fprintf(out, "  3. %s\n", ui.StyleSymbol.Render("Use environment variables or a secrets manager instead"))

	return nil
}

// parseRelativeTime parses human-readable relative time expressions.
func parseRelativeTime(expr string) (time.Time, error) {
	expr = strings.ToLower(strings.TrimSpace(expr))

	// Handle common patterns
	now := time.Now()

	if expr == "yesterday" {
		return now.AddDate(0, 0, -1), nil
	}
	if expr == "last week" {
		return now.AddDate(0, 0, -7), nil
	}
	if expr == "last month" {
		return now.AddDate(0, -1, 0), nil
	}
	if expr == "last year" {
		return now.AddDate(-1, 0, 0), nil
	}

	// Parse patterns like "1 week ago", "2 months ago", "30 days ago"
	var num int
	var unit string
	if _, err := fmt.Sscanf(expr, "%d %s ago", &num, &unit); err == nil {
		unit = strings.TrimSuffix(unit, "s") // Normalize plural
		switch unit {
		case "day":
			return now.AddDate(0, 0, -num), nil
		case "week":
			return now.AddDate(0, 0, -num*7), nil
		case "month":
			return now.AddDate(0, -num, 0), nil
		case "year":
			return now.AddDate(-num, 0, 0), nil
		case "hour":
			return now.Add(-time.Duration(num) * time.Hour), nil
		}
	}

	// Try parsing as duration
	if d, err := time.ParseDuration(expr); err == nil {
		return now.Add(-d), nil
	}

	// Try parsing as RFC3339
	if t, err := time.Parse(time.RFC3339, expr); err == nil {
		return t, nil
	}

	// Try parsing as date
	if t, err := time.Parse("2006-01-02", expr); err == nil {
		return t, nil
	}

	return time.Time{}, fmt.Errorf("unrecognized time format: %s", expr)
}

// renderHistoricalSecretsJSON outputs historical findings as JSON.
func renderHistoricalSecretsJSON(out io.Writer, result *secrets.HistoryScanResult) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// renderHistoricalSecretsText outputs historical findings as text.
func renderHistoricalSecretsText(out io.Writer, result *secrets.HistoryScanResult, noRedact bool) error {
	// Header
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Git History Secrets Scan:"))
	fmt.Fprintf(out, "  Repository: %s\n", ui.StylePackageName.Render(result.Repository))
	fmt.Fprintf(out, "  Commits scanned: %s\n", ui.StyleVersion.Render(fmt.Sprintf("%d", result.CommitsScanned)))

	if len(result.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No secrets found in git history"))
		return nil
	}

	// Section header
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleDowngraded.Render("∴"),
		ui.StyleHeader.Render(fmt.Sprintf("Historical Secrets (%d):", len(result.Findings))))

	// Group by still present vs removed
	var active, removed []secrets.HistoricalFinding
	for _, f := range result.Findings {
		if f.StillPresent {
			active = append(active, f)
		} else {
			removed = append(removed, f)
		}
	}

	// Show active secrets (still in HEAD)
	if len(active) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StyleRemoved.Render("!"),
			ui.StyleBold.Render(fmt.Sprintf("Active Secrets (%d) - still present in current code:", len(active))))

		for _, f := range active {
			renderHistoricalFinding(out, f, noRedact)
		}
	}

	// Show removed secrets (no longer in HEAD but in history)
	if len(removed) > 0 {
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StyleDowngraded.Render("-"),
			ui.StyleBold.Render(fmt.Sprintf("Removed Secrets (%d) - deleted but still in git history:", len(removed))))

		for _, f := range removed {
			renderHistoricalFinding(out, f, noRedact)
		}
	}

	// Summary
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Summary:"))
	fmt.Fprintf(out, "  Total unique secrets: %d\n", result.Stats.TotalSecrets)
	fmt.Fprintf(out, "  Still active: %s\n", ui.StyleRemoved.Render(fmt.Sprintf("%d", result.Stats.ActiveSecrets)))
	fmt.Fprintf(out, "  Removed (but in history): %s\n", ui.StyleDowngraded.Render(fmt.Sprintf("%d", result.Stats.RemovedSecrets)))

	if result.Stats.OldestSecret > 0 {
		fmt.Fprintf(out, "  Oldest secret age: %s\n", ui.StyleMeta.Render(formatDuration(result.Stats.OldestSecret)))
	}

	// Recommendations for historical secrets
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Recommended Actions:"))
	fmt.Fprintf(out, "  1. %s\n", ui.StyleSymbol.Render("Rotate ALL detected secrets immediately (including removed ones)"))
	fmt.Fprintf(out, "  2. %s\n", ui.StyleSymbol.Render("Secrets in git history remain accessible - rotation is mandatory"))
	fmt.Fprintf(out, "  3. %s\n", ui.StyleSymbol.Render("Consider using git-filter-repo to remove secrets from history"))
	fmt.Fprintf(out, "  4. %s\n", ui.StyleSymbol.Render("Enable pre-commit hooks to prevent future secret commits"))

	return nil
}

// renderHistoricalFinding renders a single historical finding.
func renderHistoricalFinding(out io.Writer, f secrets.HistoricalFinding, noRedact bool) {
	typeDisplay := secretTypeDisplay(f.Finding.Type)
	confLabel := confidenceLabel(f.Finding.Confidence)

	fmt.Fprintf(out, "  %s %s %s\n",
		ui.StyleVersion.Render("•"),
		typeDisplay,
		confLabel)

	// Show redacted value
	value := f.Finding.Redacted
	if noRedact && f.Finding.Value != "" {
		value = f.Finding.Value
	}
	fmt.Fprintf(out, "    %s\n", ui.StyleDim.Render(value))

	// Show file location
	if f.Finding.File != "" {
		loc := f.Finding.File
		if f.Finding.Line > 0 {
			loc += fmt.Sprintf(":%d", f.Finding.Line)
		}
		fmt.Fprintf(out, "    File: %s\n", ui.StylePath.Render(loc))
	}

	// Show commit info
	if f.IntroducedIn != nil {
		fmt.Fprintf(out, "    Introduced: %s by %s (%s)\n",
			ui.StyleVersion.Render(f.IntroducedIn.ShortHash),
			ui.StyleMeta.Render(f.IntroducedIn.Author),
			ui.StyleMeta.Render(f.IntroducedIn.Date.Format("2006-01-02")))
	}

	if f.RemovedIn != nil {
		fmt.Fprintf(out, "    Removed: %s (%s)\n",
			ui.StyleVersion.Render(f.RemovedIn.ShortHash),
			ui.StyleMeta.Render(f.RemovedIn.Date.Format("2006-01-02")))
	}

	// Show age
	if f.Age > 0 {
		fmt.Fprintf(out, "    Age: %s\n", ui.StyleMeta.Render(formatDuration(f.Age)))
	}
}

// formatDuration formats a duration in a human-readable way.
func formatDuration(d time.Duration) string {
	days := int(d.Hours() / 24)
	if days > 365 {
		years := days / 365
		return fmt.Sprintf("%d year(s)", years)
	}
	if days > 30 {
		months := days / 30
		return fmt.Sprintf("%d month(s)", months)
	}
	if days > 0 {
		return fmt.Sprintf("%d day(s)", days)
	}
	hours := int(d.Hours())
	if hours > 0 {
		return fmt.Sprintf("%d hour(s)", hours)
	}
	return d.String()
}

// renderSecretsJSONWithVerification outputs findings with verification results as JSON using protojson.
func renderSecretsJSONWithVerification(out io.Writer, result SecretsResult, verifications map[int]secrets.VerificationResult) error {
	// Convert findings to proto with verification data
	protoFindings := make([]*secretsv1.Finding, len(result.Findings))
	for i, f := range result.Findings {
		var v *secrets.VerificationResult
		if vr, ok := verifications[i]; ok {
			v = &vr
		}
		protoFindings[i] = internalproto.SecretsFindingWithVerificationToProto(f, v)
	}

	// Build proto response
	resp := &secretsv1.ScanResponse{
		Findings: protoFindings,
		Stats: &secretsv1.Stats{
			Total:               int32(result.SecretsFound),
			HighConfidenceCount: int32(result.HighConfidenceCount),
			FilesScanned:        int32(result.FilesScanned),
			CountByType:         make(map[string]int32),
		},
	}
	for t, count := range result.Stats {
		resp.Stats.CountByType[string(t)] = int32(count)
	}

	return outputSecretsProtoJSON(out, resp)
}

// renderSecretsTextWithVerification outputs findings with verification results as text.
func renderSecretsTextWithVerification(out io.Writer, result SecretsResult, showValues bool, verifications map[int]secrets.VerificationResult) error {
	// Header block (Deputy style)
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Secrets Scan Results:"))
	fmt.Fprintf(out, "  Target: %s\n", ui.StylePackageName.Render(result.Target))
	fmt.Fprintf(out, "  Files scanned: %s\n", ui.StyleVersion.Render(fmt.Sprintf("%d", result.FilesScanned)))

	// No secrets found - success case
	if len(result.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No secrets detected"))
		return nil
	}

	// Secrets found - show section header
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleDowngraded.Render("∴"),
		ui.StyleHeader.Render(fmt.Sprintf("Secrets Detected (%d):", len(result.Findings))))

	// Group findings by file, sorted for consistent output
	byFile := make(map[string][]int) // file -> finding indices
	var fileOrder []string
	for i, f := range result.Findings {
		file := f.File
		if file == "" {
			file = "(inline)"
		}
		if _, seen := byFile[file]; !seen {
			fileOrder = append(fileOrder, file)
		}
		byFile[file] = append(byFile[file], i)
	}

	for _, file := range fileOrder {
		indices := byFile[file]
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StylePackageName.Render(file),
			ui.StyleVersion.Render(fmt.Sprintf("[%d]", len(indices))))

		for _, idx := range indices {
			f := result.Findings[idx]

			// Build location string
			location := ""
			if f.Line > 0 {
				location = fmt.Sprintf(":%d", f.Line)
				if f.Column > 0 {
					location += fmt.Sprintf(":%d", f.Column)
				}
			}

			// Confidence indicator (styled like severity)
			confLabel := confidenceLabel(f.Confidence)

			// Secret type display
			typeDisplay := secretTypeDisplay(f.Type)

			// Verification status if available
			verifyLabel := ""
			if v, ok := verifications[idx]; ok {
				verifyLabel = " " + verificationStatusLabel(v.Status)
			}

			fmt.Fprintf(out, "  %s %s %s%s%s\n",
				ui.StyleVersion.Render("•"),
				typeDisplay,
				confLabel,
				verifyLabel,
				ui.StyleMeta.Render(location))

			// Show redacted value (or actual value if --no-redact)
			value := f.Redacted
			if showValues && f.Value != "" {
				value = f.Value
			}
			fmt.Fprintf(out, "    %s\n", ui.StyleDim.Render(value))

			// Show verification details if available
			if v, ok := verifications[idx]; ok && v.Message != "" {
				fmt.Fprintf(out, "    %s\n", ui.StyleMeta.Render(v.Message))
			}

			// Show description if available and different from type
			if f.Description != "" && f.Description != string(f.Type) {
				fmt.Fprintf(out, "    %s\n", ui.StyleMeta.Render(f.Description))
			}
		}
	}

	// Summary section
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Summary:"))

	// Count verified secrets
	if len(verifications) > 0 {
		var valid, invalid, unknown int
		for _, v := range verifications {
			switch v.Status {
			case secrets.StatusValid:
				valid++
			case secrets.StatusInvalid, secrets.StatusExpired:
				invalid++
			default:
				unknown++
			}
		}
		if valid > 0 {
			fmt.Fprintf(out, "  %s %s\n",
				ui.StyleRemoved.Render("!"),
				ui.StyleSymbol.Render(fmt.Sprintf("%d secrets verified as ACTIVE - immediate rotation required", valid)))
		}
		if invalid > 0 {
			fmt.Fprintf(out, "  %s %s\n",
				ui.StyleAdded.Render("✓"),
				ui.StyleSymbol.Render(fmt.Sprintf("%d secrets are invalid/revoked", invalid)))
		}
		if unknown > 0 {
			fmt.Fprintf(out, "  %s %s\n",
				ui.StyleMeta.Render("-"),
				ui.StyleSymbol.Render(fmt.Sprintf("%d secrets could not be verified", unknown)))
		}
	} else {
		// Standard summary without verification
		highConfCount := 0
		for _, f := range result.Findings {
			if f.Confidence >= 0.9 {
				highConfCount++
			}
		}
		if highConfCount > 0 {
			fmt.Fprintf(out, "  %s %s\n",
				ui.StyleRemoved.Render("!"),
				ui.StyleSymbol.Render(fmt.Sprintf("%d high-confidence secrets require attention", highConfCount)))
		}
	}

	// Types breakdown (sorted)
	var types []secrets.SecretType
	for t := range result.Stats {
		types = append(types, t)
	}
	// Sort by count descending, then by name
	for i := 0; i < len(types)-1; i++ {
		for j := i + 1; j < len(types); j++ {
			if result.Stats[types[i]] < result.Stats[types[j]] ||
				(result.Stats[types[i]] == result.Stats[types[j]] && string(types[i]) > string(types[j])) {
				types[i], types[j] = types[j], types[i]
			}
		}
	}

	fmt.Fprintf(out, "  %s\n", ui.StyleMeta.Render("By type:"))
	for _, secretType := range types {
		count := result.Stats[secretType]
		fmt.Fprintf(out, "    %s %s %s\n",
			ui.StyleVersion.Render("•"),
			secretTypeDisplay(secretType),
			ui.StyleVersion.Render(fmt.Sprintf("(%d)", count)))
	}

	// Recommendations
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Recommended Actions:"))
	fmt.Fprintf(out, "  1. %s\n", ui.StyleSymbol.Render("Rotate any exposed credentials immediately"))
	fmt.Fprintf(out, "  2. %s\n", ui.StyleSymbol.Render("Add secrets to .gitignore or use environment variables"))
	fmt.Fprintf(out, "  3. %s\n", ui.StyleSymbol.Render("Consider using a secrets manager (Vault, AWS Secrets Manager, etc.)"))

	return nil
}

// verificationStatusLabel returns a styled label for verification status.
func verificationStatusLabel(status secrets.VerificationStatus) string {
	switch status {
	case secrets.StatusValid:
		return ui.StyleRemoved.Render("[ACTIVE]")
	case secrets.StatusInvalid:
		return ui.StyleAdded.Render("[REVOKED]")
	case secrets.StatusExpired:
		return ui.StyleDowngraded.Render("[EXPIRED]")
	case secrets.StatusRateLimited:
		return ui.StyleMeta.Render("[RATE-LIMITED]")
	case secrets.StatusError:
		return ui.StyleMeta.Render("[ERROR]")
	default:
		return ui.StyleVersion.Render("[UNKNOWN]")
	}
}

// runContainerSecretsScan scans a container image for secrets in its config,
// environment variables, build history, labels, and layer contents.
// When deepScan is true, it also scans files within each layer using SCALIBR.
func runContainerSecretsScan(ctx context.Context, out io.Writer, errW io.Writer, target, format string, noRedact, deepScan bool) (int, error) {
	fmt.Fprintln(errW, ui.StyleMeta.Render("Loading container image..."))

	// Normalize target to include scheme if needed
	normalizedTarget := normalizeContainerTarget(target)

	// Open the container image using Deputy's target system
	mat, err := targets.Open(ctx, normalizedTarget, nil)
	if err != nil {
		return 0, fmt.Errorf("loading container image: %w", err)
	}
	if mat.Cleanup != nil {
		defer mat.Cleanup()
	}

	// Extract ContainerImageData which contains both SCALIBR image and v1.Image
	imgData, ok := mat.Data.(*providers.ContainerImageData)
	if !ok || imgData == nil {
		return 0, fmt.Errorf("target %q is not a container image", target)
	}

	// Extract v1.Image for config access
	v1Img := imgData.V1Image
	if v1Img == nil {
		return 0, fmt.Errorf("image config extraction not available for this transport; try using docker:// scheme for remote images")
	}

	// Extract image info (config, metadata, history)
	imageInfo, err := image.Extract(v1Img)
	if err != nil {
		return 0, fmt.Errorf("extracting image configuration: %w", err)
	}

	fmt.Fprintln(errW, ui.StyleMeta.Render("Scanning image configuration for secrets..."))

	// Create container scanner with default config
	config := secrets.DefaultContainerScanConfig()
	scanner, err := secrets.NewContainerScanner(config)
	if err != nil {
		return 0, fmt.Errorf("initializing container scanner: %w", err)
	}

	// Build ImageConfig from extracted info for the scanner
	imgConfig := buildImageConfigForScanner(imageInfo)

	// Scan image config (env vars, labels, history, entrypoint)
	findings, err := scanner.ScanImageConfig(ctx, imgConfig)
	if err != nil {
		return 0, fmt.Errorf("scanning image config: %w", err)
	}

	// Deep layer scanning if requested
	if deepScan {
		fmt.Fprintln(errW, ui.StyleMeta.Render("Performing deep layer scanning..."))

		// Get SCALIBR layers from the image data
		layers, err := imgData.Layers()
		if err != nil {
			return 0, fmt.Errorf("getting image layers for deep scan: %w", err)
		}

		if len(layers) > 0 {
			// Use individual layer scanning to identify which layer introduced each secret
			layerFindings, err := scanner.ScanIndividualLayers(ctx, layers, config.BaseImageLayers)
			if err != nil {
				fmt.Fprintf(errW, "Warning: deep layer scan failed: %v\n", err)
			} else {
				findings = append(findings, layerFindings...)
				fmt.Fprintf(errW, "%s\n", ui.StyleMeta.Render(fmt.Sprintf("Scanned %d layers, found %d secrets in layer files", len(layers), len(layerFindings))))
			}
		}
	}

	// Get image digest for result
	var digest string
	if d, err := v1Img.Digest(); err == nil {
		digest = d.String()
	}

	// Get layer count
	layersScanned := 0
	if imageInfo != nil && imageInfo.Metadata.LayerCount > 0 {
		layersScanned = imageInfo.Metadata.LayerCount
	}

	// Build stats
	stats := secrets.ContainerScanStats{
		TotalSecrets: len(findings),
		BySource:     make(map[secrets.ContainerSecretSource]int),
		ByLayer:      make(map[int]int),
	}
	for _, f := range findings {
		stats.BySource[f.Source]++
		if f.Source == secrets.SourceHistory || f.Source == secrets.SourceLayerFile {
			stats.ByLayer[f.LayerIndex]++
		}
		if f.InBaseImage {
			stats.InBaseImage++
		} else {
			stats.InAppLayers++
		}
	}

	result := secrets.ContainerScanResult{
		Image:         target,
		Digest:        digest,
		LayersScanned: layersScanned,
		Findings:      findings,
		Stats:         stats,
	}

	found := len(findings)
	if format == "json" {
		return found, renderContainerSecretsJSON(out, result)
	}
	return found, renderContainerSecretsText(out, result, noRedact)
}

// runVMImageSecretsScan scans a VM disk image or rootfs for secrets.
// It opens the disk image, extracts the filesystem, and walks it to find secrets.
func runVMImageSecretsScan(ctx context.Context, out io.Writer, errW io.Writer, target, format string, noRedact bool, includeGlob, excludeGlob string) (int, error) {
	fmt.Fprintln(errW, ui.StyleMeta.Render("Loading VM image..."))

	// Open the VM image using Deputy's target system
	mat, err := targets.Open(ctx, target, nil)
	if err != nil {
		return 0, fmt.Errorf("loading VM image: %w", err)
	}
	if mat.Cleanup != nil {
		defer mat.Cleanup()
	}

	// Verify we got a filesystem
	if mat.FS == nil {
		return 0, fmt.Errorf("VM image %q did not provide a filesystem", target)
	}

	fmt.Fprintln(errW, ui.StyleMeta.Render("Scanning VM filesystem for secrets..."))

	// Create secret detection engine
	engine, err := secrets.NewEngine()
	if err != nil {
		return 0, fmt.Errorf("creating secrets engine: %w", err)
	}

	// Scan the filesystem for secrets
	findings, filesScanned, err := scanFilesystem(ctx, engine, mat.FS, includeGlob, excludeGlob)
	if err != nil {
		return 0, fmt.Errorf("scanning VM filesystem: %w", err)
	}

	// Build stats
	stats := make(map[secrets.SecretType]int)
	highConfCount := 0
	for _, f := range findings {
		stats[f.Type]++
		if f.Confidence >= 0.9 {
			highConfCount++
		}
	}

	result := SecretsResult{
		Target:              target,
		Generated:           time.Now().UTC().Format(time.RFC3339),
		FilesScanned:        filesScanned,
		SecretsFound:        len(findings),
		HighConfidenceCount: highConfCount,
		Findings:            findings,
		Stats:               stats,
	}

	found := len(findings)

	// Add provenance info if available
	if mat.Meta.Provenance != nil {
		if format == "json" {
			// Include provenance in JSON output
			type vmSecretsResult struct {
				SecretsResult
				Provenance map[string]string `json:"provenance,omitempty"`
			}
			vmResult := vmSecretsResult{
				SecretsResult: result,
				Provenance:    mat.Meta.Provenance,
			}
			enc := json.NewEncoder(out)
			enc.SetIndent("", "  ")
			return found, enc.Encode(vmResult)
		}
	}

	if format == "json" {
		enc := json.NewEncoder(out)
		enc.SetIndent("", "  ")
		return found, enc.Encode(result)
	}

	return found, renderVMSecretsText(out, result, mat.Meta.Provenance, noRedact)
}

// scanFilesystem scans an fs.FS for secrets.
// This is similar to scanDirectory but works with any fs.FS implementation.
func scanFilesystem(ctx context.Context, engine *secrets.Engine, fsys fs.FS, includeGlob, excludeGlob string) ([]secrets.Finding, int, error) {
	var findings []secrets.Finding
	var filesScanned int

	// Parse include/exclude patterns
	var includePatterns, excludePatterns []string
	if includeGlob != "" {
		includePatterns = strings.Split(includeGlob, ",")
		for i := range includePatterns {
			includePatterns[i] = strings.TrimSpace(includePatterns[i])
		}
	}
	if excludeGlob != "" {
		excludePatterns = strings.Split(excludeGlob, ",")
		for i := range excludePatterns {
			excludePatterns[i] = strings.TrimSpace(excludePatterns[i])
		}
	}

	// Default exclusions for binary files and common non-source patterns
	defaultExcludes := []string{
		// Binary extensions
		"*.exe", "*.dll", "*.so", "*.dylib", "*.a", "*.o", "*.obj", "*.class", "*.pyc", "*.pyo",
		// Media files
		"*.png", "*.jpg", "*.jpeg", "*.gif", "*.ico", "*.svg", "*.webp", "*.bmp",
		"*.mp3", "*.mp4", "*.wav", "*.avi", "*.mov",
		// Documents
		"*.pdf", "*.doc", "*.docx", "*.xls", "*.xlsx", "*.ppt", "*.pptx",
		// Archives
		"*.zip", "*.tar", "*.gz", "*.bz2", "*.xz", "*.7z", "*.rar", "*.jar", "*.war",
		// Database files
		"*.db", "*.sqlite", "*.sqlite3",
		// Fonts
		"*.ttf", "*.otf", "*.woff", "*.woff2", "*.eot",
	}
	excludePatterns = append(excludePatterns, defaultExcludes...)

	// Compile path matchers once; reused across the whole walk.
	excl, incl, err := secretScanFilters(includePatterns, excludePatterns)
	if err != nil {
		return nil, 0, err
	}

	err = fs.WalkDir(fsys, ".", func(path string, d fs.DirEntry, err error) error {
		// Check context cancellation
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories
		if d.IsDir() {
			// Skip excluded directories early (whole subtree).
			if excl.MatchPath(path) {
				return fs.SkipDir
			}
			return nil
		}

		relPath := filepath.FromSlash(path)

		// Check exclude patterns
		if excl.MatchPath(path) {
			return nil
		}

		// Check include patterns (if specified)
		if !incl.Empty() && !incl.MatchPath(path) {
			return nil
		}

		// Skip large files (> 1MB)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > 1<<20 {
			return nil
		}

		// Read file contents
		content, err := fs.ReadFile(fsys, path)
		if err != nil {
			return nil // Skip unreadable files
		}

		filesScanned++

		// Scan file for secrets
		fileFindings, err := engine.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil // Continue on scan errors
		}

		findings = append(findings, fileFindings...)
		return nil
	})

	return findings, filesScanned, err
}

// renderVMSecretsText outputs VM scan results as human-readable text.
func renderVMSecretsText(out io.Writer, result SecretsResult, provenance map[string]string, noRedact bool) error {
	// Header
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("VM Image Secrets Scan:"))
	fmt.Fprintf(out, "  Target: %s\n", ui.StylePackageName.Render(result.Target))

	// Show provenance details
	if provenance != nil {
		if format := provenance["format"]; format != "" {
			fmt.Fprintf(out, "  Format: %s\n", ui.StyleVersion.Render(format))
		}
		if pt := provenance["partition_table"]; pt != "" {
			fmt.Fprintf(out, "  Partition Table: %s\n", ui.StyleVersion.Render(pt))
		}
		if fsType := provenance["filesystem_type"]; fsType != "" {
			fmt.Fprintf(out, "  Filesystem: %s\n", ui.StyleVersion.Render(fsType))
		}
	}

	fmt.Fprintf(out, "  Files scanned: %d\n", result.FilesScanned)
	fmt.Fprintln(out)

	if len(result.Findings) == 0 {
		fmt.Fprintln(out, ui.StyleMeta.Render("No secrets detected."))
		return nil
	}

	// Summary
	fmt.Fprintln(out, ui.StyleCritical.Render(fmt.Sprintf("Found %d potential secrets (%d high confidence):",
		result.SecretsFound, result.HighConfidenceCount)))
	fmt.Fprintln(out)

	// Type breakdown
	if len(result.Stats) > 0 {
		fmt.Fprintln(out, "  By type:")
		for secretType, count := range result.Stats {
			fmt.Fprintf(out, "    %s: %d\n", secretType, count)
		}
		fmt.Fprintln(out)
	}

	// Individual findings
	for i, f := range result.Findings {
		if i >= 20 {
			fmt.Fprintf(out, "  ... and %d more findings\n", len(result.Findings)-20)
			break
		}

		confidenceStyle := ui.StyleMeta
		if f.Confidence >= 0.9 {
			confidenceStyle = ui.StyleCritical
		} else if f.Confidence >= 0.7 {
			confidenceStyle = ui.StyleDowngraded // Yellow/warning color
		}

		fmt.Fprintf(out, "  %s %s\n",
			confidenceStyle.Render(fmt.Sprintf("[%.0f%%]", f.Confidence*100)),
			ui.StylePackageName.Render(string(f.Type)))

		fmt.Fprintf(out, "    File: %s", ui.StylePath.Render(f.File))
		if f.Line > 0 {
			fmt.Fprintf(out, ":%d", f.Line)
		}
		fmt.Fprintln(out)

		if f.Redacted != "" {
			displayed := f.Redacted
			if !noRedact && len(displayed) > 40 {
				displayed = displayed[:20] + "..." + displayed[len(displayed)-10:]
			}
			fmt.Fprintf(out, "    Match: %s\n", displayed)
		}
		fmt.Fprintln(out)
	}

	return nil
}

// buildImageConfigForScanner converts image.Info to secrets.ImageConfig for the scanner.
func buildImageConfigForScanner(info *image.Info) *secrets.ImageConfig {
	if info == nil {
		return &secrets.ImageConfig{}
	}

	imgConfig := &secrets.ImageConfig{
		Env:        info.Config.Env,
		Entrypoint: info.Config.Entrypoint,
		Cmd:        info.Config.Cmd,
		Labels:     info.Config.Labels,
	}

	// Convert history entries
	for _, h := range info.History {
		imgConfig.History = append(imgConfig.History, secrets.ImageHistoryEntry{
			CreatedBy:  h.CreatedBy,
			EmptyLayer: h.EmptyLayer,
		})
	}

	return imgConfig
}

// renderContainerSecretsJSON outputs container scan results as JSON.
func renderContainerSecretsJSON(out io.Writer, result secrets.ContainerScanResult) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// renderContainerSecretsText outputs container scan results as human-readable text.
func renderContainerSecretsText(out io.Writer, result secrets.ContainerScanResult, noRedact bool) error {
	// Header
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Container Image Secrets Scan:"))
	fmt.Fprintf(out, "  Image: %s\n", ui.StylePackageName.Render(result.Image))
	if result.Digest != "" {
		fmt.Fprintf(out, "  Digest: %s\n", ui.StyleVersion.Render(result.Digest[:19]+"..."))
	}
	if result.LayersScanned > 0 {
		fmt.Fprintf(out, "  Layers: %s\n", ui.StyleVersion.Render(fmt.Sprintf("%d", result.LayersScanned)))
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No secrets detected in container image"))
		return nil
	}

	// Section header for findings
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleRemoved.Render("!"),
		ui.StyleHeader.Render(fmt.Sprintf("Secrets Detected (%d):", len(result.Findings))))

	// Group findings by source for clearer presentation
	bySource := make(map[secrets.ContainerSecretSource][]secrets.ContainerFinding)
	sourceOrder := []secrets.ContainerSecretSource{
		secrets.SourceEnvVar,
		secrets.SourceHistory,
		secrets.SourceEntrypoint,
		secrets.SourceLabel,
		secrets.SourceLayerFile,
	}
	for _, f := range result.Findings {
		bySource[f.Source] = append(bySource[f.Source], f)
	}

	for _, source := range sourceOrder {
		findings := bySource[source]
		if len(findings) == 0 {
			continue
		}

		// Source section header
		fmt.Fprintln(out)
		sourceLabel := containerSourceLabel(source)
		fmt.Fprintf(out, "%s %s\n",
			ui.StyleDowngraded.Render("∴"),
			ui.StyleBold.Render(fmt.Sprintf("%s (%d):", sourceLabel, len(findings))))

		for _, f := range findings {
			// Secret type and confidence
			confLabel := confidenceLabel(f.Finding.Confidence)
			typeDisplay := secretTypeDisplay(f.Finding.Type)

			// Layer info for history/layer sources
			layerInfo := ""
			if f.Source == secrets.SourceHistory || f.Source == secrets.SourceLayerFile {
				layerInfo = fmt.Sprintf(" [layer %d]", f.LayerIndex)
				if f.InBaseImage {
					layerInfo += " (base image)"
				}
			}

			fmt.Fprintf(out, "  %s %s %s%s\n",
				ui.StyleVersion.Render("•"),
				typeDisplay,
				confLabel,
				ui.StyleMeta.Render(layerInfo))

			// File/location context
			if f.Finding.File != "" {
				fmt.Fprintf(out, "    Location: %s\n", ui.StylePath.Render(f.Finding.File))
			}

			// Show redacted value
			value := f.Finding.Redacted
			if noRedact && f.Finding.Value != "" {
				value = f.Finding.Value
			}
			fmt.Fprintf(out, "    Value: %s\n", ui.StyleDim.Render(value))

			// Show layer command context for history findings
			if f.LayerCommand != "" {
				fmt.Fprintf(out, "    Command: %s\n", ui.StyleMeta.Render(f.LayerCommand))
			}
		}
	}

	// Summary
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Summary:"))

	// By source breakdown
	fmt.Fprintf(out, "  %s\n", ui.StyleMeta.Render("By location:"))
	for source, count := range result.Stats.BySource {
		if count > 0 {
			fmt.Fprintf(out, "    %s %s %s\n",
				ui.StyleVersion.Render("•"),
				containerSourceLabel(source),
				ui.StyleVersion.Render(fmt.Sprintf("(%d)", count)))
		}
	}

	// Base image vs app layers
	if result.Stats.InBaseImage > 0 || result.Stats.InAppLayers > 0 {
		fmt.Fprintf(out, "  %s\n", ui.StyleMeta.Render("By layer origin:"))
		if result.Stats.InBaseImage > 0 {
			fmt.Fprintf(out, "    %s Base image layers: %s\n",
				ui.StyleVersion.Render("•"),
				ui.StyleDowngraded.Render(fmt.Sprintf("%d", result.Stats.InBaseImage)))
		}
		if result.Stats.InAppLayers > 0 {
			fmt.Fprintf(out, "    %s Application layers: %s\n",
				ui.StyleVersion.Render("•"),
				ui.StyleRemoved.Render(fmt.Sprintf("%d", result.Stats.InAppLayers)))
		}
	}

	// Recommendations
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Recommended Actions:"))
	fmt.Fprintf(out, "  1. %s\n", ui.StyleSymbol.Render("Rotate ALL detected secrets immediately"))
	fmt.Fprintf(out, "  2. %s\n", ui.StyleSymbol.Render("Rebuild image without secrets in ENV/ARG instructions"))
	fmt.Fprintf(out, "  3. %s\n", ui.StyleSymbol.Render("Use secret mounting (--secret) during builds instead of ENV"))
	fmt.Fprintf(out, "  4. %s\n", ui.StyleSymbol.Render("Consider multi-stage builds to avoid secrets in final image"))
	fmt.Fprintf(out, "  5. %s\n", ui.StyleSymbol.Render("Secrets in build history persist even after removal - rebuild from scratch"))

	return nil
}

// containerSourceLabel returns a human-readable label for a container secret source.
func containerSourceLabel(source secrets.ContainerSecretSource) string {
	labels := map[secrets.ContainerSecretSource]string{
		secrets.SourceLayerFile:  "Layer Files",
		secrets.SourceEnvVar:     "Environment Variables",
		secrets.SourceBuildArg:   "Build Arguments",
		secrets.SourceLabel:      "Image Labels",
		secrets.SourceHistory:    "Build History",
		secrets.SourceEntrypoint: "Entrypoint/CMD",
	}
	if label, ok := labels[source]; ok {
		return label
	}
	return string(source)
}

// normalizeContainerTarget ensures the target has a proper scheme prefix.
// If no scheme is present, it defaults to "docker://" for remote registry access.
func normalizeContainerTarget(target string) string {
	target = strings.TrimSpace(target)
	if strings.Contains(target, "://") {
		return target
	}
	// Default to docker:// scheme for remote registry access
	return "docker://" + target
}

// runArchiveSecretsScan scans an archive file (zip, tar, tar.gz, etc.) for secrets.
// When deepScan is true, it also scans binary files for embedded strings.
func runArchiveSecretsScan(ctx context.Context, out io.Writer, errW io.Writer, target string, format secrets.ArchiveFormat, outputFormat string, noRedact, deepScan bool) (int, error) {
	fmt.Fprintf(errW, "%s\n", ui.StyleMeta.Render(fmt.Sprintf("Scanning %s archive: %s", format, filepath.Base(target))))

	// Create archive scanner with configuration
	config := secrets.DefaultArchiveScanConfig()
	if deepScan {
		config.ScanBinaryStrings = true
	}

	scanner, err := secrets.NewArchiveScanner(config)
	if err != nil {
		return 0, fmt.Errorf("initializing archive scanner: %w", err)
	}

	// Scan the archive
	result, err := scanner.ScanArchive(ctx, target)
	if err != nil {
		return 0, fmt.Errorf("scanning archive: %w", err)
	}

	// Report any non-fatal errors
	for _, e := range result.Errors {
		fmt.Fprintf(errW, "Warning: %s\n", e)
	}

	if result.Truncated {
		fmt.Fprintf(errW, "Warning: scan truncated: %s\n", result.TruncationReason)
	}

	found := len(result.Findings)
	if outputFormat == "json" {
		return found, renderArchiveSecretsJSON(out, result)
	}
	return found, renderArchiveSecretsText(out, result, noRedact)
}

// renderArchiveSecretsJSON outputs archive scan results as JSON.
func renderArchiveSecretsJSON(out io.Writer, result *secrets.ArchiveScanResult) error {
	enc := json.NewEncoder(out)
	enc.SetIndent("", "  ")
	return enc.Encode(result)
}

// renderArchiveSecretsText outputs archive scan results as human-readable text.
func renderArchiveSecretsText(out io.Writer, result *secrets.ArchiveScanResult, noRedact bool) error {
	// Header
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Archive Secrets Scan:"))
	fmt.Fprintf(out, "  Archive: %s\n", ui.StylePackageName.Render(result.ArchivePath))
	fmt.Fprintf(out, "  Format: %s\n", ui.StyleVersion.Render(string(result.Format)))
	fmt.Fprintf(out, "  Entries scanned: %s\n", ui.StyleVersion.Render(fmt.Sprintf("%d", result.EntriesScanned)))
	fmt.Fprintf(out, "  Bytes scanned: %s\n", ui.StyleVersion.Render(formatBytes(result.BytesScanned)))

	if result.Truncated {
		fmt.Fprintf(out, "  %s %s\n", ui.StyleDowngraded.Render("!"), ui.StyleMeta.Render("Scan truncated: "+result.TruncationReason))
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(out)
		fmt.Fprintln(out, ui.StyleAdded.Render("✓ No secrets detected in archive"))
		return nil
	}

	// Section header for findings
	fmt.Fprintln(out)
	fmt.Fprintf(out, "%s %s\n",
		ui.StyleRemoved.Render("!"),
		ui.StyleHeader.Render(fmt.Sprintf("Secrets Detected (%d):", len(result.Findings))))

	// Group findings by entry path
	byPath := make(map[string][]secrets.ArchiveFinding)
	var pathOrder []string
	for _, f := range result.Findings {
		path := f.EntryPath
		if f.Nested {
			path = fmt.Sprintf("[nested:%d] %s", f.NestingDepth, f.EntryPath)
		}
		if _, seen := byPath[path]; !seen {
			pathOrder = append(pathOrder, path)
		}
		byPath[path] = append(byPath[path], f)
	}

	for _, path := range pathOrder {
		findings := byPath[path]
		fmt.Fprintln(out)
		fmt.Fprintf(out, "%s %s\n",
			ui.StylePackageName.Render(path),
			ui.StyleVersion.Render(fmt.Sprintf("[%d]", len(findings))))

		for _, f := range findings {
			confLabel := confidenceLabel(f.Finding.Confidence)
			typeDisplay := secretTypeDisplay(f.Finding.Type)

			// Location info
			location := ""
			if f.Finding.Line > 0 {
				location = fmt.Sprintf(":%d", f.Finding.Line)
			}

			fmt.Fprintf(out, "  %s %s %s%s\n",
				ui.StyleVersion.Render("•"),
				typeDisplay,
				confLabel,
				ui.StyleMeta.Render(location))

			// Show redacted value
			value := f.Finding.Redacted
			if noRedact && f.Finding.Value != "" {
				value = f.Finding.Value
			}
			fmt.Fprintf(out, "    %s\n", ui.StyleDim.Render(value))
		}
	}

	// Summary
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Summary:"))

	// Count by type
	byType := make(map[secrets.SecretType]int)
	nestedCount := 0
	for _, f := range result.Findings {
		byType[f.Finding.Type]++
		if f.Nested {
			nestedCount++
		}
	}

	fmt.Fprintf(out, "  Total secrets: %s\n", ui.StyleRemoved.Render(fmt.Sprintf("%d", len(result.Findings))))
	if nestedCount > 0 {
		fmt.Fprintf(out, "  In nested archives: %s\n", ui.StyleDowngraded.Render(fmt.Sprintf("%d", nestedCount)))
	}

	fmt.Fprintf(out, "  %s\n", ui.StyleMeta.Render("By type:"))
	for secretType, count := range byType {
		fmt.Fprintf(out, "    %s %s %s\n",
			ui.StyleVersion.Render("•"),
			secretTypeDisplay(secretType),
			ui.StyleVersion.Render(fmt.Sprintf("(%d)", count)))
	}

	// Recommendations
	fmt.Fprintln(out)
	fmt.Fprintln(out, ui.StyleHeader.Render("Recommended Actions:"))
	fmt.Fprintf(out, "  1. %s\n", ui.StyleSymbol.Render("Rotate ALL detected secrets immediately"))
	fmt.Fprintf(out, "  2. %s\n", ui.StyleSymbol.Render("Remove secrets from archive before distribution"))
	fmt.Fprintf(out, "  3. %s\n", ui.StyleSymbol.Render("Use environment variables or secret managers instead"))
	fmt.Fprintf(out, "  4. %s\n", ui.StyleSymbol.Render("Add pre-commit hooks to prevent secret commits"))

	return nil
}
