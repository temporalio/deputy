package cmd

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	git "github.com/go-git/go-git/v5"
	"github.com/go-git/go-git/v5/plumbing"
	"github.com/google/osv-scalibr/extractor"
	gitx "github.com/picatz/deputy/internal/gitutil"
	indexpkg "github.com/picatz/deputy/internal/index"
	indextui "github.com/picatz/deputy/internal/index/tui"
	inv "github.com/picatz/deputy/internal/inventory"
	"github.com/spf13/cobra"

	"github.com/picatz/deputy/internal/repository"
	sbomx "github.com/picatz/deputy/internal/sbom"
)

const defaultIndexPath = ".deputy/index"

// AddIndexCommand wires the `deputy index` command hierarchy into the CLI.
func AddIndexCommand(root *cobra.Command) {
	var indexPath string

	indexCmd := &cobra.Command{
		Use:   "index",
		Short: "Create, query, and manage Deputy indexes",
		Long: `Store analysis artifacts in a local Pebble-backed index, query them with CEL,
bulk load JSON payloads, prune data, and open the interactive viewer. The same index
format powers Deputy's automated analysis features.`,
	}

	indexCmd.PersistentFlags().StringVar(&indexPath, "path", defaultIndexPath, "Path to the index directory")

	indexCmd.AddCommand(
		newIndexInitCmd(&indexPath),
		newIndexIngestCmd(&indexPath),
		newIndexPutCmd(&indexPath),
		newIndexQueryCmd(&indexPath),
		newIndexDeleteCmd(&indexPath),
		newIndexDropCmd(&indexPath),
		newIndexTUICmd(&indexPath),
	)

	root.AddCommand(indexCmd)
}

func newIndexInitCmd(indexPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "init",
		Short: "Create a new index at the provided path",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}

			if err := os.MkdirAll(resolved, 0o755); err != nil {
				return fmt.Errorf("create index directory: %w", err)
			}

			idx, err := indexpkg.Open(resolved)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			fmt.Fprintf(cmd.OutOrStdout(), "Initialized index at %s\n", resolved)
			return nil
		},
	}
	return cmd
}

func newIndexIngestCmd(indexPath *string) *cobra.Command {
	var (
		ref        string
		ecosystems []string
		namespace  string
		artifactTy string
	)

	cmd := &cobra.Command{
		Use:   "ingest [target]",
		Short: "Scan a target for package inventory and add artifacts to the index",
		Long: `Clone or open the target, collect dependency inventory using osv-scalibr, and
store each discovered package as an index artifact. Targets may be local directories
or remote Git repositories (GitHub shorthand and URLs supported).`,
		Args: cobra.MaximumNArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx := cmd.Context()

			resolvedIndex, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}
			if err := os.MkdirAll(resolvedIndex, 0o755); err != nil {
				return fmt.Errorf("ensure index directory: %w", err)
			}

			target := ""
			if len(args) > 0 {
				target = strings.TrimSpace(args[0])
			}
			if target == "" {
				cwd, err := os.Getwd()
				if err != nil {
					return fmt.Errorf("determine working directory: %w", err)
				}
				target = cwd
			}

			res, err := collectPackagesForIndexing(ctx, target, ref, ecosystems)
			if err != nil {
				return err
			}
			defer res.source.Close()

			idx, err := indexpkg.Open(resolvedIndex)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			meta := ingestMetadata{
				namespace:    namespace,
				artifactType: artifactTy,
				repo:         res.repoIdentifier,
				ref:          res.effectiveRef,
				commitHash:   res.commitHash,
				commitTime:   res.commitTime,
			}

			stored := 0
			for i, pkg := range res.packages {
				if pkg == nil {
					continue
				}
				artifact := packageToArtifact(pkg, meta, i)
				if err := idx.PutArtifact(ctx, artifact); err != nil {
					return fmt.Errorf("store artifact for package %q: %w", artifact.Entity.ID, err)
				}
				stored++
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Indexed %d packages from %s@%s into %s\n", stored, res.repoIdentifier, res.effectiveRef, resolvedIndex)
			return nil
		},
	}

	cmd.Flags().StringVar(&ref, "ref", "HEAD", "Git reference to ingest (branch, tag, commit, or HEAD)")
	cmd.Flags().StringSliceVar(&ecosystems, "ecosystems", []string{"all"}, "Ecosystems to include (default: all supported)")
	cmd.Flags().StringVar(&namespace, "namespace", "security", "Artifact namespace to use when storing packages")
	cmd.Flags().StringVar(&artifactTy, "type", "sca_package", "Artifact type to use when storing packages")

	return cmd
}

func newIndexPutCmd(indexPath *string) *cobra.Command {
	var filePath string
	cmd := &cobra.Command{
		Use:   "put",
		Short: "Insert or update artifacts from JSON input",
		Long: `Accept JSON describing artifacts and upsert them into the index. Input can be a
single artifact object, an array of artifacts, or newline-delimited JSON records.`,
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}

			reader, closer, err := openInputSource(cmd, filePath)
			if err != nil {
				return err
			}
			if closer != nil {
				defer closer.Close()
			}

			artifacts, err := decodeArtifacts(reader)
			if err != nil {
				return err
			}
			if len(artifacts) == 0 {
				return errors.New("no artifacts decoded from input")
			}

			idx, err := indexpkg.Open(resolved)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			now := time.Now().UTC()
			var count int
			for i := range artifacts {
				art := artifacts[i]
				if art.Timestamp.IsZero() {
					art.Timestamp = now.Add(time.Duration(i))
				}
				if err := idx.PutArtifact(cmd.Context(), art); err != nil {
					return fmt.Errorf("put artifact %q: %w", art.ID, err)
				}
				count++
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Stored %d artifacts in %s\n", count, resolved)
			return nil
		},
	}
	cmd.Flags().StringVarP(&filePath, "file", "f", "-", "JSON file containing artifacts ('-' for stdin)")
	return cmd
}

func newIndexQueryCmd(indexPath *string) *cobra.Command {
	var expr string
	var format string
	var limit int
	var vars []string

	cmd := &cobra.Command{
		Use:   "query",
		Short: "Execute a CEL expression against the index",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(expr) == "" {
				return errors.New("--expr is required")
			}

			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}
			if !pathExists(resolved) {
				return fmt.Errorf("index does not exist at %s", resolved)
			}

			idx, err := indexpkg.Open(resolved)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			variables, err := parseVarAssignments(vars)
			if err != nil {
				return err
			}

			compiled, err := idx.Compile(expr, variables)
			if err != nil {
				return fmt.Errorf("compile expression: %w", err)
			}

			seq, err := idx.Query(cmd.Context(), compiled)
			if err != nil {
				return fmt.Errorf("query index: %w", err)
			}

			artifacts, err := collectArtifacts(seq, limit)
			if err != nil {
				return err
			}
			switch strings.ToLower(format) {
			case "", "table", "text":
				return renderArtifactsTable(cmd.OutOrStdout(), artifacts)
			case "json":
				enc := json.NewEncoder(cmd.OutOrStdout())
				enc.SetIndent("", "  ")
				return enc.Encode(artifacts)
			default:
				return fmt.Errorf("unknown format %q (use table or json)", format)
			}
		},
	}

	cmd.Flags().StringVar(&expr, "expr", "", "CEL expression to evaluate")
	cmd.Flags().StringVarP(&format, "format", "o", "table", "Output format: table | json")
	cmd.Flags().IntVarP(&limit, "limit", "n", 0, "Maximum artifacts to return (0 for all)")
	cmd.Flags().StringArrayVar(&vars, "var", nil, "Variable assignment in key=value form (repeatable)")
	return cmd
}

func newIndexDeleteCmd(indexPath *string) *cobra.Command {
	var expr string
	var limit int
	var vars []string
	var yes bool
	var dryRun bool

	cmd := &cobra.Command{
		Use:   "delete",
		Short: "Delete artifacts that match a CEL expression",
		RunE: func(cmd *cobra.Command, args []string) error {
			if strings.TrimSpace(expr) == "" {
				return errors.New("--expr is required")
			}

			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}
			if !pathExists(resolved) {
				return fmt.Errorf("index does not exist at %s", resolved)
			}

			idx, err := indexpkg.Open(resolved)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			variables, err := parseVarAssignments(vars)
			if err != nil {
				return err
			}

			compiled, err := idx.Compile(expr, variables)
			if err != nil {
				return fmt.Errorf("compile expression: %w", err)
			}

			seq, err := idx.Query(cmd.Context(), compiled)
			if err != nil {
				return fmt.Errorf("query index: %w", err)
			}

			artifacts, err := collectArtifacts(seq, limit)
			if err != nil {
				return err
			}
			if len(artifacts) == 0 {
				fmt.Fprintln(cmd.OutOrStdout(), "No artifacts matched the expression.")
				return nil
			}

			if dryRun {
				fmt.Fprintf(cmd.OutOrStdout(), "Matched %d artifacts (dry run).\n", len(artifacts))
				return renderArtifactsTable(cmd.OutOrStdout(), artifacts)
			}

			if !yes {
				return errors.New("refusing to delete without --yes (review matches with --dry-run)")
			}

			ctx := cmd.Context()
			for _, art := range artifacts {
				if err := idx.DeleteArtifact(ctx, art); err != nil {
					return fmt.Errorf("delete artifact %q: %w", art.ID, err)
				}
			}

			fmt.Fprintf(cmd.OutOrStdout(), "Deleted %d artifacts from %s\n", len(artifacts), resolved)
			return nil
		},
	}

	cmd.Flags().StringVar(&expr, "expr", "", "CEL expression to match for deletion")
	cmd.Flags().StringArrayVar(&vars, "var", nil, "Variable assignment in key=value form (repeatable)")
	cmd.Flags().IntVarP(&limit, "limit", "n", 0, "Maximum artifacts to delete (0 for all matches)")
	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm deletion without additional prompts")
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Preview matching artifacts without deleting")
	return cmd
}

func newIndexDropCmd(indexPath *string) *cobra.Command {
	var yes bool

	cmd := &cobra.Command{
		Use:   "drop",
		Short: "Remove the entire index directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}
			if !pathExists(resolved) {
				fmt.Fprintf(cmd.OutOrStdout(), "Index path %s does not exist.\n", resolved)
				return nil
			}
			if !yes {
				return errors.New("refusing to drop index without --yes")
			}
			if err := os.RemoveAll(resolved); err != nil {
				return fmt.Errorf("drop index: %w", err)
			}
			fmt.Fprintf(cmd.OutOrStdout(), "Removed index at %s\n", resolved)
			return nil
		},
	}

	cmd.Flags().BoolVar(&yes, "yes", false, "Confirm dropping the entire index")
	return cmd
}

func newIndexTUICmd(indexPath *string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "tui",
		Short: "Open the interactive index viewer",
		RunE: func(cmd *cobra.Command, args []string) error {
			resolved, err := resolveIndexPath(*indexPath)
			if err != nil {
				return err
			}
			if !pathExists(resolved) {
				return fmt.Errorf("index does not exist at %s", resolved)
			}

			idx, err := indexpkg.Open(resolved)
			if err != nil {
				return fmt.Errorf("open index: %w", err)
			}
			defer idx.Close()

			return indextui.Run(cmd.Context(), idx)
		},
	}
	return cmd
}

func resolveIndexPath(path string) (string, error) {
	if strings.TrimSpace(path) == "" {
		path = defaultIndexPath
	}
	cleaned := filepath.Clean(path)
	if filepath.IsAbs(cleaned) {
		return cleaned, nil
	}
	cwd, err := os.Getwd()
	if err != nil {
		return "", fmt.Errorf("get working directory: %w", err)
	}
	return filepath.Join(cwd, cleaned), nil
}

func pathExists(p string) bool {
	info, err := os.Stat(p)
	if err != nil {
		return false
	}
	return info.IsDir()
}

func openInputSource(cmd *cobra.Command, filePath string) (io.Reader, io.Closer, error) {
	if filePath == "" || filePath == "-" {
		return cmd.InOrStdin(), nil, nil
	}
	f, err := os.Open(filePath)
	if err != nil {
		return nil, nil, fmt.Errorf("open input file: %w", err)
	}
	return bufio.NewReader(f), f, nil
}

func decodeArtifacts(r io.Reader) ([]indexpkg.Artifact, error) {
	data, err := io.ReadAll(r)
	if err != nil {
		return nil, fmt.Errorf("read input: %w", err)
	}
	data = bytes.TrimSpace(data)
	if len(data) == 0 {
		return nil, errors.New("input is empty")
	}

	if data[0] == '[' {
		var artifacts []indexpkg.Artifact
		if err := json.Unmarshal(data, &artifacts); err != nil {
			return nil, fmt.Errorf("decode artifact array: %w", err)
		}
		return artifacts, nil
	}

	if data[0] == '{' {
		var artifact indexpkg.Artifact
		if err := json.Unmarshal(data, &artifact); err != nil {
			return nil, fmt.Errorf("decode artifact: %w", err)
		}
		return []indexpkg.Artifact{artifact}, nil
	}

	lines := bytes.Split(data, []byte("\n"))
	artifacts := make([]indexpkg.Artifact, 0, len(lines))
	for _, line := range lines {
		line = bytes.TrimSpace(line)
		if len(line) == 0 {
			continue
		}
		var artifact indexpkg.Artifact
		if err := json.Unmarshal(line, &artifact); err != nil {
			return nil, fmt.Errorf("decode artifact line: %w", err)
		}
		artifacts = append(artifacts, artifact)
	}
	return artifacts, nil
}

func parseVarAssignments(pairs []string) (map[string]any, error) {
	if len(pairs) == 0 {
		return nil, nil
	}
	vars := make(map[string]any, len(pairs))
	for _, pair := range pairs {
		parts := strings.SplitN(pair, "=", 2)
		if len(parts) != 2 {
			return nil, fmt.Errorf("invalid variable assignment %q (expected key=value)", pair)
		}
		key := strings.TrimSpace(parts[0])
		val := strings.TrimSpace(parts[1])
		if key == "" {
			return nil, fmt.Errorf("invalid variable assignment %q (empty key)", pair)
		}
		parsedVal, err := parseVarValue(val)
		if err != nil {
			return nil, fmt.Errorf("parse variable %q: %w", key, err)
		}
		vars[key] = parsedVal
	}
	return vars, nil
}

func parseVarValue(input string) (any, error) {
	switch {
	case strings.EqualFold(input, "true"):
		return true, nil
	case strings.EqualFold(input, "false"):
		return false, nil
	}
	if i, err := strconv.ParseInt(input, 10, 64); err == nil {
		return i, nil
	}
	if f, err := strconv.ParseFloat(input, 64); err == nil {
		return f, nil
	}
	if t, err := time.Parse(time.RFC3339, input); err == nil {
		return t, nil
	}
	if strings.HasPrefix(input, "\"") && strings.HasSuffix(input, "\"") && len(input) >= 2 {
		unquoted, err := strconv.Unquote(input)
		if err != nil {
			return nil, err
		}
		return unquoted, nil
	}
	return input, nil
}

type ingestionResult struct {
	source         *repository.Source
	repoIdentifier string
	effectiveRef   string
	commitHash     string
	commitTime     time.Time
	packages       []*extractor.Package
}

type ingestMetadata struct {
	namespace    string
	artifactType string
	repo         string
	ref          string
	commitHash   string
	commitTime   time.Time
}

func collectPackagesForIndexing(ctx context.Context, target, ref string, ecosystems []string) (*ingestionResult, error) {
	if strings.TrimSpace(target) == "" {
		return nil, errors.New("target path or repository is required")
	}

	if fi, err := os.Stat(target); err == nil && fi.IsDir() {
		return collectLocalPackages(ctx, target, ref, ecosystems)
	}

	return collectRemotePackages(ctx, target, ref, ecosystems)
}

func collectLocalPackages(ctx context.Context, target, ref string, ecosystems []string) (*ingestionResult, error) {
	abs, err := filepath.Abs(target)
	if err != nil {
		return nil, fmt.Errorf("resolve target path: %w", err)
	}

	src, err := repository.Open(abs)
	if err != nil {
		return nil, fmt.Errorf("open repository: %w", err)
	}

	repo := src.Repo
	effRef := refOrHEAD(ref)
	scanOpts := inv.ScanOptions{Ecosystems: ecosystems}

	var (
		pkgs       []*extractor.Package
		commitHash string
		commitTime time.Time
	)

	if strings.EqualFold(effRef, "HEAD") || strings.EqualFold(effRef, "WORKING") {
		pkgs, err = inv.ScanPackagesWorking(ctx, src.Workspace, scanOpts)
		if err != nil {
			src.Close()
			return nil, fmt.Errorf("scan working tree: %w", err)
		}
		hash, when, dirty := headMetadata(repo)
		commitHash = hash
		commitTime = when
		if dirty || strings.EqualFold(ref, "WORKING") {
			effRef = "WORKING"
		}
	} else {
		hash, err := gitx.ResolveRevisionEnhanced(repo, effRef)
		if err != nil {
			src.Close()
			return nil, fmt.Errorf("resolve ref %q: %w", effRef, err)
		}
		pkgs, err = inv.ScanPackagesAtCommitSnapshot(ctx, repo, *hash, scanOpts)
		if err != nil {
			src.Close()
			return nil, fmt.Errorf("scan commit %s: %w", hash.String(), err)
		}
		commitHash = hash.String()
		commitTime = commitTimeFromCommit(repo, *hash)
	}

	if commitTime.IsZero() {
		commitTime = time.Now().UTC()
	}

	repoID := repoIdentity(repo, abs)

	return &ingestionResult{
		source:         src,
		repoIdentifier: repoID,
		effectiveRef:   shortGitRef(effRef),
		commitHash:     commitHash,
		commitTime:     commitTime,
		packages:       pkgs,
	}, nil
}

func collectRemotePackages(ctx context.Context, target, ref string, ecosystems []string) (*ingestionResult, error) {
	url := sbomx.ToHTTPSGitURL(target)
	if url == "" {
		return nil, fmt.Errorf("could not interpret %q as a repository", target)
	}

	auth := sbomx.AuthForURL(url)
	effRef := refOrHEAD(ref)

	cloneOpts := &git.CloneOptions{
		URL:          url,
		Depth:        1,
		SingleBranch: true,
		Tags:         git.NoTags,
		Auth:         auth,
	}

	if rn, err := sbomx.ResolveReferenceName(ctx, url, auth, effRef); err == nil && rn.String() != "" {
		cloneOpts.ReferenceName = rn
		effRef = rn.String()
	}

	src, err := repository.Clone(ctx, cloneOpts, true)
	if err != nil {
		return nil, fmt.Errorf("failed to clone remote repo %s: %w", url, err)
	}

	scanOpts := inv.ScanOptions{Ecosystems: ecosystems}
	pkgs, err := inv.ScanPackagesWorking(ctx, src.Workspace, scanOpts)
	if err != nil {
		src.Close()
		return nil, fmt.Errorf("scan cloned repository: %w", err)
	}

	repo := src.Repo
	commitHash := ""
	commitTime := time.Now().UTC()

	if hash, err := gitx.ResolveRevisionEnhanced(repo, effRef); err == nil && hash != nil {
		commitHash = hash.String()
		if t := commitTimeFromCommit(repo, *hash); !t.IsZero() {
			commitTime = t
		}
	} else if head, err := repo.Head(); err == nil {
		commitHash = head.Hash().String()
		effRef = head.Name().String()
		if t := commitTimeFromCommit(repo, head.Hash()); !t.IsZero() {
			commitTime = t
		}
	}

	return &ingestionResult{
		source:         src,
		repoIdentifier: url,
		effectiveRef:   shortGitRef(effRef),
		commitHash:     commitHash,
		commitTime:     commitTime,
		packages:       pkgs,
	}, nil
}

func packageToArtifact(pkg *extractor.Package, meta ingestMetadata, seq int) indexpkg.Artifact {
	repoTarget := meta.repo
	if repoTarget != "" && !strings.HasPrefix(repoTarget, "repo:") {
		repoTarget = "repo:" + repoTarget
	}

	entityID := ""
	if purl := pkg.PURL(); purl != nil {
		entityID = purl.String()
	}
	if entityID == "" {
		entityID = strings.TrimSpace(pkg.Name)
	}
	if entityID == "" {
		entityID = fmt.Sprintf("pkg-%d", seq)
	}

	ecosystem := strings.TrimSpace(pkg.Ecosystem())

	entityMeta := map[string]any{}
	if pkg.Name != "" {
		entityMeta["name"] = pkg.Name
	}
	if pkg.Version != "" {
		entityMeta["version"] = pkg.Version
	}
	if ecosystem != "" {
		entityMeta["ecosystem"] = ecosystem
	}
	if entityID != "" {
		entityMeta["purl"] = entityID
	}
	if pkg.SourceCode != nil {
		entityMeta["source_code"] = map[string]any{
			"repo":   pkg.SourceCode.Repo,
			"commit": pkg.SourceCode.Commit,
		}
	}

	dimensions := map[string]string{}
	if ecosystem != "" {
		dimensions["ecosystem"] = ecosystem
	}
	if pkg.Name != "" {
		dimensions["package"] = pkg.Name
	}
	if pkg.Version != "" {
		dimensions["version"] = pkg.Version
	}
	if meta.repo != "" {
		dimensions["repository"] = meta.repo
	}

	data := map[string]any{}
	if len(pkg.Plugins) > 0 {
		data["detected_by"] = pkg.Plugins
	}
	if len(pkg.Locations) > 0 {
		data["locations"] = pkg.Locations
	}
	if len(pkg.Licenses) > 0 {
		data["licenses"] = pkg.Licenses
	}
	if pkg.LayerDetails != nil {
		data["layer_details"] = pkg.LayerDetails
	}
	if pkg.Metadata != nil {
		data["metadata"] = pkg.Metadata
	}
	if len(pkg.AnnotationsDeprecated) > 0 {
		data["annotations"] = pkg.AnnotationsDeprecated
	}
	if len(pkg.ExploitabilitySignals) > 0 {
		data["exploitability_signals"] = pkg.ExploitabilitySignals
	}

	timestamp := meta.commitTime
	if timestamp.IsZero() {
		timestamp = time.Now().UTC()
	}

	context := map[string]any{
		"repository":  meta.repo,
		"ref":         meta.ref,
		"ingested_at": time.Now().UTC(),
	}
	if meta.commitHash != "" {
		context["commit"] = meta.commitHash
	}

	relationships := []indexpkg.Relationship{}
	if repoTarget != "" {
		rel := indexpkg.Relationship{
			Type:   "observed_in",
			Target: repoTarget,
		}
		rel.Metadata = map[string]any{}
		if meta.ref != "" {
			rel.Metadata["ref"] = meta.ref
		}
		if meta.commitHash != "" {
			rel.Metadata["commit"] = meta.commitHash
		}
		relationships = append(relationships, rel)
	}

	artifactID := composeArtifactID(meta.commitHash, entityID, seq)

	return indexpkg.Artifact{
		Namespace: meta.namespace,
		Type:      meta.artifactType,
		ID:        artifactID,
		Entity: indexpkg.Entity{
			Type:     "package",
			ID:       entityID,
			Metadata: entityMeta,
		},
		Timestamp:     timestamp,
		Data:          data,
		Relationships: relationships,
		Context:       context,
		Dimensions:    dimensions,
	}
}

func composeArtifactID(commitHash, entityID string, seq int) string {
	base := strings.TrimSpace(commitHash)
	if base == "" {
		base = fmt.Sprintf("snapshot-%d", seq)
	}
	if entityID == "" {
		return fmt.Sprintf("%s:%d", base, seq)
	}
	return fmt.Sprintf("%s:%s", base, entityID)
}

func headMetadata(repo *git.Repository) (hash string, when time.Time, dirty bool) {
	if repo == nil {
		return "", time.Time{}, false
	}
	if wt, err := repo.Worktree(); err == nil {
		if st, err := wt.Status(); err == nil && !st.IsClean() {
			dirty = true
		}
	}
	if head, err := repo.Head(); err == nil {
		hash = head.Hash().String()
		when = commitTimeFromCommit(repo, head.Hash())
	}
	return
}

func commitTimeFromCommit(repo *git.Repository, hash plumbing.Hash) time.Time {
	if repo == nil {
		return time.Time{}
	}
	commit, err := repo.CommitObject(hash)
	if err != nil {
		return time.Time{}
	}
	if !commit.Committer.When.IsZero() {
		return commit.Committer.When.UTC()
	}
	return commit.Author.When.UTC()
}

func repoIdentity(repo *git.Repository, fallback string) string {
	if repo == nil {
		return fallback
	}
	if remote, err := repo.Remote("origin"); err == nil && remote != nil {
		if cfg := remote.Config(); cfg != nil {
			for _, raw := range cfg.URLs {
				trimmed := strings.TrimSpace(raw)
				if trimmed == "" {
					continue
				}
				if canonical := sbomx.ToHTTPSGitURL(trimmed); canonical != "" {
					return canonical
				}
				return trimmed
			}
		}
	}
	return fallback
}

func collectArtifacts(seq func(func(indexpkg.Artifact, error) bool), limit int) ([]indexpkg.Artifact, error) {
	artifacts := make([]indexpkg.Artifact, 0)
	if limit > 0 {
		artifacts = make([]indexpkg.Artifact, 0, limit)
	}
	count := 0
	var iterErr error
	seq(func(art indexpkg.Artifact, err error) bool {
		if err != nil {
			iterErr = err
			return false
		}
		artifacts = append(artifacts, art)
		count++
		if limit > 0 && count >= limit {
			return false
		}
		return true
	})
	if iterErr != nil {
		return nil, iterErr
	}
	return artifacts, nil
}

func renderArtifactsTable(w io.Writer, artifacts []indexpkg.Artifact) error {
	tw := tabwriter.NewWriter(w, 0, 2, 2, ' ', 0)
	if _, err := fmt.Fprintln(tw, "NAMESPACE\tTYPE\tID\tTIMESTAMP\tENTITY"); err != nil {
		return err
	}
	sort.SliceStable(artifacts, func(i, j int) bool {
		a, b := artifacts[i], artifacts[j]
		if a.Namespace != b.Namespace {
			return a.Namespace < b.Namespace
		}
		if a.Type != b.Type {
			return a.Type < b.Type
		}
		if !a.Timestamp.Equal(b.Timestamp) {
			return a.Timestamp.After(b.Timestamp)
		}
		return a.ID < b.ID
	})
	for _, art := range artifacts {
		if _, err := fmt.Fprintf(tw, "%s\t%s\t%s\t%s\t%s\n",
			art.Namespace,
			art.Type,
			art.ID,
			art.Timestamp.Format(time.RFC3339),
			art.Entity.ID,
		); err != nil {
			return err
		}
	}
	return tw.Flush()
}
