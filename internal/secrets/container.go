package secrets

import (
	"archive/tar"
	"compress/gzip"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"io/fs"
	"log/slog"
	"strings"

	v1 "github.com/google/go-containerregistry/pkg/v1"
	scalibrimage "github.com/google/osv-scalibr/artifact/image"
	"github.com/temporalio/deputy/internal/globmatch"
)

// ContainerFinding extends Finding with container layer context.
type ContainerFinding struct {
	Finding

	// LayerIndex is the layer number (0 = base layer).
	LayerIndex int `json:"layerIndex"`
	// LayerDigest is the layer's digest.
	LayerDigest string `json:"layerDigest,omitempty"`
	// LayerCommand is the Dockerfile command that created this layer.
	LayerCommand string `json:"layerCommand,omitempty"`
	// InBaseImage indicates if this layer is from the base image.
	InBaseImage bool `json:"inBaseImage"`
	// Source indicates where the secret was found.
	Source ContainerSecretSource `json:"source"`
}

// ContainerSecretSource identifies where in a container a secret was found.
type ContainerSecretSource string

const (
	// SourceLayerFile means the secret was found in a file within a layer.
	SourceLayerFile ContainerSecretSource = "layer_file"
	// SourceEnvVar means the secret was found in an environment variable.
	SourceEnvVar ContainerSecretSource = "env_var"
	// SourceBuildArg means the secret was found in a build argument.
	SourceBuildArg ContainerSecretSource = "build_arg"
	// SourceLabel means the secret was found in an image label.
	SourceLabel ContainerSecretSource = "label"
	// SourceHistory means the secret was found in build history.
	SourceHistory ContainerSecretSource = "history"
	// SourceEntrypoint means the secret was found in entrypoint/cmd.
	SourceEntrypoint ContainerSecretSource = "entrypoint"
)

// ContainerScanConfig configures container secret scanning.
type ContainerScanConfig struct {
	// ScanLayers enables deep layer content scanning.
	ScanLayers bool
	// ScanEnvVars enables environment variable scanning.
	ScanEnvVars bool
	// ScanHistory enables build history scanning.
	ScanHistory bool
	// ScanLabels enables label scanning.
	ScanLabels bool
	// MaxLayerSize limits layer scanning to files under this size (bytes).
	MaxLayerSize int64
	// PathPatterns limits file scanning to matching paths.
	PathPatterns []string
	// BaseImageLayers is the number of layers from the base image.
	BaseImageLayers int
}

// DefaultContainerScanConfig returns sensible defaults for container scanning.
func DefaultContainerScanConfig() ContainerScanConfig {
	return ContainerScanConfig{
		ScanLayers:   true,
		ScanEnvVars:  true,
		ScanHistory:  true,
		ScanLabels:   true,
		MaxLayerSize: 10 * 1024 * 1024, // 10MB
		PathPatterns: []string{
			"*.env", "*.yaml", "*.yml", "*.json", "*.conf", "*.config",
			"*.properties", "*.ini", "*.toml", "*.xml", "*.sh", "*.bash",
			".env*", ".npmrc", ".pypirc", ".docker/config.json",
			"*credentials*", "*secret*", "*password*", "*token*",
		},
	}
}

// ContainerScanResult contains results from scanning a container image.
type ContainerScanResult struct {
	// Image is the image reference that was scanned.
	Image string `json:"image"`
	// Digest is the image digest.
	Digest string `json:"digest,omitempty"`
	// LayersScanned is how many layers were analyzed.
	LayersScanned int `json:"layersScanned"`
	// Findings contains all discovered secrets.
	Findings []ContainerFinding `json:"findings"`
	// Stats provides aggregate statistics.
	Stats ContainerScanStats `json:"stats"`
}

// ContainerScanStats provides aggregate statistics.
type ContainerScanStats struct {
	// TotalSecrets is the total secrets found.
	TotalSecrets int `json:"totalSecrets"`
	// BySource breaks down by source location.
	BySource map[ContainerSecretSource]int `json:"bySource"`
	// ByLayer breaks down by layer index.
	ByLayer map[int]int `json:"byLayer"`
	// InBaseImage counts secrets from base image layers.
	InBaseImage int `json:"inBaseImage"`
	// InAppLayers counts secrets from application layers.
	InAppLayers int `json:"inAppLayers"`
}

// ContainerScanner scans container images for secrets.
type ContainerScanner struct {
	engine *Engine
	config ContainerScanConfig
}

// NewContainerScanner creates a new container scanner.
func NewContainerScanner(config ContainerScanConfig) (*ContainerScanner, error) {
	engine, err := NewEngine()
	if err != nil {
		return nil, err
	}
	return &ContainerScanner{
		engine: engine,
		config: config,
	}, nil
}

// ScanImageConfig scans container image configuration for secrets.
// This includes environment variables, labels, entrypoint, and build history.
func (c *ContainerScanner) ScanImageConfig(ctx context.Context, config *ImageConfig) ([]ContainerFinding, error) {
	var findings []ContainerFinding

	// Scan environment variables
	if c.config.ScanEnvVars {
		for _, env := range config.Env {
			parts := strings.SplitN(env, "=", 2)
			if len(parts) != 2 {
				continue
			}
			name, value := parts[0], parts[1]

			// Skip empty values
			if value == "" {
				continue
			}

			// Scan the value
			valueFindings, err := c.engine.Scan(ctx, []byte(value))
			if err != nil {
				continue
			}

			for _, f := range valueFindings {
				f.File = "ENV:" + name
				findings = append(findings, ContainerFinding{
					Finding: f,
					Source:  SourceEnvVar,
				})
			}

			// Also check if name suggests a secret with a non-redacted value
			if IsSensitiveEnvName(name) && !looksRedacted(value) {
				findings = append(findings, ContainerFinding{
					Finding: Finding{
						Type:        TypeSensitiveEnvVar,
						Description: "Sensitive environment variable with potential secret value",
						File:        "ENV:" + name,
						Value:       value,
						Redacted:    redactValue(value, TypeSensitiveEnvVar),
						Confidence:  0.8,
					},
					Source: SourceEnvVar,
				})
			}
		}
	}

	// Scan labels
	if c.config.ScanLabels {
		for key, value := range config.Labels {
			if value == "" {
				continue
			}
			labelFindings, err := c.engine.Scan(ctx, []byte(value))
			if err != nil {
				continue
			}
			for _, f := range labelFindings {
				f.File = "LABEL:" + key
				findings = append(findings, ContainerFinding{
					Finding: f,
					Source:  SourceLabel,
				})
			}
		}
	}

	// Scan entrypoint and cmd
	cmdLine := strings.Join(append(config.Entrypoint, config.Cmd...), " ")
	if cmdLine != "" {
		cmdFindings, err := c.engine.Scan(ctx, []byte(cmdLine))
		if err == nil {
			for _, f := range cmdFindings {
				f.File = "ENTRYPOINT/CMD"
				findings = append(findings, ContainerFinding{
					Finding: f,
					Source:  SourceEntrypoint,
				})
			}
		}
	}

	// Scan build history
	if c.config.ScanHistory {
		for i, entry := range config.History {
			if entry.CreatedBy == "" {
				continue
			}
			histFindings, err := c.engine.Scan(ctx, []byte(entry.CreatedBy))
			if err != nil {
				continue
			}
			for _, f := range histFindings {
				f.File = "HISTORY"
				findings = append(findings, ContainerFinding{
					Finding:      f,
					LayerIndex:   i,
					LayerCommand: truncate(entry.CreatedBy, 100),
					Source:       SourceHistory,
					InBaseImage:  i < c.config.BaseImageLayers,
				})
			}
		}
	}

	return findings, nil
}

// ScanLayerTarball scans a single layer's tarball for secrets.
func (c *ContainerScanner) ScanLayerTarball(ctx context.Context, layerReader io.Reader, layerIndex int, layerDigest string, isBaseImage bool) ([]ContainerFinding, error) {
	if !c.config.ScanLayers {
		return nil, nil
	}

	var findings []ContainerFinding

	// Handle gzip compression
	gzReader, err := gzip.NewReader(layerReader)
	if err != nil {
		// Try uncompressed
		gzReader = nil
	}

	var tarReader *tar.Reader
	if gzReader != nil {
		tarReader = tar.NewReader(gzReader)
		defer gzReader.Close()
	} else {
		// Assume already uncompressed - need to re-read
		return nil, nil
	}

	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			continue
		}

		// Skip directories and special files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Check file size limit
		if header.Size > c.config.MaxLayerSize {
			continue
		}

		// Check path patterns
		if len(c.config.PathPatterns) > 0 && !matchesPathPatterns(header.Name, c.config.PathPatterns) {
			continue
		}

		// Skip binary files
		if isBinaryFile(header.Name) {
			continue
		}

		// Read file content
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, content); err != nil {
			continue
		}

		// Scan for secrets
		fileFindings, err := c.engine.ScanFile(ctx, header.Name, content)
		if err != nil {
			continue
		}

		for _, f := range fileFindings {
			findings = append(findings, ContainerFinding{
				Finding:     f,
				LayerIndex:  layerIndex,
				LayerDigest: layerDigest,
				InBaseImage: isBaseImage,
				Source:      SourceLayerFile,
			})
		}
	}

	return findings, nil
}

// ScanImageLayers scans all layers of a container image for secrets using v1.Image.
// This performs deep content scanning of files within each layer's filesystem.
// The baseImageLayers parameter indicates how many layers are from the base image
// (for distinguishing base image secrets from application secrets).
func (c *ContainerScanner) ScanImageLayers(ctx context.Context, img v1.Image, baseImageLayers int) ([]ContainerFinding, error) {
	if !c.config.ScanLayers {
		return nil, nil
	}

	layers, err := img.Layers()
	if err != nil {
		return nil, fmt.Errorf("getting image layers: %w", err)
	}

	var allFindings []ContainerFinding

	for i, layer := range layers {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		// Get layer digest for identification
		digest, err := layer.Digest()
		if err != nil {
			slog.Debug("failed to get layer digest", "layer", i, "error", err)
			continue
		}

		// Get uncompressed layer content
		reader, err := layer.Uncompressed()
		if err != nil {
			slog.Debug("failed to get uncompressed layer", "layer", i, "digest", digest.String(), "error", err)
			continue
		}

		isBaseImage := i < baseImageLayers

		// Scan this layer's tarball
		findings, err := c.scanLayerTar(ctx, reader, i, digest.String(), isBaseImage)
		reader.Close()

		if err != nil {
			slog.Debug("failed to scan layer", "layer", i, "digest", digest.String(), "error", err)
			continue
		}

		allFindings = append(allFindings, findings...)
	}

	return allFindings, nil
}

// ScanChainLayers scans container image layers using OSV-SCALIBR's ChainLayer interface.
// This provides access to the merged filesystem at each layer, which is more efficient
// for scanning the final state of files across all layers.
// The baseImageLayers parameter indicates how many layers are from the base image.
func (c *ContainerScanner) ScanChainLayers(ctx context.Context, chainLayers []scalibrimage.ChainLayer, baseImageLayers int) ([]ContainerFinding, error) {
	if !c.config.ScanLayers || len(chainLayers) == 0 {
		return nil, nil
	}

	var allFindings []ContainerFinding

	// Scan the final chain layer (contains merged filesystem of all layers)
	// This avoids scanning the same file multiple times across layers
	finalLayer := chainLayers[len(chainLayers)-1]
	layerFS := finalLayer.FS()
	if layerFS == nil {
		return nil, nil
	}

	layerIndex := finalLayer.Index()
	layerDigest := finalLayer.ChainID().String()
	isBaseImage := layerIndex < baseImageLayers

	slog.Debug("scanning final chain layer filesystem",
		"layer_index", layerIndex,
		"chain_id", layerDigest,
		"is_base_image", isBaseImage,
	)

	// Walk the filesystem and scan files
	err := fs.WalkDir(layerFS, ".", func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible entries
		}

		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		// Skip directories
		if d.IsDir() {
			return nil
		}

		// Check path patterns if configured
		if len(c.config.PathPatterns) > 0 && !matchesPathPatterns(path, c.config.PathPatterns) {
			return nil
		}

		// Skip binary files by extension
		if isBinaryFile(path) {
			return nil
		}

		// Get file info for size check
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > c.config.MaxLayerSize {
			return nil
		}

		// Read file content
		file, err := layerFS.Open(path)
		if err != nil {
			return nil
		}
		defer file.Close()

		content, err := io.ReadAll(io.LimitReader(file, c.config.MaxLayerSize))
		if err != nil {
			return nil
		}

		// Skip binary content
		if isBinaryContent(content) {
			return nil
		}

		// Scan for secrets
		fileFindings, err := c.engine.ScanFile(ctx, path, content)
		if err != nil {
			return nil
		}

		for _, f := range fileFindings {
			allFindings = append(allFindings, ContainerFinding{
				Finding:     f,
				LayerIndex:  layerIndex,
				LayerDigest: layerDigest,
				InBaseImage: isBaseImage,
				Source:      SourceLayerFile,
			})
		}

		return nil
	})

	if err != nil {
		return allFindings, fmt.Errorf("walking layer filesystem: %w", err)
	}

	return allFindings, nil
}

// ScanIndividualLayers scans each layer independently using SCALIBR's Layer interface.
// This shows which layer introduced each secret, useful for identifying when secrets
// were added during the build process.
func (c *ContainerScanner) ScanIndividualLayers(ctx context.Context, layers []scalibrimage.Layer, baseImageLayers int) ([]ContainerFinding, error) {
	if !c.config.ScanLayers || len(layers) == 0 {
		return nil, nil
	}

	var allFindings []ContainerFinding

	for i, layer := range layers {
		select {
		case <-ctx.Done():
			return allFindings, ctx.Err()
		default:
		}

		if layer.IsEmpty() {
			continue
		}

		layerFS := layer.FS()
		if layerFS == nil {
			continue
		}

		layerDigest := layer.DiffID().String()
		layerCommand := layer.Command()
		isBaseImage := i < baseImageLayers

		slog.Debug("scanning individual layer",
			"layer_index", i,
			"diff_id", layerDigest,
			"is_base_image", isBaseImage,
			"command", truncate(layerCommand, 50),
		)

		// Walk this layer's filesystem
		err := fs.WalkDir(layerFS, ".", func(path string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}

			select {
			case <-ctx.Done():
				return ctx.Err()
			default:
			}

			if d.IsDir() {
				return nil
			}

			// Check path patterns
			if len(c.config.PathPatterns) > 0 && !matchesPathPatterns(path, c.config.PathPatterns) {
				return nil
			}

			if isBinaryFile(path) {
				return nil
			}

			info, err := d.Info()
			if err != nil {
				return nil
			}
			if info.Size() > c.config.MaxLayerSize {
				return nil
			}

			file, err := layerFS.Open(path)
			if err != nil {
				return nil
			}
			defer file.Close()

			content, err := io.ReadAll(io.LimitReader(file, c.config.MaxLayerSize))
			if err != nil {
				return nil
			}

			if isBinaryContent(content) {
				return nil
			}

			fileFindings, err := c.engine.ScanFile(ctx, path, content)
			if err != nil {
				return nil
			}

			for _, f := range fileFindings {
				allFindings = append(allFindings, ContainerFinding{
					Finding:      f,
					LayerIndex:   i,
					LayerDigest:  layerDigest,
					LayerCommand: truncate(layerCommand, 100),
					InBaseImage:  isBaseImage,
					Source:       SourceLayerFile,
				})
			}

			return nil
		})

		if err != nil {
			slog.Debug("error walking layer", "layer", i, "error", err)
			continue
		}
	}

	return allFindings, nil
}

// scanLayerTar scans an uncompressed tar stream for secrets.
func (c *ContainerScanner) scanLayerTar(ctx context.Context, reader io.Reader, layerIndex int, layerDigest string, isBaseImage bool) ([]ContainerFinding, error) {
	var findings []ContainerFinding
	tarReader := tar.NewReader(reader)

	for {
		select {
		case <-ctx.Done():
			return findings, ctx.Err()
		default:
		}

		header, err := tarReader.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			// Corrupted tar entry, skip
			continue
		}

		// Skip directories and special files
		if header.Typeflag != tar.TypeReg {
			continue
		}

		// Check file size limit
		if header.Size > c.config.MaxLayerSize {
			continue
		}

		// Check path patterns if configured
		if len(c.config.PathPatterns) > 0 && !matchesPathPatterns(header.Name, c.config.PathPatterns) {
			continue
		}

		// Skip binary files by extension
		if isBinaryFile(header.Name) {
			continue
		}

		// Read file content
		content := make([]byte, header.Size)
		if _, err := io.ReadFull(tarReader, content); err != nil {
			continue
		}

		// Skip binary content (check first bytes)
		if isBinaryContent(content) {
			continue
		}

		// Scan for secrets
		fileFindings, err := c.engine.ScanFile(ctx, header.Name, content)
		if err != nil {
			continue
		}

		for _, f := range fileFindings {
			findings = append(findings, ContainerFinding{
				Finding:     f,
				LayerIndex:  layerIndex,
				LayerDigest: layerDigest,
				InBaseImage: isBaseImage,
				Source:      SourceLayerFile,
			})
		}
	}

	return findings, nil
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

// ImageConfig represents container image configuration.
type ImageConfig struct {
	Env        []string            `json:"Env"`
	Entrypoint []string            `json:"Entrypoint"`
	Cmd        []string            `json:"Cmd"`
	Labels     map[string]string   `json:"Labels"`
	History    []ImageHistoryEntry `json:"History"`
}

// ImageHistoryEntry represents a single build history entry.
type ImageHistoryEntry struct {
	CreatedBy  string `json:"created_by"`
	EmptyLayer bool   `json:"empty_layer"`
}

// ParseImageConfig parses image configuration from JSON.
func ParseImageConfig(data []byte) (*ImageConfig, error) {
	var config struct {
		Config  ImageConfig `json:"config"`
		History []struct {
			CreatedBy  string `json:"created_by"`
			EmptyLayer bool   `json:"empty_layer"`
		} `json:"history"`
	}
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	for _, h := range config.History {
		config.Config.History = append(config.Config.History, ImageHistoryEntry{
			CreatedBy:  h.CreatedBy,
			EmptyLayer: h.EmptyLayer,
		})
	}
	return &config.Config, nil
}

// looksRedacted checks if a value appears to be already redacted.
func looksRedacted(value string) bool {
	redactPatterns := []string{
		"REDACTED", "REMOVED", "HIDDEN", "MASKED",
		"***", "xxx", "...", "<secret>",
		"${", "$(", "$(",
	}
	lower := strings.ToLower(value)
	for _, p := range redactPatterns {
		if strings.Contains(lower, strings.ToLower(p)) {
			return true
		}
	}
	// Short placeholder values
	if len(value) < 4 {
		return true
	}
	return false
}

// matchesPathPatterns checks if a path matches any of the patterns. Patterns use
// globmatch's gitignore-flavored semantics, whose bare-name-at-any-depth and
// "dir/**" subtree matching supersede the previous ad-hoc substring fallback.
// Compiled per call; a malformed pattern is treated as no-match.
func matchesPathPatterns(path string, patterns []string) bool {
	m, err := globmatch.Compile(patterns)
	if err != nil {
		return false
	}
	return m.MatchPath(path)
}

// truncate shortens a string to max length.
func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}
