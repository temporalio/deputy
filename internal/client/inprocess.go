package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	containerv1 "github.com/picatz/deputy/gen/deputy/container/v1"
	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	diffv1 "github.com/picatz/deputy/gen/deputy/diff/v1"
	graphv1 "github.com/picatz/deputy/gen/deputy/graph/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	vulnerabilityv1 "github.com/picatz/deputy/gen/deputy/vulnerability/v1"
	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/compare"
	"github.com/picatz/deputy/internal/container/image"
	"github.com/picatz/deputy/internal/dependency/graph"
	"github.com/picatz/deputy/internal/inventory"
	internalproto "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/scan"
	sbomx "github.com/picatz/deputy/internal/sbom"
	sbomdiff "github.com/picatz/deputy/internal/sbom/diff"
	"github.com/picatz/deputy/internal/secrets"
	"github.com/picatz/deputy/internal/targets"
	"github.com/picatz/deputy/internal/vulnerability"
)

// InProcess implements Client by calling services directly without serialization.
// This is the default mode for CLI usage, providing zero overhead compared to
// calling the services directly.
type InProcess struct {
	scanner scan.Scanner
}

// Ensure InProcess implements Client at compile time.
var _ Client = (*InProcess)(nil)

// NewInProcess creates an in-process client with the given scanner.
// If scanner is nil, a default scan.Service is created.
func NewInProcess(scanner scan.Scanner) *InProcess {
	if scanner == nil {
		scanner = scan.NewService()
	}
	return &InProcess{scanner: scanner}
}

// Scanner returns the underlying scan.Scanner for direct access.
// This allows CLI commands to use scanner methods not yet exposed via the client interface.
func (c *InProcess) Scanner() scan.Scanner {
	return c.scanner
}

// Scan performs a vulnerability scan on a target.
// It routes to the appropriate scanner method based on target type detection
// or explicit TargetHint in options.
func (c *InProcess) Scan(ctx context.Context, req *connect.Request[scanv1.ScanRequest]) (*connect.Response[scanv1.ScanResponse], error) {
	target := req.Msg.Target
	if target == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Convert proto options to internal options
	opts := internalproto.ScanOptionsFromProto(req.Msg.Options)

	// Extract ref from options if provided
	ref := ""
	refProvided := false
	if req.Msg.Options != nil && req.Msg.Options.Ref != "" {
		ref = req.Msg.Options.Ref
		refProvided = true
	}

	// Route to appropriate scanner method based on target hint or auto-detection
	execution, err := c.routeScan(ctx, target, ref, refProvided, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan failed: %w", err))
	}

	// Ensure cleanup
	if execution != nil {
		defer execution.Close()
	}

	// Convert result to proto
	response := internalproto.ScanResultToProto(&execution.Result)
	return connect.NewResponse(response), nil
}

// routeScan routes to the appropriate scanner method based on target type.
func (c *InProcess) routeScan(ctx context.Context, target, ref string, refProvided bool, opts scan.Options) (*scan.Execution, error) {
	// Use explicit hint if provided, otherwise auto-detect
	kind := opts.TargetHint.Kind
	if kind == targets.KindUnspecified {
		kind = targets.DetectKind(target)
	}

	switch kind {
	case targets.KindPURL:
		return c.scanner.ScanPURL(ctx, target, opts)

	case targets.KindSBOM:
		// For SBOM targets, repository scan handles file-based detection
		return c.scanner.ScanRepository(ctx, target, ref, refProvided, opts)

	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		if opts.TargetHint.ImageTransport != "" {
			targetOpts["transport"] = opts.TargetHint.ImageTransport
		}
		return c.scanner.ScanContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDockerfile:
		return c.scanner.ScanDockerfile(ctx, target, opts)

	case targets.KindDir:
		return c.scanner.ScanDirectory(ctx, target, opts)

	case targets.KindGit:
		return c.scanner.ScanRepository(ctx, target, ref, refProvided, opts)

	default:
		// Default: try repository scan (handles local dirs, remote repos, etc.)
		return c.scanner.ScanRepository(ctx, target, ref, refProvided, opts)
	}
}

// routeInventory routes to the appropriate inventory collector based on target type.
// This is the fast path that skips vulnerability scanning.
// It uses the inventory package directly for cleaner separation of concerns.
func (c *InProcess) routeInventory(ctx context.Context, req *listv1.ListPackagesRequest) (*inventory.Execution, error) {
	target := req.Target

	// Build inventory options from request
	opts := inventory.Options{}
	if req.Options != nil {
		opts.Ecosystems = req.Options.Ecosystems
		opts.Platform = req.Options.Platform
	}

	// Auto-detect target type
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return inventory.CollectContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDockerfile:
		return inventory.CollectDockerfile(ctx, target, opts)

	case targets.KindDir:
		return inventory.CollectDirectory(ctx, target, opts)

	case targets.KindGit:
		// For git targets, extract ref from options
		ref := "HEAD"
		refProvided := false
		if req.Options != nil && req.Options.Ref != "" {
			ref = req.Options.Ref
			refProvided = true
		}
		return inventory.CollectRepository(ctx, target, ref, refProvided, opts)

	default:
		// Default: try repository (handles local dirs, remote repos, etc.)
		ref := "HEAD"
		refProvided := false
		if req.Options != nil && req.Options.Ref != "" {
			ref = req.Options.Ref
			refProvided = true
		}
		return inventory.CollectRepository(ctx, target, ref, refProvided, opts)
	}
}

// StreamScan performs a vulnerability scan with streaming progress updates.
func (c *InProcess) StreamScan(ctx context.Context, req *connect.Request[scanv1.StreamScanRequest]) (Stream[scanv1.ScanProgress], error) {
	target := req.Msg.Target
	if target == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Create a channel-based stream for in-process mode
	stream := &inProcessScanStream{
		progress: make(chan *scanv1.ScanProgress, 10),
		done:     make(chan struct{}),
	}

	// Run scan in background, sending progress to channel
	go func() {
		defer close(stream.progress)
		defer close(stream.done)

		// Send initializing phase
		stream.progress <- &scanv1.ScanProgress{
			Phase:   scanv1.ScanPhase_SCAN_PHASE_INITIALIZING,
			Message: "Initializing scan...",
		}

		// Convert proto options to internal options
		opts := internalproto.ScanOptionsFromProto(req.Msg.Options)

		// Send resolving target phase
		stream.progress <- &scanv1.ScanProgress{
			Phase:   scanv1.ScanPhase_SCAN_PHASE_RESOLVING_TARGET,
			Message: fmt.Sprintf("Resolving target: %s", target),
		}

		// Extract ref from options if provided
		ref := ""
		refProvided := false
		if req.Msg.Options != nil && req.Msg.Options.Ref != "" {
			ref = req.Msg.Options.Ref
			refProvided = true
		}

		// Send extracting inventory phase
		stream.progress <- &scanv1.ScanProgress{
			Phase:   scanv1.ScanPhase_SCAN_PHASE_EXTRACTING_INVENTORY,
			Message: "Extracting package inventory...",
		}

		// Perform the scan using unified routing
		execution, err := c.routeScan(ctx, target, ref, refProvided, opts)
		if err != nil {
			stream.progress <- &scanv1.ScanProgress{
				Phase:   scanv1.ScanPhase_SCAN_PHASE_FAILED,
				Message: fmt.Sprintf("Scan failed: %v", err),
				Error:   err.Error(),
			}
			return
		}

		if execution != nil {
			defer execution.Close()
		}

		// Convert result to proto
		response := internalproto.ScanResultToProto(&execution.Result)

		// Send complete phase with result
		stream.progress <- &scanv1.ScanProgress{
			Phase:                scanv1.ScanPhase_SCAN_PHASE_COMPLETE,
			Message:              "Scan completed",
			PackagesFound:        response.PackagesScanned,
			VulnerabilitiesFound: int32(len(response.Findings)),
			Result:               response,
		}
	}()

	return stream, nil
}

// ListPackages lists packages in a target.
func (c *InProcess) ListPackages(ctx context.Context, req *connect.Request[listv1.ListPackagesRequest]) (*connect.Response[listv1.ListPackagesResponse], error) {
	target := req.Msg.Target
	if target == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Build inventory options (no vuln scanning needed for list)
	opts := scan.InventoryOptions{}
	onlyDirect := false
	if req.Msg.Options != nil {
		onlyDirect = req.Msg.Options.OnlyDirect
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Route based on target type, similar to how Scan routes
	execution, err := c.routeInventory(ctx, req.Msg)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("list packages failed: %w", err))
	}
	if execution != nil {
		defer execution.Close()
	}

	// Deduplicate packages by PURL, merging direct flags and locations.
	// If any occurrence is direct, the package is considered direct.
	type pkgEntry struct {
		pkg       *dependencyv1.Package
		isDirect  bool
		locations map[string]bool
	}
	entries := make(map[string]*pkgEntry)
	order := make([]string, 0, len(execution.Result.Packages))

	for _, pkg := range execution.Result.Packages {
		isDirect := execution.Result.Direct[pkg.Name]

		purlStr := ""
		if p := pkg.PURL(); p != nil {
			purlStr = p.String()
		}

		// Build a deduplication key from PURL or fallback to ecosystem|name|version
		key := purlStr
		if key == "" {
			key = fmt.Sprintf("%s|%s|%s", pkg.PURLType, pkg.Name, pkg.Version)
		}

		if existing, ok := entries[key]; ok {
			// Merge: if any occurrence is direct, mark as direct
			if isDirect {
				existing.isDirect = true
			}
			// Merge locations
			for _, loc := range pkg.Locations {
				existing.locations[loc] = true
			}
			continue
		}

		// New entry
		locs := make(map[string]bool)
		for _, loc := range pkg.Locations {
			locs[loc] = true
		}
		entries[key] = &pkgEntry{
			pkg: &dependencyv1.Package{
				Name:      pkg.Name,
				Version:   pkg.Version,
				Ecosystem: string(pkg.PURLType),
				Purl:      purlStr,
			},
			isDirect:  isDirect,
			locations: locs,
		}
		order = append(order, key)
	}

	// Build final package list in original order
	packages := make([]*dependencyv1.Package, 0, len(entries))
	ecosystemCounts := make(map[string]int32)
	directCount := int32(0)
	transitiveCount := int32(0)

	for _, key := range order {
		entry := entries[key]
		if onlyDirect && !entry.isDirect {
			continue
		}

		// Convert locations map to slice
		locs := make([]string, 0, len(entry.locations))
		for loc := range entry.locations {
			locs = append(locs, loc)
		}

		entry.pkg.Direct = entry.isDirect
		entry.pkg.Locations = locs
		packages = append(packages, entry.pkg)

		ecosystemCounts[entry.pkg.Ecosystem]++
		if entry.isDirect {
			directCount++
		} else {
			transitiveCount++
		}
	}

	// Convert inventory.Target to scan.Target for proto conversion
	scanTarget := scan.Target{
		Kind:         execution.Result.Target.Kind,
		DisplayPath:  execution.Result.Target.DisplayPath,
		LocalPath:    execution.Result.Target.LocalPath,
		Ref:          execution.Result.Target.Ref,
		EffectiveRef: execution.Result.Target.EffectiveRef,
		CommitHash:   execution.Result.Target.CommitHash,
		OriginURL:    execution.Result.Target.OriginURL,
		Cloned:       execution.Result.Target.Cloned,
		Provenance:   execution.Result.Target.Provenance,
	}

	return connect.NewResponse(&listv1.ListPackagesResponse{
		Target:   internalproto.TargetToProto(scanTarget),
		Packages: packages,
		Stats: &listv1.ListStats{
			TotalPackages:      int32(len(packages)),
			DirectPackages:     directCount,
			TransitivePackages: transitiveCount,
			Ecosystems:         ecosystemCounts,
		},
	}), nil
}

// ListEcosystems lists supported package ecosystems.
func (c *InProcess) ListEcosystems(ctx context.Context, req *connect.Request[listv1.ListEcosystemsRequest]) (*connect.Response[listv1.ListEcosystemsResponse], error) {
	// Return hardcoded list of supported ecosystems
	// In the future, this could be dynamic based on available extractors
	ecosystems := []*listv1.EcosystemInfo{
		{Name: "go", DisplayName: "Go", Description: "Go modules", ManifestFiles: []string{"go.mod"}, LockFiles: []string{"go.sum"}},
		{Name: "npm", DisplayName: "npm", Description: "Node.js packages", ManifestFiles: []string{"package.json"}, LockFiles: []string{"package-lock.json", "yarn.lock", "pnpm-lock.yaml"}},
		{Name: "pypi", DisplayName: "PyPI", Description: "Python packages", ManifestFiles: []string{"requirements.txt", "setup.py", "pyproject.toml"}, LockFiles: []string{"Pipfile.lock", "poetry.lock"}},
		{Name: "maven", DisplayName: "Maven", Description: "Java Maven packages", ManifestFiles: []string{"pom.xml"}},
		{Name: "cargo", DisplayName: "Cargo", Description: "Rust crates", ManifestFiles: []string{"Cargo.toml"}, LockFiles: []string{"Cargo.lock"}},
		{Name: "nuget", DisplayName: "NuGet", Description: ".NET packages", ManifestFiles: []string{"*.csproj", "packages.config", "*.nuspec"}},
		{Name: "rubygems", DisplayName: "RubyGems", Description: "Ruby gems", ManifestFiles: []string{"Gemfile"}, LockFiles: []string{"Gemfile.lock"}},
		{Name: "composer", DisplayName: "Composer", Description: "PHP packages", ManifestFiles: []string{"composer.json"}, LockFiles: []string{"composer.lock"}},
	}

	return connect.NewResponse(&listv1.ListEcosystemsResponse{
		Ecosystems: ecosystems,
	}), nil
}

// GenerateSBOM generates a Software Bill of Materials.
func (c *InProcess) GenerateSBOM(ctx context.Context, req *connect.Request[sbomv1.GenerateRequest]) (*connect.Response[sbomv1.GenerateResponse], error) {
	target := req.Msg.Target
	if target == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target is required"))
	}

	// Convert proto format to internal format string
	formatStr := protoSBOMFormatToString(req.Msg.Format)

	// Build internal options
	opts := sbomx.Options{}
	if req.Msg.Options != nil {
		opts.EnrichLicenses = req.Msg.Options.IncludeLicenses
		opts.Ref = req.Msg.Options.Ref
	}
	if opts.Ref == "" {
		opts.Ref = "HEAD"
	}

	// Generate SBOM
	result, err := sbomx.Generate(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("SBOM generation failed: %w", err))
	}

	// Serialize SBOM to requested format
	var buf bytes.Buffer
	switch formatStr {
	case "cyclonedx-json":
		if err := sbomx.WriteCycloneDXJSON(result.Document, &buf); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to serialize SBOM: %w", err))
		}
	case "spdx-json":
		if err := sbomx.WriteSPDXJSON(result.Document, &buf); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to serialize SBOM: %w", err))
		}
	case "protobom-json":
		if err := sbomx.WriteProtobomJSON(result.Document, &buf); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to serialize SBOM: %w", err))
		}
	default:
		if err := sbomx.WriteCycloneDXJSON(result.Document, &buf); err != nil {
			return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to serialize SBOM: %w", err))
		}
	}

	// Build response
	resp := &sbomv1.GenerateResponse{
		Sbom:        buf.Bytes(),
		Format:      req.Msg.Format,
		GeneratedAt: timestamppb.Now(),
	}

	// Add target info if available
	if result.Target.DisplayPath != "" || result.Target.CommitHash != "" {
		resp.Target = internalproto.TargetToProto(result.Target)
	}

	// Add stats
	ecosystems := make(map[string]int32)
	for _, pkg := range result.Packages {
		eco := pkg.Ecosystem()
		if eco == "" {
			eco = pkg.PURLType
		}
		ecosystems[eco]++
	}
	resp.Stats = &sbomv1.Stats{
		TotalComponents: int32(len(result.Packages)),
		Ecosystems:      ecosystems,
	}

	return connect.NewResponse(resp), nil
}

// protoSBOMFormatToString converts proto SBOM format to internal string format.
func protoSBOMFormatToString(f sbomv1.Format) string {
	switch f {
	case sbomv1.Format_FORMAT_CYCLONEDX_JSON:
		return "cyclonedx-json"
	case sbomv1.Format_FORMAT_CYCLONEDX_XML:
		return "cyclonedx-xml"
	case sbomv1.Format_FORMAT_SPDX_JSON:
		return "spdx-json"
	case sbomv1.Format_FORMAT_SPDX_TV:
		return "spdx-tv"
	case sbomv1.Format_FORMAT_PROTOBOM_JSON:
		return "protobom-json"
	default:
		return "cyclonedx-json"
	}
}

// DiffSBOM computes differences between two SBOMs.
func (c *InProcess) DiffSBOM(ctx context.Context, req *connect.Request[sbomv1.DiffRequest]) (*connect.Response[sbomv1.DiffResponse], error) {
	if len(req.Msg.Base) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base SBOM is required"))
	}
	if len(req.Msg.Target) == 0 {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target SBOM is required"))
	}

	// Parse base SBOM
	baseSBOM, err := sbomx.Read(req.Msg.Base)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse base SBOM: %w", err))
	}

	// Parse target SBOM
	targetSBOM, err := sbomx.Read(req.Msg.Target)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("failed to parse target SBOM: %w", err))
	}

	// Compute diff
	d, err := sbomdiff.Compare(baseSBOM, targetSBOM)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to compare SBOMs: %w", err))
	}

	// Convert to proto response
	resp := &sbomv1.DiffResponse{
		Added:    make([]*dependencyv1.Package, 0, len(d.Added)),
		Removed:  make([]*dependencyv1.Package, 0, len(d.Removed)),
		Modified: make([]*sbomv1.PackageChange, 0, len(d.Changed)),
	}

	for _, pkg := range d.Added {
		resp.Added = append(resp.Added, &dependencyv1.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Purl:      pkg.PURL,
			Licenses:  pkg.Licenses,
		})
	}

	for _, pkg := range d.Removed {
		resp.Removed = append(resp.Removed, &dependencyv1.Package{
			Name:      pkg.Name,
			Version:   pkg.Version,
			Ecosystem: pkg.Ecosystem,
			Purl:      pkg.PURL,
			Licenses:  pkg.Licenses,
		})
	}

	for _, change := range d.Changed {
		resp.Modified = append(resp.Modified, &sbomv1.PackageChange{
			Package: &dependencyv1.Package{
				Name: change.Name,
				Purl: change.PURL,
			},
			PreviousVersion: change.OldVersion,
			NewVersion:      change.NewVersion,
		})
	}

	stats := d.Stats()
	resp.Stats = &sbomv1.DiffStats{
		AddedCount:    int32(stats.Added),
		RemovedCount:  int32(stats.Removed),
		ModifiedCount: int32(stats.Changed),
	}

	return connect.NewResponse(resp), nil
}

// Mode returns the client's execution mode.
func (c *InProcess) Mode() Mode {
	return ModeInProcess
}

// Close releases any resources held by the client.
func (c *InProcess) Close() error {
	// In-process client has no resources to release
	return nil
}

// inProcessScanStream implements Stream[scanv1.ScanProgress] for in-process mode.
type inProcessScanStream struct {
	progress chan *scanv1.ScanProgress
	done     chan struct{}
}

// Receive returns the next progress message.
func (s *inProcessScanStream) Receive() (*scanv1.ScanProgress, error) {
	select {
	case msg, ok := <-s.progress:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-s.done:
		return nil, io.EOF
	}
}

// Close closes the stream.
func (s *inProcessScanStream) Close() error {
	// Stream is already closed when progress channel is closed
	return nil
}

// ============================================================================
// Remediation Service Implementation
// ============================================================================

// GeneratePlan creates a remediation plan from scan results.
func (c *InProcess) GeneratePlan(ctx context.Context, req *connect.Request[remediationv1.GeneratePlanRequest]) (*connect.Response[remediationv1.GeneratePlanResponse], error) {
	// TODO: Implement using internal/remediation package
	// 1. Extract vulnerabilities from ScanResult or SBOM
	// 2. Call remediation.CommandsFromConsolidated()
	// 3. Convert to proto RemediationPlan using internalproto.RemediationCommandsToSteps()
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("GeneratePlan not yet implemented"))
}

// ExecutePlan applies a previously generated remediation plan.
func (c *InProcess) ExecutePlan(ctx context.Context, req *connect.Request[remediationv1.ExecutePlanRequest]) (Stream[remediationv1.ExecutionEvent], error) {
	// TODO: Implement plan execution with streaming
	// 1. Parse plan from request
	// 2. Execute each step, streaming ExecutionEvents
	// 3. Handle deputy:* internal commands specially
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("ExecutePlan not yet implemented"))
}

// ExecuteWithAgent uses an AI agent to generate and apply fixes interactively.
func (c *InProcess) ExecuteWithAgent(ctx context.Context, req *connect.Request[remediationv1.ExecuteWithAgentRequest]) (Stream[remediationv1.AgentEvent], error) {
	// TODO: Implement agent execution with streaming
	// 1. Get provider from ai.DefaultRegistry
	// 2. Create ai.Session with appropriate config
	// 3. Stream AgentEvents from provider execution
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("ExecuteWithAgent not yet implemented"))
}

// ResumeAgent resumes a previous agent execution session.
func (c *InProcess) ResumeAgent(ctx context.Context, req *connect.Request[remediationv1.ResumeAgentRequest]) (Stream[remediationv1.AgentEvent], error) {
	// TODO: Implement session resumption
	// 1. Look up session by ID
	// 2. Resume with follow-up message or approval response
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("ResumeAgent not yet implemented"))
}

// ListAgents returns available AI agents for remediation.
func (c *InProcess) ListAgents(ctx context.Context, req *connect.Request[remediationv1.ListAgentsRequest]) (*connect.Response[remediationv1.ListAgentsResponse], error) {
	// Return agents from the default registry
	providers := ai.AvailableProviders()
	agents := internalproto.AgentInfosToProto(providers)

	return connect.NewResponse(&remediationv1.ListAgentsResponse{
		Agents: agents,
	}), nil
}

// ApproveStep approves or denies a pending remediation step.
func (c *InProcess) ApproveStep(ctx context.Context, req *connect.Request[remediationv1.ApproveStepRequest]) (*connect.Response[remediationv1.ApproveStepResponse], error) {
	// TODO: Implement approval handling
	// 1. Find pending approval by session/step ID
	// 2. Send approval/denial to waiting goroutine
	return nil, connect.NewError(connect.CodeUnimplemented, fmt.Errorf("ApproveStep not yet implemented"))
}

// ============================================================================
// Secrets Service Implementation
// ============================================================================

// secretsEngine is lazily initialized on first secrets call.
func (c *InProcess) getSecretsEngine() (*secrets.Engine, error) {
	// Create engine on demand (could cache this in future)
	return secrets.NewEngine()
}

// ScanSecrets performs secret detection on a target.
// For in-process mode, we use the secrets engine directly to allow local paths.
func (c *InProcess) ScanSecrets(ctx context.Context, req *connect.Request[secretsv1.ScanRequest]) (*connect.Response[secretsv1.ScanResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	engine, err := c.getSecretsEngine()
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to create secrets engine: %w", err))
	}

	// Build scan options from request
	opts := internalproto.SecretsScanOptionsFromProto(req.Msg.Options)

	// Parse include/exclude patterns from options
	var includePatterns, excludePatterns []string
	if req.Msg.Options != nil {
		includePatterns = req.Msg.Options.IncludePatterns
		excludePatterns = req.Msg.Options.ExcludePatterns
	}

	// Scan based on target type
	var findings []secrets.Finding
	var filesScanned int

	info, err := os.Stat(target)
	if err != nil {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target not found: %w", err))
	}

	if info.IsDir() {
		findings, filesScanned, err = c.scanSecretsDir(ctx, engine, target, includePatterns, excludePatterns)
	} else {
		findings, filesScanned, err = c.scanSecretsFile(ctx, engine, target)
	}
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets scan failed: %w", err))
	}

	// Apply confidence filter if set
	if opts.EntropyThreshold > 0 {
		var filtered []secrets.Finding
		for _, f := range findings {
			if f.Confidence >= opts.EntropyThreshold {
				filtered = append(filtered, f)
			}
		}
		findings = filtered
	}

	// Build response
	response := &secretsv1.ScanResponse{
		Target: &targetv1.Target{
			Kind:        targets.DetectKind(target),
			DisplayPath: target,
		},
		GeneratedAt: timestamppb.Now(),
		Findings:    internalproto.SecretsFindingsToProto(findings),
		Stats:       internalproto.SecretsStatsToProto(findings),
	}
	if response.Stats != nil {
		response.Stats.FilesScanned = int32(filesScanned)
	}

	return connect.NewResponse(response), nil
}

// scanSecretsDir scans a directory for secrets.
func (c *InProcess) scanSecretsDir(ctx context.Context, engine *secrets.Engine, dir string, includePatterns, excludePatterns []string) ([]secrets.Finding, int, error) {
	var findings []secrets.Finding
	var filesScanned int

	// Default exclusions
	defaultExcludes := []string{".git", "node_modules", "vendor", "__pycache__", ".venv", "venv", "dist", "build", "target"}

	err := filepath.WalkDir(dir, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return nil // Skip inaccessible files
		}

		// Skip directories
		if d.IsDir() {
			for _, excl := range defaultExcludes {
				if d.Name() == excl {
					return filepath.SkipDir
				}
			}
			return nil
		}

		// Get relative path
		relPath, _ := filepath.Rel(dir, path)

		// Check exclude patterns
		for _, pattern := range excludePatterns {
			if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
				return nil
			}
		}

		// Check include patterns (if specified)
		if len(includePatterns) > 0 {
			included := false
			for _, pattern := range includePatterns {
				if matched, _ := filepath.Match(pattern, filepath.Base(path)); matched {
					included = true
					break
				}
			}
			if !included {
				return nil
			}
		}

		// Skip large files (> 1MB)
		info, err := d.Info()
		if err != nil {
			return nil
		}
		if info.Size() > 1<<20 {
			return nil
		}

		// Read and scan file
		content, err := os.ReadFile(path)
		if err != nil {
			return nil
		}

		// Skip binary files
		if isBinaryContent(content) {
			return nil
		}

		fileFindings, err := engine.ScanFile(ctx, relPath, content)
		if err != nil {
			return nil
		}

		findings = append(findings, fileFindings...)
		filesScanned++

		return nil
	})

	return findings, filesScanned, err
}

// scanSecretsFile scans a single file for secrets.
func (c *InProcess) scanSecretsFile(ctx context.Context, engine *secrets.Engine, path string) ([]secrets.Finding, int, error) {
	content, err := os.ReadFile(path)
	if err != nil {
		return nil, 0, fmt.Errorf("reading file: %w", err)
	}

	findings, err := engine.ScanFile(ctx, path, content)
	if err != nil {
		return nil, 0, fmt.Errorf("scanning file: %w", err)
	}

	return findings, 1, nil
}

// isBinaryContent checks if content appears to be binary.
func isBinaryContent(content []byte) bool {
	if len(content) == 0 {
		return false
	}
	checkLen := min(512, len(content))
	for i := 0; i < checkLen; i++ {
		if content[i] == 0 {
			return true
		}
	}
	return false
}

// StreamScanSecrets performs secret detection with streaming progress updates.
// For in-process mode, we simulate streaming by running a regular scan and
// emitting progress events.
func (c *InProcess) StreamScanSecrets(ctx context.Context, req *connect.Request[secretsv1.StreamScanRequest]) (Stream[secretsv1.ScanProgress], error) {
	// Create a channel-based stream for in-process mode
	stream := &inProcessSecretsStream{
		progress: make(chan *secretsv1.ScanProgress, 10),
		done:     make(chan struct{}),
	}

	// Run scan in background, sending progress to channel
	go func() {
		defer close(stream.progress)
		defer close(stream.done)

		// Send initializing phase
		stream.progress <- &secretsv1.ScanProgress{
			Phase:   secretsv1.ScanPhase_SCAN_PHASE_INITIALIZING,
			Message: "Initializing secrets scan...",
		}

		// Convert StreamScanRequest to ScanRequest
		scanReq := connect.NewRequest(&secretsv1.ScanRequest{
			Target:  req.Msg.Target,
			Options: req.Msg.Options,
		})

		// Send scanning phase
		stream.progress <- &secretsv1.ScanProgress{
			Phase:   secretsv1.ScanPhase_SCAN_PHASE_SCANNING,
			Message: "Scanning for secrets...",
		}

		// Perform the scan using our in-process method
		resp, err := c.ScanSecrets(ctx, scanReq)
		if err != nil {
			stream.progress <- &secretsv1.ScanProgress{
				Phase:   secretsv1.ScanPhase_SCAN_PHASE_FAILED,
				Message: fmt.Sprintf("Scan failed: %v", err),
				Error:   err.Error(),
			}
			return
		}

		// Send complete phase with result
		stream.progress <- &secretsv1.ScanProgress{
			Phase:        secretsv1.ScanPhase_SCAN_PHASE_COMPLETE,
			Message:      "Secrets scan completed",
			SecretsFound: resp.Msg.Stats.GetTotal(),
			Result:       resp.Msg,
		}
	}()

	return stream, nil
}

// ScanSecretsHistory scans git history for secrets.
func (c *InProcess) ScanSecretsHistory(ctx context.Context, req *connect.Request[secretsv1.ScanHistoryRequest]) (*connect.Response[secretsv1.ScanHistoryResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Use the existing git history scanning from internal/secrets
	historyFindings, err := secrets.ScanGitHistory(ctx, target, secrets.GitHistoryOptions{
		MaxCommits:     int(req.Msg.MaxCommits),
		Since:          req.Msg.Since,
		Until:          req.Msg.Until,
		Branch:         req.Msg.Branch,
		IncludeRemoved: req.Msg.IncludeRemoved,
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets history scan failed: %w", err))
	}

	// Convert findings
	var findings []secrets.Finding
	for _, hf := range historyFindings {
		findings = append(findings, hf.Finding)
	}

	response := &secretsv1.ScanHistoryResponse{
		Target: &targetv1.Target{
			Kind:        targetv1.TargetKind_TARGET_KIND_GIT,
			DisplayPath: target,
		},
		GeneratedAt:    timestamppb.Now(),
		Findings:       historyFindingsToProto(historyFindings),
		CommitsScanned: int32(len(historyFindings)),
		Stats:          internalproto.SecretsStatsToProto(findings),
	}

	return connect.NewResponse(response), nil
}

// historyFindingsToProto converts history findings to proto with git context.
func historyFindingsToProto(findings []secrets.HistoryFinding) []*secretsv1.Finding {
	if len(findings) == 0 {
		return nil
	}

	out := make([]*secretsv1.Finding, len(findings))
	for i, hf := range findings {
		pf := internalproto.SecretsFindingToProto(hf.Finding)

		// Add git context
		if pf.Location == nil {
			pf.Location = &secretsv1.Location{}
		}
		pf.Location.Source = secretsv1.SecretSource_SECRET_SOURCE_GIT_COMMIT
		pf.Location.GitContext = &secretsv1.GitContext{
			CommitHash:    hf.CommitHash,
			Author:        hf.Author,
			AuthorEmail:   hf.AuthorEmail,
			CommitDate:    hf.CommitDate,
			CommitMessage: hf.CommitMessage,
			RemovedIn:     hf.RemovedIn,
			StillPresent:  hf.StillPresent,
		}

		out[i] = pf
	}
	return out
}

// ScanSecretsDiff scans changes between two git refs for secrets.
func (c *InProcess) ScanSecretsDiff(ctx context.Context, req *connect.Request[secretsv1.ScanDiffRequest]) (*connect.Response[secretsv1.ScanDiffResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	baseRef := req.Msg.BaseRef
	targetRef := req.Msg.TargetRef

	// Use the existing diff scanning from internal/secrets
	diffResult, err := secrets.ScanGitDiff(ctx, target, baseRef, targetRef)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets diff scan failed: %w", err))
	}

	response := &secretsv1.ScanDiffResponse{
		Target: &targetv1.Target{
			Kind:        targetv1.TargetKind_TARGET_KIND_GIT,
			DisplayPath: target,
		},
		GeneratedAt:     timestamppb.Now(),
		BaseRef:         baseRef,
		TargetRef:       targetRef,
		AddedFindings:   internalproto.SecretsFindingsToProto(diffResult.Added),
		RemovedFindings: internalproto.SecretsFindingsToProto(diffResult.Removed),
		Stats:           internalproto.SecretsStatsToProto(diffResult.Added),
	}

	return connect.NewResponse(response), nil
}

// VerifySecrets attempts to validate detected secrets.
func (c *InProcess) VerifySecrets(ctx context.Context, req *connect.Request[secretsv1.VerifyRequest]) (*connect.Response[secretsv1.VerifyResponse], error) {
	findings := internalproto.SecretsFindingsFromProto(req.Msg.Findings)

	// Verify findings
	verifiedFindings, err := secrets.VerifyFindings(ctx, findings, secrets.VerifyOptions{
		RateLimit: int(req.Msg.RateLimit),
		Timeout:   0, // Use default
	})
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("secrets verify failed: %w", err))
	}

	// Count results
	var verifiedCount, skippedCount int32
	for _, f := range verifiedFindings {
		if f.Validated {
			verifiedCount++
		} else {
			skippedCount++
		}
	}

	response := &secretsv1.VerifyResponse{
		Results:       internalproto.SecretsFindingsToProto(verifiedFindings),
		VerifiedCount: verifiedCount,
		SkippedCount:  skippedCount,
	}

	return connect.NewResponse(response), nil
}

// ListDetectors returns available secret detectors.
func (c *InProcess) ListDetectors(ctx context.Context, req *connect.Request[secretsv1.ListDetectorsRequest]) (*connect.Response[secretsv1.ListDetectorsResponse], error) {
	// Return a static list of built-in detectors
	detectors := []*secretsv1.DetectorInfo{
		{Id: "aws", Name: "AWS Credentials", Description: "Detects AWS access keys and secret keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "github", Name: "GitHub Tokens", Description: "Detects GitHub personal access tokens", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "gcp", Name: "GCP Credentials", Description: "Detects GCP API keys and service account keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "slack", Name: "Slack Tokens", Description: "Detects Slack tokens and webhooks", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "stripe", Name: "Stripe Keys", Description: "Detects Stripe API keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "openai", Name: "OpenAI Keys", Description: "Detects OpenAI API keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "anthropic", Name: "Anthropic Keys", Description: "Detects Anthropic API keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "private_key", Name: "Private Keys", Description: "Detects RSA, DSA, EC, and other private keys", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "jwt", Name: "JSON Web Tokens", Description: "Detects JWT tokens", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
		{Id: "generic", Name: "Generic API Keys", Description: "Detects generic API key patterns", Source: secretsv1.DetectorSource_DETECTOR_SOURCE_BUILTIN, Enabled: true},
	}

	return connect.NewResponse(&secretsv1.ListDetectorsResponse{
		Detectors: detectors,
	}), nil
}

// inProcessSecretsStream implements Stream[secretsv1.ScanProgress] for in-process mode.
type inProcessSecretsStream struct {
	progress chan *secretsv1.ScanProgress
	done     chan struct{}
}

// Receive returns the next progress message.
func (s *inProcessSecretsStream) Receive() (*secretsv1.ScanProgress, error) {
	select {
	case msg, ok := <-s.progress:
		if !ok {
			return nil, io.EOF
		}
		return msg, nil
	case <-s.done:
		return nil, io.EOF
	}
}

// Close closes the stream.
func (s *inProcessSecretsStream) Close() error {
	return nil
}

// ============================================================================
// Diff Service Implementation
// ============================================================================

// DiffPackages compares dependencies between two targets.
func (c *InProcess) DiffPackages(ctx context.Context, req *connect.Request[diffv1.DiffPackagesRequest]) (*connect.Response[diffv1.DiffPackagesResponse], error) {
	baseTarget := req.Msg.BaseTarget
	targetTarget := req.Msg.TargetTarget

	if baseTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_target is required"))
	}
	if targetTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_target is required"))
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory from base target
	baseExec, err := c.collectInventoryForDiff(ctx, baseTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect base inventory: %w", err))
	}
	if baseExec != nil {
		defer baseExec.Close()
	}

	// Collect inventory from target target
	targetExec, err := c.collectInventoryForDiff(ctx, targetTarget, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect target inventory: %w", err))
	}
	if targetExec != nil {
		defer targetExec.Close()
	}

	// Compare packages
	changes := compare.ComparePackages(
		baseExec.Result.Packages,
		targetExec.Result.Packages,
		baseExec.Result.Direct,
		nil, // pkgDirect
		nil, // workspace
	)

	// Build response
	response := &diffv1.DiffPackagesResponse{
		BaseTarget: &targetv1.Target{
			Kind:        baseExec.Result.Target.Kind,
			DisplayPath: baseExec.Result.Target.DisplayPath,
		},
		TargetTarget: &targetv1.Target{
			Kind:        targetExec.Result.Target.Kind,
			DisplayPath: targetExec.Result.Target.DisplayPath,
		},
		GeneratedAt: timestamppb.Now(),
		Changes:     internalproto.PackageChangesToProto(changes),
		Stats:       internalproto.DiffStatsToProto(changes),
	}

	return connect.NewResponse(response), nil
}

// collectInventoryForDiff collects inventory from a target for diff purposes.
func (c *InProcess) collectInventoryForDiff(ctx context.Context, target string, opts inventory.Options) (*inventory.Execution, error) {
	kind := targets.DetectKind(target)

	switch kind {
	case targets.KindContainerImage:
		targetOpts := map[string]string{}
		if opts.Platform != "" {
			targetOpts["platform"] = opts.Platform
		}
		return inventory.CollectContainerImage(ctx, target, targetOpts, opts)

	case targets.KindDir:
		return inventory.CollectDirectory(ctx, target, opts)

	case targets.KindGit:
		return inventory.CollectRepository(ctx, target, "HEAD", false, opts)

	default:
		return inventory.CollectRepository(ctx, target, "HEAD", false, opts)
	}
}

// DiffVulnerabilities compares vulnerabilities between two targets.
func (c *InProcess) DiffVulnerabilities(ctx context.Context, req *connect.Request[diffv1.DiffVulnerabilitiesRequest]) (*connect.Response[diffv1.DiffVulnerabilitiesResponse], error) {
	baseTarget := req.Msg.BaseTarget
	targetTarget := req.Msg.TargetTarget

	if baseTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_target is required"))
	}
	if targetTarget == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_target is required"))
	}

	// Convert proto options to internal options
	opts := internalproto.ScanOptionsFromProto(req.Msg.ScanOptions)

	// Scan base target
	baseExec, err := c.routeScan(ctx, baseTarget, "", false, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan base target: %w", err))
	}
	if baseExec != nil {
		defer baseExec.Close()
	}

	// Scan target target
	targetExec, err := c.routeScan(ctx, targetTarget, "", false, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to scan target: %w", err))
	}
	if targetExec != nil {
		defer targetExec.Close()
	}

	// Build sets of vulnerability IDs for comparison
	baseVulns := make(map[string]bool)
	for _, f := range baseExec.Result.Findings {
		baseVulns[f.AdvisoryID] = true
	}

	targetVulns := make(map[string]bool)
	for _, f := range targetExec.Result.Findings {
		targetVulns[f.AdvisoryID] = true
	}

	// Merge advisories from both scans into proto format
	advisories := internalproto.AdvisoriesToProto(baseExec.Result.Advisories)
	for id, adv := range internalproto.AdvisoriesToProto(targetExec.Result.Advisories) {
		advisories[id] = adv
	}

	// Find added vulnerabilities (in target but not in base)
	var addedFindings []*vulnerabilityv1.Finding
	for _, f := range targetExec.Result.Findings {
		if !baseVulns[f.AdvisoryID] {
			adv := targetExec.Result.Advisories[f.AdvisoryID]
			addedFindings = append(addedFindings, internalproto.FindingToProto(f, internalproto.AdvisoriesToProto(map[string]vulnerabilityv1.Advisory{f.AdvisoryID: adv})[f.AdvisoryID]))
		}
	}

	// Find removed vulnerabilities (in base but not in target)
	var removedFindings []*vulnerabilityv1.Finding
	for _, f := range baseExec.Result.Findings {
		if !targetVulns[f.AdvisoryID] {
			adv := baseExec.Result.Advisories[f.AdvisoryID]
			removedFindings = append(removedFindings, internalproto.FindingToProto(f, internalproto.AdvisoriesToProto(map[string]vulnerabilityv1.Advisory{f.AdvisoryID: adv})[f.AdvisoryID]))
		}
	}

	// Build stats
	addedBySeverity := make(map[string]int32)
	removedBySeverity := make(map[string]int32)
	for _, f := range addedFindings {
		if adv, ok := advisories[f.AdvisoryId]; ok && adv.Severity != nil {
			addedBySeverity[adv.Severity.Level.String()]++
		}
	}
	for _, f := range removedFindings {
		if adv, ok := advisories[f.AdvisoryId]; ok && adv.Severity != nil {
			removedBySeverity[adv.Severity.Level.String()]++
		}
	}

	response := &diffv1.DiffVulnerabilitiesResponse{
		BaseTarget: &targetv1.Target{
			Kind:        baseExec.Result.Target.Kind,
			DisplayPath: baseExec.Result.Target.DisplayPath,
		},
		TargetTarget: &targetv1.Target{
			Kind:        targetExec.Result.Target.Kind,
			DisplayPath: targetExec.Result.Target.DisplayPath,
		},
		GeneratedAt:           timestamppb.Now(),
		AddedVulnerabilities:  addedFindings,
		RemovedVulnerabilities: removedFindings,
		Advisories:            advisories,
		Stats: &diffv1.VulnerabilityDiffStats{
			AddedCount:        int32(len(addedFindings)),
			RemovedCount:      int32(len(removedFindings)),
			AddedBySeverity:   addedBySeverity,
			RemovedBySeverity: removedBySeverity,
		},
	}

	return connect.NewResponse(response), nil
}

// ============================================================================
// Graph Service Implementation
// ============================================================================

// BuildGraph constructs a dependency graph for a target.
func (c *InProcess) BuildGraph(ctx context.Context, req *connect.Request[graphv1.BuildGraphRequest]) (*connect.Response[graphv1.BuildGraphResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := c.collectInventoryForDiff(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)

	// TODO: If options specify use_proxy or use_git, resolve edges
	// This would involve calling edge resolvers for each ecosystem

	// Update depths based on edges
	g.UpdateDepths()

	// Convert to proto
	nodes, edges, roots := internalproto.GraphToProto(g)

	response := &graphv1.BuildGraphResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		GeneratedAt: timestamppb.Now(),
		Nodes:       nodes,
		Edges:       edges,
		Roots:       roots,
		Stats:       internalproto.GraphStatsToProto(g.Stats()),
	}

	return connect.NewResponse(response), nil
}

// WhyDependency finds paths explaining why a dependency exists.
func (c *InProcess) WhyDependency(ctx context.Context, req *connect.Request[graphv1.WhyDependencyRequest]) (*connect.Response[graphv1.WhyDependencyResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	dependency := req.Msg.Dependency
	if dependency == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("dependency is required"))
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := c.collectInventoryForDiff(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()

	// Find the dependency node by PURL or name match
	var targetPURL string
	for n := range g.Nodes() {
		if n.PURL == dependency || n.Name == dependency || strings.Contains(n.Name, dependency) {
			targetPURL = n.PURL
			break
		}
	}

	response := &graphv1.WhyDependencyResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		Dependency: dependency,
		Found:      targetPURL != "",
	}

	if targetPURL != "" {
		// Find paths to the dependency
		paths := g.PathsTo(targetPURL)
		response.Paths = internalproto.PathsToProto(paths)
		response.Dependency = targetPURL
	}

	return connect.NewResponse(response), nil
}

// QueryGraph returns a filtered subset of a dependency graph.
func (c *InProcess) QueryGraph(ctx context.Context, req *connect.Request[graphv1.QueryGraphRequest]) (*connect.Response[graphv1.QueryGraphResponse], error) {
	target := req.Msg.Target
	if target == "" {
		target = "."
	}

	// Build inventory options
	opts := inventory.Options{}
	if req.Msg.Options != nil {
		opts.Ecosystems = req.Msg.Options.Ecosystems
		opts.Platform = req.Msg.Options.Platform
	}

	// Collect inventory
	exec, err := c.collectInventoryForDiff(ctx, target, opts)
	if err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("failed to collect inventory: %w", err))
	}
	if exec != nil {
		defer exec.Close()
	}

	// Build graph from inventory
	g := graph.FromInventory(exec.Result.Packages, exec.Result.Direct)
	g.UpdateDepths()

	// Apply filters if specified
	if req.Msg.Filter != nil {
		filter := req.Msg.Filter

		// Filter by subgraph root
		if filter.RootPurl != "" {
			g = g.Subgraph(filter.RootPurl)
		}

		// Filter by predicate
		g = g.Filter(func(n *graph.Node) bool {
			// Ecosystem filter
			if len(filter.Ecosystems) > 0 {
				found := false
				for _, eco := range filter.Ecosystems {
					if strings.EqualFold(n.Ecosystem, eco) {
						found = true
						break
					}
				}
				if !found {
					return false
				}
			}

			// Depth filters
			if filter.MinDepth > 0 && n.Depth < int(filter.MinDepth) {
				return false
			}
			if filter.MaxDepth > 0 && n.Depth > int(filter.MaxDepth) {
				return false
			}

			// Direct/transitive filters
			if filter.OnlyDirect && !n.Direct {
				return false
			}
			if filter.OnlyTransitive && n.Direct {
				return false
			}

			// Vulnerable filter
			if filter.OnlyVulnerable && n.VulnCount.Total == 0 {
				return false
			}

			// Name pattern filter
			if filter.NamePattern != "" {
				matched, _ := filepath.Match(filter.NamePattern, n.Name)
				if !matched {
					return false
				}
			}

			return true
		})
	}

	// Convert to proto
	nodes, edges, _ := internalproto.GraphToProto(g)

	response := &graphv1.QueryGraphResponse{
		Target: &targetv1.Target{
			Kind:        exec.Result.Target.Kind,
			DisplayPath: exec.Result.Target.DisplayPath,
		},
		Nodes: nodes,
		Edges: edges,
		Stats: internalproto.GraphStatsToProto(g.Stats()),
	}

	return connect.NewResponse(response), nil
}

// DiffContainerImages performs a comprehensive diff between two container images.
func (c *InProcess) DiffContainerImages(ctx context.Context, req *connect.Request[diffv1.DiffContainerImagesRequest]) (*connect.Response[diffv1.DiffContainerImagesResponse], error) {
	baseImage := req.Msg.BaseImage
	targetImage := req.Msg.TargetImage

	if baseImage == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("base_image is required"))
	}
	if targetImage == "" {
		return nil, connect.NewError(connect.CodeInvalidArgument, fmt.Errorf("target_image is required"))
	}

	opts := req.Msg.Options
	if opts == nil {
		opts = &diffv1.ContainerDiffOptions{}
	}

	// Normalize image references based on transport
	baseRef := normalizeContainerRef(baseImage, opts.ImageTransport)
	targetRef := normalizeContainerRef(targetImage, opts.ImageTransport)

	// Build scan options from proto options
	scanOpts := scan.Options{}
	if opts.ScanOptions != nil {
		scanOpts = internalproto.ScanOptionsFromProto(opts.ScanOptions)
	}

	// Scan both images in parallel
	type scanResult struct {
		exec *scan.Execution
		err  error
	}

	baseCh := make(chan scanResult, 1)
	targetCh := make(chan scanResult, 1)

	go func() {
		exec, err := c.scanner.ScanContainerImage(ctx, baseRef, nil, scanOpts)
		baseCh <- scanResult{exec: exec, err: err}
	}()

	go func() {
		exec, err := c.scanner.ScanContainerImage(ctx, targetRef, nil, scanOpts)
		targetCh <- scanResult{exec: exec, err: err}
	}()

	// Wait for both scans
	baseRes := <-baseCh
	targetRes := <-targetCh

	if baseRes.err != nil {
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan base image %q: %w", baseRef, baseRes.err))
	}
	if targetRes.err != nil {
		if baseRes.exec != nil {
			baseRes.exec.Close()
		}
		return nil, connect.NewError(connect.CodeInternal, fmt.Errorf("scan target image %q: %w", targetRef, targetRes.err))
	}

	defer baseRes.exec.Close()
	defer targetRes.exec.Close()

	// Build the response
	response := buildContainerDiffResponse(&baseRes.exec.Result, &targetRes.exec.Result)

	return connect.NewResponse(response), nil
}

// normalizeContainerRef ensures the image reference has the appropriate scheme.
func normalizeContainerRef(ref, transport string) string {
	ref = strings.TrimSpace(ref)
	if ref == "" {
		return ref
	}
	// Already has a scheme - respect it
	if strings.Contains(ref, "://") {
		return ref
	}
	// Add appropriate prefix based on transport
	switch strings.ToLower(transport) {
	case "daemon", "docker-daemon":
		return "docker-daemon://" + ref
	default:
		return "oci://" + ref
	}
}

// buildContainerDiffResponse constructs the proto response from scan results.
func buildContainerDiffResponse(baseResult, targetResult *scan.Result) *diffv1.DiffContainerImagesResponse {
	now := timestamppb.Now()

	response := &diffv1.DiffContainerImagesResponse{
		BaseImage:     extractContainerImageRef(baseResult),
		TargetImage:   extractContainerImageRef(targetResult),
		GeneratedAt:   now,
		BaseContext:   extractContainerContext(baseResult),
		TargetContext: extractContainerContext(targetResult),
	}

	// Compare packages
	response.PackageChanges = compareContainerPackages(baseResult, targetResult)

	// Compare vulnerabilities
	response.VulnerabilityChanges, response.Advisories = compareContainerVulnerabilities(baseResult, targetResult)

	// Compare configuration
	if baseResult != nil && targetResult != nil &&
		baseResult.ImageInfo != nil && targetResult.ImageInfo != nil {
		response.ConfigChanges = compareContainerConfigs(baseResult.ImageInfo, targetResult.ImageInfo)
		response.LayerAnalysis = compareContainerLayers(baseResult.ImageInfo, targetResult.ImageInfo)
	}

	// Calculate summary
	response.Summary = calculateContainerDiffSummary(response)

	return response
}

func extractContainerImageRef(result *scan.Result) *diffv1.ContainerImageRef {
	if result == nil {
		return &diffv1.ContainerImageRef{}
	}
	ref := &diffv1.ContainerImageRef{
		Reference: result.Target.DisplayPath,
	}
	if result.Target.Provenance != nil {
		ref.Registry = result.Target.Provenance["registry"]
		ref.Repository = result.Target.Provenance["repository"]
		ref.Tag = result.Target.Provenance["tag"]
		ref.Digest = result.Target.Provenance["digest"]
	}
	return ref
}

func extractContainerContext(result *scan.Result) *diffv1.ContainerImageContext {
	if result == nil {
		return &diffv1.ContainerImageContext{}
	}

	ctx := &diffv1.ContainerImageContext{
		PackageCount: int32(len(result.Inventory.Packages)),
	}

	// Extract distro from packages
	ctx.Distro = extractDistroFromResult(result)

	// Extract metadata from ImageInfo
	if result.ImageInfo != nil {
		ctx.Size = result.ImageInfo.Metadata.Size
		ctx.Architecture = result.ImageInfo.Metadata.Architecture
	}

	return ctx
}

func extractDistroFromResult(result *scan.Result) string {
	if result == nil || len(result.Inventory.Packages) == 0 {
		return ""
	}

	// Count ecosystems to find the most common one
	ecosystemCounts := make(map[string]int)
	for _, pkg := range result.Inventory.Packages {
		eco := pkg.Ecosystem()
		if eco == "" {
			continue
		}
		if strings.Contains(eco, ":") {
			ecosystemCounts[eco]++
		}
	}

	if len(ecosystemCounts) == 0 {
		return ""
	}

	var mostCommon string
	var maxCount int
	for eco, count := range ecosystemCounts {
		if count > maxCount {
			maxCount = count
			mostCommon = eco
		}
	}

	// Format nicely: "Debian:11" -> "Debian 11"
	if mostCommon != "" {
		parts := strings.SplitN(mostCommon, ":", 2)
		if len(parts) == 2 {
			return parts[0] + " " + parts[1]
		}
		return mostCommon
	}
	return ""
}

func compareContainerPackages(baseResult, targetResult *scan.Result) []*diffv1.ContainerPackageChange {
	if baseResult == nil || targetResult == nil {
		return nil
	}

	// Use existing ComparePackages logic
	baseChanges := compare.ComparePackages(
		baseResult.Inventory.Packages,
		targetResult.Inventory.Packages,
		nil, nil, nil,
	)

	// Build layer lookup maps
	baseLayerMap := buildPackageLayerMapForProto(baseResult)
	targetLayerMap := buildPackageLayerMapForProto(targetResult)

	// Convert to proto
	changes := make([]*diffv1.ContainerPackageChange, 0, len(baseChanges))
	for _, c := range baseChanges {
		change := &diffv1.ContainerPackageChange{
			Name:               c.Name,
			Ecosystem:          c.Ecosystem,
			ChangeKind:         convertChangeKind(c.ChangeType),
			BaseVersion:        c.BaseVersion,
			TargetVersion:      c.TargetVersion,
			OldName:            c.OldName,
			IsDirect:           c.IsDirect,
			BaseLayerDetails:   baseLayerMap[c.Name],
			TargetLayerDetails: targetLayerMap[c.Name],
		}
		// For removed packages, use old name if different
		if c.ChangeType == compare.Removed && c.OldName != "" {
			change.BaseLayerDetails = baseLayerMap[c.OldName]
		}
		changes = append(changes, change)
	}

	return changes
}

func convertChangeKind(ct compare.ChangeType) diffv1.ChangeKind {
	switch ct {
	case compare.Added:
		return diffv1.ChangeKind_CHANGE_KIND_ADDED
	case compare.Removed:
		return diffv1.ChangeKind_CHANGE_KIND_REMOVED
	case compare.Upgraded:
		return diffv1.ChangeKind_CHANGE_KIND_UPGRADED
	case compare.Downgraded:
		return diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED
	case compare.Updated:
		return diffv1.ChangeKind_CHANGE_KIND_UPDATED
	default:
		return diffv1.ChangeKind_CHANGE_KIND_UNSPECIFIED
	}
}

func buildPackageLayerMapForProto(result *scan.Result) map[string]*containerv1.LayerDetails {
	layerMap := make(map[string]*containerv1.LayerDetails)

	for _, finding := range result.Findings {
		if finding.LayerDetails == nil {
			continue
		}
		layerMap[finding.Dependency.Name] = &containerv1.LayerDetails{
			Index:       finding.LayerDetails.Index,
			DiffId:      finding.LayerDetails.DiffId,
			ChainId:     finding.LayerDetails.ChainId,
			Command:     finding.LayerDetails.Command,
			InBaseImage: finding.LayerDetails.InBaseImage,
		}
	}

	return layerMap
}

func compareContainerVulnerabilities(baseResult, targetResult *scan.Result) ([]*diffv1.ContainerVulnerabilityChange, map[string]*vulnerabilityv1.Advisory) {
	if baseResult == nil || targetResult == nil {
		return nil, nil
	}

	// Build map of findings by advisory ID
	baseFindings := make(map[string]vulnerability.Finding)
	targetFindings := make(map[string]vulnerability.Finding)

	for _, f := range baseResult.Findings {
		baseFindings[f.AdvisoryID] = f
	}
	for _, f := range targetResult.Findings {
		targetFindings[f.AdvisoryID] = f
	}

	var changes []*diffv1.ContainerVulnerabilityChange
	advisories := make(map[string]*vulnerabilityv1.Advisory)

	// Find removed/fixed vulnerabilities
	for advisoryID, baseFinding := range baseFindings {
		baseAdvisory := baseResult.Advisories[advisoryID]
		_, exists := targetFindings[advisoryID]
		if !exists {
			changeKind := diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED
			// Check if it was fixed by an upgrade
			if wasVulnFixedByUpgrade(baseFinding, targetResult) {
				changeKind = diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED
			}
			change := buildVulnChangeProto(advisoryID, changeKind, baseAdvisory,
				baseFinding.Dependency.Name, baseFinding.Dependency.Ecosystem,
				baseFinding.Version, "",
				baseFinding.LayerDetails, nil)
			changes = append(changes, change)
			advCopy := baseAdvisory
			advisories[advisoryID] = &advCopy
		} else {
			// Vulnerability persists
			targetFinding := targetFindings[advisoryID]
			targetAdvisory := targetResult.Advisories[advisoryID]
			change := buildVulnChangeProto(advisoryID, diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_PERSISTED, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				baseFinding.Version, targetFinding.Version,
				baseFinding.LayerDetails, targetFinding.LayerDetails)
			changes = append(changes, change)
			advCopy := targetAdvisory
			advisories[advisoryID] = &advCopy
		}
	}

	// Find added vulnerabilities
	for advisoryID, targetFinding := range targetFindings {
		if _, exists := baseFindings[advisoryID]; !exists {
			targetAdvisory := targetResult.Advisories[advisoryID]
			change := buildVulnChangeProto(advisoryID, diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED, targetAdvisory,
				targetFinding.Dependency.Name, targetFinding.Dependency.Ecosystem,
				"", targetFinding.Version,
				nil, targetFinding.LayerDetails)
			changes = append(changes, change)
			advCopy := targetAdvisory
			advisories[advisoryID] = &advCopy
		}
	}

	return changes, advisories
}

func wasVulnFixedByUpgrade(finding vulnerability.Finding, targetResult *scan.Result) bool {
	pkgName := finding.Dependency.Name
	baseVersion := finding.Version

	for _, pkg := range targetResult.Inventory.Packages {
		if pkg.Name == pkgName {
			if pkg.Version != baseVersion {
				return true
			}
			return false
		}
	}
	return false
}

func buildVulnChangeProto(
	advisoryID string,
	changeKind diffv1.VulnerabilityChangeKind,
	advisory vulnerabilityv1.Advisory,
	pkgName, ecosystem, baseVersion, targetVersion string,
	baseLayerDetails, targetLayerDetails *containerv1.LayerDetails,
) *diffv1.ContainerVulnerabilityChange {
	var sevLevel, sevType string
	if advisory.Severity != nil {
		sevLevel = advisory.Severity.Level.String()
		sevType = advisory.Severity.Type.String()
	}

	change := &diffv1.ContainerVulnerabilityChange{
		Id:            advisoryID,
		ChangeKind:    changeKind,
		Severity:      sevLevel,
		SeverityType:  sevType,
		PackageName:   pkgName,
		Ecosystem:     ecosystem,
		BaseVersion:   baseVersion,
		TargetVersion: targetVersion,
		FixedVersions: advisory.FixedVersions,
		Summary:       advisory.Summary,
		Aliases:       advisory.Aliases,
	}

	// Format published date if available
	if pub := vulnerability.AdvisoryPublished(&advisory); !pub.IsZero() {
		change.Published = pub.Format("2006-01-02")
	}

	// Copy layer details
	if baseLayerDetails != nil {
		change.BaseLayerDetails = &containerv1.LayerDetails{
			Index:       baseLayerDetails.Index,
			DiffId:      baseLayerDetails.DiffId,
			ChainId:     baseLayerDetails.ChainId,
			Command:     baseLayerDetails.Command,
			InBaseImage: baseLayerDetails.InBaseImage,
		}
	}
	if targetLayerDetails != nil {
		change.TargetLayerDetails = &containerv1.LayerDetails{
			Index:       targetLayerDetails.Index,
			DiffId:      targetLayerDetails.DiffId,
			ChainId:     targetLayerDetails.ChainId,
			Command:     targetLayerDetails.Command,
			InBaseImage: targetLayerDetails.InBaseImage,
		}
	}

	return change
}

func compareContainerConfigs(baseInfo, targetInfo *image.Info) *diffv1.ContainerConfigDiff {
	if baseInfo == nil || targetInfo == nil {
		return nil
	}

	diff := &diffv1.ContainerConfigDiff{}

	// User comparison
	if baseInfo.Config.User != targetInfo.Config.User {
		diff.UserChanged = true
		diff.BaseUser = baseInfo.Config.User
		diff.TargetUser = targetInfo.Config.User
	}

	// Root user comparison
	baseIsRoot := baseInfo.Config.IsRootUser()
	targetIsRoot := targetInfo.Config.IsRootUser()
	if baseIsRoot != targetIsRoot {
		diff.RootChanged = true
		diff.BaseIsRoot = baseIsRoot
		diff.TargetIsRoot = targetIsRoot
	}

	// Ports comparison
	basePorts := make(map[string]bool)
	for _, p := range baseInfo.Config.ExposedPorts {
		basePorts[p] = true
	}
	targetPorts := make(map[string]bool)
	for _, p := range targetInfo.Config.ExposedPorts {
		targetPorts[p] = true
	}
	for p := range targetPorts {
		if !basePorts[p] {
			diff.PortsAdded = append(diff.PortsAdded, p)
		}
	}
	for p := range basePorts {
		if !targetPorts[p] {
			diff.PortsRemoved = append(diff.PortsRemoved, p)
		}
	}
	diff.PortsChanged = len(diff.PortsAdded) > 0 || len(diff.PortsRemoved) > 0

	// Volumes comparison
	baseVols := make(map[string]bool)
	for _, v := range baseInfo.Config.Volumes {
		baseVols[v] = true
	}
	targetVols := make(map[string]bool)
	for _, v := range targetInfo.Config.Volumes {
		targetVols[v] = true
	}
	for v := range targetVols {
		if !baseVols[v] {
			diff.VolumesAdded = append(diff.VolumesAdded, v)
		}
	}
	for v := range baseVols {
		if !targetVols[v] {
			diff.VolumesRemoved = append(diff.VolumesRemoved, v)
		}
	}
	diff.VolumesChanged = len(diff.VolumesAdded) > 0 || len(diff.VolumesRemoved) > 0

	// Entrypoint comparison
	if !slicesEqual(baseInfo.Config.Entrypoint, targetInfo.Config.Entrypoint) {
		diff.EntrypointChanged = true
		diff.BaseEntrypoint = baseInfo.Config.Entrypoint
		diff.TargetEntrypoint = targetInfo.Config.Entrypoint
	}

	// Cmd comparison
	if !slicesEqual(baseInfo.Config.Cmd, targetInfo.Config.Cmd) {
		diff.CmdChanged = true
		diff.BaseCmd = baseInfo.Config.Cmd
		diff.TargetCmd = targetInfo.Config.Cmd
	}

	// Working dir comparison
	if baseInfo.Config.WorkingDir != targetInfo.Config.WorkingDir {
		diff.WorkingDirChanged = true
		diff.BaseWorkingDir = baseInfo.Config.WorkingDir
		diff.TargetWorkingDir = targetInfo.Config.WorkingDir
	}

	// Healthcheck comparison
	baseHasHealth := baseInfo.Config.Healthcheck != nil
	targetHasHealth := targetInfo.Config.Healthcheck != nil
	diff.HealthcheckChanged = baseHasHealth != targetHasHealth

	// Environment variable comparison
	diff.EnvChanges = compareEnvVars(baseInfo.Config.Env, targetInfo.Config.Env)

	// Label comparison
	diff.LabelChanges = compareLabels(baseInfo.Config.Labels, targetInfo.Config.Labels)

	return diff
}

func slicesEqual(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

func compareEnvVars(baseEnv, targetEnv []string) []*diffv1.EnvChange {
	baseMap := make(map[string]string)
	for _, e := range baseEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			baseMap[parts[0]] = parts[1]
		}
	}

	targetMap := make(map[string]string)
	for _, e := range targetEnv {
		parts := strings.SplitN(e, "=", 2)
		if len(parts) == 2 {
			targetMap[parts[0]] = parts[1]
		}
	}

	var changes []*diffv1.EnvChange

	// Find added and updated
	for name, targetVal := range targetMap {
		baseVal, exists := baseMap[name]
		if !exists {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_ADDED,
				TargetValue: targetVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		} else if baseVal != targetVal {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_UPDATED,
				BaseValue:   baseVal,
				TargetValue: targetVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		}
	}

	// Find removed
	for name, baseVal := range baseMap {
		if _, exists := targetMap[name]; !exists {
			changes = append(changes, &diffv1.EnvChange{
				Name:        name,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_REMOVED,
				BaseValue:   baseVal,
				IsSensitive: isSensitiveEnvVar(name),
			})
		}
	}

	return changes
}

func isSensitiveEnvVar(name string) bool {
	upper := strings.ToUpper(name)
	sensitivePatterns := []string{"PASSWORD", "SECRET", "TOKEN", "KEY", "CREDENTIAL", "API_KEY"}
	for _, p := range sensitivePatterns {
		if strings.Contains(upper, p) {
			return true
		}
	}
	return false
}

func compareLabels(baseLabels, targetLabels map[string]string) []*diffv1.LabelChange {
	var changes []*diffv1.LabelChange

	// Find added and updated
	for key, targetVal := range targetLabels {
		baseVal, exists := baseLabels[key]
		if !exists {
			changes = append(changes, &diffv1.LabelChange{
				Key:         key,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_ADDED,
				TargetValue: targetVal,
			})
		} else if baseVal != targetVal {
			changes = append(changes, &diffv1.LabelChange{
				Key:         key,
				ChangeKind:  diffv1.ChangeKind_CHANGE_KIND_UPDATED,
				BaseValue:   baseVal,
				TargetValue: targetVal,
			})
		}
	}

	// Find removed
	for key, baseVal := range baseLabels {
		if _, exists := targetLabels[key]; !exists {
			changes = append(changes, &diffv1.LabelChange{
				Key:        key,
				ChangeKind: diffv1.ChangeKind_CHANGE_KIND_REMOVED,
				BaseValue:  baseVal,
			})
		}
	}

	return changes
}

func compareContainerLayers(baseInfo, targetInfo *image.Info) *diffv1.LayerDiffAnalysis {
	if baseInfo == nil || targetInfo == nil {
		return nil
	}

	analysis := &diffv1.LayerDiffAnalysis{
		BaseLayerCount:   int32(baseInfo.Metadata.LayerCount),
		TargetLayerCount: int32(targetInfo.Metadata.LayerCount),
	}

	// Compare layers by history
	baseLen := len(baseInfo.History)
	targetLen := len(targetInfo.History)
	maxLen := baseLen
	if targetLen > maxLen {
		maxLen = targetLen
	}

	for i := 0; i < maxLen; i++ {
		var change diffv1.LayerChange
		change.Index = int32(i)

		hasBase := i < baseLen
		hasTarget := i < targetLen

		if hasBase {
			change.BaseCommand = baseInfo.History[i].CreatedBy
		}
		if hasTarget {
			change.TargetCommand = targetInfo.History[i].CreatedBy
		}

		if hasBase && hasTarget {
			if baseInfo.History[i].CreatedBy == targetInfo.History[i].CreatedBy {
				change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED
				analysis.CommonLayers++
			} else {
				change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_MODIFIED
			}
		} else if hasTarget {
			change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED
		} else {
			change.ChangeKind = diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED
		}

		// Only include non-unchanged layers in the response
		if change.ChangeKind != diffv1.LayerChangeKind_LAYER_CHANGE_KIND_UNCHANGED {
			analysis.LayerChanges = append(analysis.LayerChanges, &change)
		}
	}

	return analysis
}

func calculateContainerDiffSummary(response *diffv1.DiffContainerImagesResponse) *diffv1.ContainerDiffSummary {
	summary := &diffv1.ContainerDiffSummary{}

	// Count package changes
	for _, c := range response.PackageChanges {
		switch c.ChangeKind {
		case diffv1.ChangeKind_CHANGE_KIND_ADDED:
			summary.PackagesAdded++
		case diffv1.ChangeKind_CHANGE_KIND_REMOVED:
			summary.PackagesRemoved++
		case diffv1.ChangeKind_CHANGE_KIND_UPGRADED:
			summary.PackagesUpgraded++
		case diffv1.ChangeKind_CHANGE_KIND_DOWNGRADED:
			summary.PackagesDowngraded++
		}
	}

	// Count vulnerability changes
	for _, v := range response.VulnerabilityChanges {
		switch v.ChangeKind {
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_ADDED:
			summary.VulnerabilitiesAdded++
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_REMOVED:
			summary.VulnerabilitiesRemoved++
		case diffv1.VulnerabilityChangeKind_VULNERABILITY_CHANGE_KIND_FIXED:
			summary.VulnerabilitiesFixed++
		}
	}

	// Count layer changes
	if response.LayerAnalysis != nil {
		for _, l := range response.LayerAnalysis.LayerChanges {
			switch l.ChangeKind {
			case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_ADDED:
				summary.LayersAdded++
			case diffv1.LayerChangeKind_LAYER_CHANGE_KIND_REMOVED:
				summary.LayersRemoved++
			}
		}
	}

	// Check for config changes
	if response.ConfigChanges != nil {
		cc := response.ConfigChanges
		summary.ConfigChanged = cc.UserChanged || cc.RootChanged || cc.PortsChanged ||
			cc.VolumesChanged || cc.EntrypointChanged || cc.CmdChanged ||
			cc.WorkingDirChanged || cc.HealthcheckChanged ||
			len(cc.EnvChanges) > 0 || len(cc.LabelChanges) > 0
	}

	return summary
}

