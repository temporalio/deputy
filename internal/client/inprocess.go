package client

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"connectrpc.com/connect"
	"google.golang.org/protobuf/types/known/timestamppb"

	dependencyv1 "github.com/picatz/deputy/gen/deputy/dependency/v1"
	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	sbomv1 "github.com/picatz/deputy/gen/deputy/sbom/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
	secretsv1 "github.com/picatz/deputy/gen/deputy/secrets/v1"
	targetv1 "github.com/picatz/deputy/gen/deputy/target/v1"
	"github.com/picatz/deputy/internal/ai"
	"github.com/picatz/deputy/internal/inventory"
	internalproto "github.com/picatz/deputy/internal/proto"
	"github.com/picatz/deputy/internal/scan"
	sbomx "github.com/picatz/deputy/internal/sbom"
	sbomdiff "github.com/picatz/deputy/internal/sbom/diff"
	"github.com/picatz/deputy/internal/secrets"
	"github.com/picatz/deputy/internal/targets"
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

