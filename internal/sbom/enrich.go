package sbomx

import (
	"context"
	"crypto/x509"
	"fmt"
	"regexp"
	"slices"
	"strings"
	"sync"

	pb "deps.dev/api/v3"
	"github.com/google/osv-scalibr/purl"
	"github.com/protobom/protobom/pkg/sbom"
	"github.com/temporalio/deputy/internal/mise"
	"github.com/temporalio/deputy/internal/purlx"
	"google.golang.org/grpc"
	"google.golang.org/grpc/credentials"
)

// EnrichOptions configures SBOM enrichment behavior.
type EnrichOptions struct {
	// AddHashes enables fetching and adding cryptographic checksums (SHA256).
	AddHashes bool
	// AddCPEs enables generating CPE identifiers for packages.
	AddCPEs bool
	// AddSuppliers enables fetching supplier/maintainer metadata.
	AddSuppliers bool
	// AddExternalRefs enables adding external references (VCS, homepage, etc.).
	AddExternalRefs bool
	// AddPublishedDate enables adding package publish dates.
	AddPublishedDate bool
	// AddDependencies enables fetching and adding dependency relationships between packages.
	// This creates "depends_on" edges between SBOM nodes based on deps.dev's dependency graph.
	AddDependencies bool
	// Concurrency limits parallel enrichment requests (default: 10).
	Concurrency int
}

// DefaultEnrichOptions returns enrichment options with all features enabled.
func DefaultEnrichOptions() EnrichOptions {
	return EnrichOptions{
		AddHashes:        true,
		AddCPEs:          true,
		AddSuppliers:     true,
		AddExternalRefs:  true,
		AddPublishedDate: true,
		AddDependencies:  false, // Off by default as it adds significant API calls
		Concurrency:      10,
	}
}

// EnrichResult captures enrichment statistics.
type EnrichResult struct {
	// NodesProcessed is the total number of nodes considered for enrichment.
	NodesProcessed int
	// NodesEnriched is the number of nodes that received new metadata.
	NodesEnriched int
	// HashesAdded is the number of hash entries added.
	HashesAdded int
	// CPEsAdded is the number of CPE identifiers generated.
	CPEsAdded int
	// SuppliersAdded is the number of supplier entries added.
	SuppliersAdded int
	// ExternalRefsAdded is the number of external references added.
	ExternalRefsAdded int
	// DependencyEdgesAdded is the number of depends_on edges added between packages.
	DependencyEdgesAdded int
	// Errors contains non-fatal errors encountered during enrichment.
	Errors []error
}

// Enrich enriches an SBOM document with additional metadata from deps.dev.
// It modifies the document in place and returns statistics about the enrichment.
func Enrich(ctx context.Context, doc *sbom.Document, opts EnrichOptions) (*EnrichResult, error) {
	if doc == nil || doc.NodeList == nil || len(doc.NodeList.Nodes) == 0 {
		return &EnrichResult{}, nil
	}

	if opts.Concurrency <= 0 {
		opts.Concurrency = 10
	}

	result := &EnrichResult{}

	// Connect to deps.dev
	certPool, err := x509.SystemCertPool()
	if err != nil {
		return nil, fmt.Errorf("deps.dev trust store: %w", err)
	}
	conn, err := grpc.NewClient("api.deps.dev:443", grpc.WithTransportCredentials(credentials.NewClientTLSFromCert(certPool, "")))
	if err != nil {
		return nil, fmt.Errorf("deps.dev dial: %w", err)
	}
	defer conn.Close()
	client := pb.NewInsightsClient(conn)

	// Collect nodes that can be enriched (have PURL)
	var enrichable []*sbom.Node
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}
		result.NodesProcessed++
		if pu := nodePackageURL(node); pu != nil {
			enrichable = append(enrichable, node)
		}
	}

	// Process nodes with concurrency limit
	sem := make(chan struct{}, opts.Concurrency)
	var wg sync.WaitGroup
	var mu sync.Mutex

	for _, node := range enrichable {
		wg.Add(1)
		go func(n *sbom.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			enriched, err := enrichNode(ctx, client, n, opts)
			mu.Lock()
			defer mu.Unlock()
			if err != nil {
				result.Errors = append(result.Errors, err)
				return
			}
			if enriched.HashesAdded > 0 || enriched.CPEsAdded > 0 ||
				enriched.SuppliersAdded > 0 || enriched.ExternalRefsAdded > 0 {
				result.NodesEnriched++
			}
			result.HashesAdded += enriched.HashesAdded
			result.CPEsAdded += enriched.CPEsAdded
			result.SuppliersAdded += enriched.SuppliersAdded
			result.ExternalRefsAdded += enriched.ExternalRefsAdded
		}(node)
	}
	wg.Wait()

	// Add CPEs for all nodes (doesn't require API calls)
	if opts.AddCPEs {
		for _, node := range doc.NodeList.Nodes {
			if node == nil {
				continue
			}
			if added := addCPEToNode(node); added {
				result.CPEsAdded++
			}
		}
	}

	// Enrich dependency relationships from deps.dev
	if opts.AddDependencies {
		edgesAdded, err := enrichDependencyEdges(ctx, client, doc, opts.Concurrency)
		if err != nil {
			result.Errors = append(result.Errors, fmt.Errorf("dependency enrichment: %w", err))
		}
		result.DependencyEdgesAdded = edgesAdded
	}

	return result, nil
}

// enrichNode enriches a single node with deps.dev metadata.
func enrichNode(ctx context.Context, client pb.InsightsClient, node *sbom.Node, opts EnrichOptions) (*EnrichResult, error) {
	result := &EnrichResult{}

	pu := nodePackageURL(node)
	if pu == nil {
		return result, nil
	}

	sys := systemFromPURL(pu)
	if sys == pb.System_SYSTEM_UNSPECIFIED {
		return result, nil
	}

	name := packageNameForSystem(pu, sys)
	version := normalizeVersionForSystem(sys, strings.TrimSpace(pu.Version))
	if name == "" || version == "" {
		return result, nil
	}

	// Fetch version info from deps.dev
	resp, err := client.GetVersion(ctx, &pb.GetVersionRequest{
		VersionKey: &pb.VersionKey{
			System:  sys,
			Name:    name,
			Version: version,
		},
	})
	if err != nil {
		return result, nil // Non-fatal: package may not exist in deps.dev
	}

	// Add external references (VCS, homepage, etc.)
	if opts.AddExternalRefs && len(resp.Links) > 0 {
		for _, link := range resp.Links {
			if link == nil || link.Url == "" {
				continue
			}
			refType := linkLabelToExternalRefType(link.Label)
			if refType == sbom.ExternalReference_UNKNOWN {
				continue
			}

			// Check if this reference already exists
			exists := false
			for _, existing := range node.ExternalReferences {
				if existing.Url == link.Url {
					exists = true
					break
				}
			}
			if !exists {
				node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
					Url:     link.Url,
					Type:    refType,
					Comment: link.Label,
				})
				result.ExternalRefsAdded++
			}
		}
	}

	// Add published date
	if opts.AddPublishedDate && resp.PublishedAt != nil && node.ReleaseDate == nil {
		node.ReleaseDate = resp.PublishedAt
	}

	// Add SLSA provenance as attestation reference
	if opts.AddExternalRefs && len(resp.SlsaProvenances) > 0 {
		for _, prov := range resp.SlsaProvenances {
			if prov == nil || prov.SourceRepository == "" {
				continue
			}
			// Add source repository as VCS reference
			exists := false
			for _, existing := range node.ExternalReferences {
				if existing.Url == prov.SourceRepository {
					exists = true
					break
				}
			}
			if !exists {
				node.ExternalReferences = append(node.ExternalReferences, &sbom.ExternalReference{
					Url:     prov.SourceRepository,
					Type:    sbom.ExternalReference_VCS,
					Comment: "SLSA provenance source",
				})
				result.ExternalRefsAdded++
			}
		}
	}

	// Try to get project info for supplier data
	if opts.AddSuppliers && len(resp.RelatedProjects) > 0 && len(node.Suppliers) == 0 {
		for _, proj := range resp.RelatedProjects {
			if proj == nil || proj.ProjectKey == nil {
				continue
			}
			// The project ID often contains the maintainer/org info
			// Format: github.com/owner/repo or gitlab.com/owner/repo
			projectID := proj.ProjectKey.Id
			if owner := extractOwnerFromProjectID(projectID); owner != "" {
				node.Suppliers = append(node.Suppliers, &sbom.Person{
					Name:  owner,
					IsOrg: true,
					Url:   "https://" + projectID,
				})
				result.SuppliersAdded++
				break // Only add first supplier
			}
		}
	}

	return result, nil
}

// addCPEToNode generates and adds a CPE identifier to a node if possible.
// Returns true if a CPE was added.
func addCPEToNode(node *sbom.Node) bool {
	if node == nil {
		return false
	}

	// Check if CPE already exists
	if node.Identifiers != nil {
		if _, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]; ok {
			return false
		}
	}

	pu := nodePackageURL(node)
	if pu == nil {
		return false
	}

	cpe := generateCPE(pu, node.Name, node.Version)
	if cpe == "" {
		return false
	}

	if node.Identifiers == nil {
		node.Identifiers = make(map[int32]string)
	}
	node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)] = cpe
	return true
}

// generateCPE creates a CPE 2.3 identifier from package information.
// Format: cpe:2.3:a:vendor:product:version:*:*:*:*:target_sw:*:*
func generateCPE(pu *purl.PackageURL, name, version string) string {
	if pu == nil {
		return ""
	}

	vendor := ""
	product := name
	targetSW := "*"

	switch strings.ToLower(pu.Type) {
	case purl.TypeGolang:
		// Go modules: vendor is often the first path segment
		// e.g., github.com/foo/bar -> vendor=foo, product=bar
		full := pu.Name
		if pu.Namespace != "" {
			full = pu.Namespace + "/" + pu.Name
		}
		parts := strings.Split(full, "/")
		if len(parts) >= 2 {
			if parts[0] == "github.com" || parts[0] == "gitlab.com" || parts[0] == "bitbucket.org" {
				vendor = sanitizeCPEField(parts[1])
				if len(parts) >= 3 {
					product = sanitizeCPEField(parts[2])
				} else {
					product = sanitizeCPEField(parts[1])
				}
			} else {
				vendor = sanitizeCPEField(parts[0])
				product = sanitizeCPEField(parts[len(parts)-1])
			}
		}
		targetSW = "go"

	case purl.TypeNPM:
		// npm: @scope/package -> vendor=scope, product=package
		if pu.Namespace != "" {
			vendor = sanitizeCPEField(strings.TrimPrefix(pu.Namespace, "@"))
		} else {
			vendor = sanitizeCPEField(pu.Name)
		}
		product = sanitizeCPEField(pu.Name)
		targetSW = "node.js"

	case purl.TypePyPi:
		vendor = sanitizeCPEField(pu.Name)
		product = sanitizeCPEField(pu.Name)
		targetSW = "python"

	case purl.TypeMaven:
		// Maven: group:artifact -> vendor=group, product=artifact
		if pu.Namespace != "" {
			vendor = sanitizeCPEField(pu.Namespace)
		}
		product = sanitizeCPEField(pu.Name)
		targetSW = "java"

	case purl.TypeCargo:
		vendor = sanitizeCPEField(pu.Name)
		product = sanitizeCPEField(pu.Name)
		targetSW = "rust"

	case purl.TypeGem:
		vendor = sanitizeCPEField(pu.Name)
		product = sanitizeCPEField(pu.Name)
		targetSW = "ruby"

	case purl.TypeNuget:
		vendor = sanitizeCPEField(pu.Name)
		product = sanitizeCPEField(pu.Name)
		targetSW = ".net"

	case purlx.TypeMise, purlx.TypeAsdf:
		// A mise/asdf node names a tool by its backend key (e.g. "ubi:cli/cli",
		// "npm:prettier"), not a CPE coordinate. Generate a CPE only when the
		// backend maps to a real registry artifact, by delegating to that
		// ecosystem's logic — identical to a first-class package of that type.
		backend, tool := mise.SplitBackend(name)
		if underlying, ok := mise.BackendArtifactPURL(backend, tool, version); ok {
			return generateCPE(&underlying, underlying.Name, version)
		}
		// Release-binary and runtime tools (ubi:, github:, aqua:, core runtimes)
		// have no registry coordinate. An owner/repo string is NOT a valid CPE
		// vendor:product — NVD's CPE dictionary is curated and irregular (e.g.
		// the gh CLI is cpe:2.3:a:github:cli, not cli:cli; many tools have no
		// CPE at all). A fabricated CPE would fail to match or false-match, so
		// emit none and let OSV remain the matching path.
		//
		// TODO(deputy): authoritative CPEs for these need an NVD CPE-dictionary
		// lookup — the model Syft uses: dictionary-first, then ranked
		// algorithmic candidates tagged with a source, surfaced as candidate
		// SETS (a component can carry multiple CPEs) so a fuzzy matcher can try
		// them. That requires (1) an embedded/queried NVD CPE dictionary, and
		// (2) multi-CPE SBOM threading (protobom node Identifiers currently hold
		// one CPE). Both are deferred; OSV stays the primary matcher. See the
		// backend coverage notes in internal/mise/backend.go.
		return ""

	default:
		// Generic: use name as both vendor and product
		vendor = sanitizeCPEField(name)
		product = sanitizeCPEField(name)
	}

	if vendor == "" || product == "" {
		return ""
	}

	// Sanitize version for CPE
	cpeVersion := sanitizeCPEField(version)
	if cpeVersion == "" {
		cpeVersion = "*"
	}

	return fmt.Sprintf("cpe:2.3:a:%s:%s:%s:*:*:*:*:%s:*:*",
		vendor, product, cpeVersion, targetSW)
}

// sanitizeCPEField cleans a string for use in a CPE identifier.
// CPE fields can only contain: a-z, 0-9, _, -, .
func sanitizeCPEField(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	if s == "" {
		return ""
	}

	// Replace common separators with underscore
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, " ", "_")
	s = strings.ReplaceAll(s, "@", "")

	// Remove invalid characters
	var result strings.Builder
	for _, r := range s {
		if (r >= 'a' && r <= 'z') || (r >= '0' && r <= '9') || r == '_' || r == '-' || r == '.' {
			result.WriteRune(r)
		}
	}

	return result.String()
}

// linkLabelToExternalRefType maps deps.dev link labels to Protobom external reference types.
func linkLabelToExternalRefType(label string) sbom.ExternalReference_ExternalReferenceType {
	label = strings.ToLower(strings.TrimSpace(label))
	switch {
	case strings.Contains(label, "source") || strings.Contains(label, "repository") ||
		strings.Contains(label, "github") || strings.Contains(label, "gitlab") ||
		strings.Contains(label, "bitbucket"):
		return sbom.ExternalReference_VCS
	case strings.Contains(label, "homepage") || strings.Contains(label, "home"):
		return sbom.ExternalReference_WEBSITE
	case strings.Contains(label, "issue") || strings.Contains(label, "bug"):
		return sbom.ExternalReference_ISSUE_TRACKER
	case strings.Contains(label, "doc") || strings.Contains(label, "documentation"):
		return sbom.ExternalReference_DOCUMENTATION
	case strings.Contains(label, "changelog") || strings.Contains(label, "release"):
		return sbom.ExternalReference_RELEASE_NOTES
	case strings.Contains(label, "license"):
		return sbom.ExternalReference_LICENSE
	case strings.Contains(label, "download") || strings.Contains(label, "registry"):
		return sbom.ExternalReference_DOWNLOAD
	case strings.Contains(label, "security") || strings.Contains(label, "advisory"):
		return sbom.ExternalReference_SECURITY_ADVISORY
	default:
		return sbom.ExternalReference_OTHER
	}
}

// extractOwnerFromProjectID extracts the owner/org from a project ID.
// e.g., "github.com/kubernetes/kubernetes" -> "kubernetes"
func extractOwnerFromProjectID(projectID string) string {
	// Pattern: host/owner/repo
	parts := strings.Split(projectID, "/")
	if len(parts) < 2 {
		return ""
	}
	// Skip host (github.com, gitlab.com, etc.)
	if len(parts) >= 2 && (parts[0] == "github.com" || parts[0] == "gitlab.com" || parts[0] == "bitbucket.org") {
		if len(parts) >= 2 {
			return parts[1]
		}
	}
	return parts[0]
}

// AddHashesToNode adds file hashes to a node.
// This is a placeholder for when we implement hash fetching from registries.
func AddHashesToNode(node *sbom.Node, algorithm sbom.HashAlgorithm, hash string) bool {
	if node == nil || hash == "" {
		return false
	}

	if node.Hashes == nil {
		node.Hashes = make(map[int32]string)
	}

	// Check if hash already exists
	if _, ok := node.Hashes[int32(algorithm)]; ok {
		return false
	}

	node.Hashes[int32(algorithm)] = hash
	return true
}

// CompletenessScore calculates how complete an SBOM document is.
// Returns a score from 0.0 to 1.0 and a breakdown of missing elements.
type CompletenessScore struct {
	// Overall score from 0.0 to 1.0
	Score float64
	// Component breakdown
	HasPURL         float64
	HasVersion      float64
	HasLicenses     float64
	HasHashes       float64
	HasCPE          float64
	HasSupplier     float64
	HasExternalRefs float64
	// Counts
	TotalComponents        int
	ComponentsWithPURL     int
	ComponentsWithHash     int
	ComponentsWithCPE      int
	ComponentsWithLicense  int
	ComponentsWithSupplier int
	// NTIA minimum elements compliance
	NTIACompliant bool
	NTIAMissing   []string
}

// CalculateCompleteness calculates the completeness score of an SBOM document.
func CalculateCompleteness(doc *sbom.Document) CompletenessScore {
	score := CompletenessScore{}

	if doc == nil || doc.NodeList == nil {
		return score
	}

	// Filter to package nodes only (skip the root application node)
	var packages []*sbom.Node
	for _, node := range doc.NodeList.Nodes {
		if node != nil && node.Type == sbom.Node_PACKAGE {
			// Skip root elements
			isRoot := slices.Contains(doc.NodeList.RootElements, node.Id)
			if !isRoot {
				packages = append(packages, node)
			}
		}
	}

	score.TotalComponents = len(packages)
	if score.TotalComponents == 0 {
		return score
	}

	for _, node := range packages {
		// Check PURL
		if node.Identifiers != nil {
			if _, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]; ok {
				score.ComponentsWithPURL++
			}
			if _, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_CPE23)]; ok {
				score.ComponentsWithCPE++
			}
		}

		// Check version
		if node.Version != "" {
			score.HasVersion += 1.0
		}

		// Check licenses
		if len(node.Licenses) > 0 {
			score.ComponentsWithLicense++
		}

		// Check hashes
		if len(node.Hashes) > 0 {
			score.ComponentsWithHash++
		}

		// Check supplier
		if len(node.Suppliers) > 0 {
			score.ComponentsWithSupplier++
		}

		// Check external references
		if len(node.ExternalReferences) > 0 {
			score.HasExternalRefs += 1.0
		}
	}

	total := float64(score.TotalComponents)
	score.HasPURL = float64(score.ComponentsWithPURL) / total
	score.HasVersion = score.HasVersion / total
	score.HasLicenses = float64(score.ComponentsWithLicense) / total
	score.HasHashes = float64(score.ComponentsWithHash) / total
	score.HasCPE = float64(score.ComponentsWithCPE) / total
	score.HasSupplier = float64(score.ComponentsWithSupplier) / total
	score.HasExternalRefs = score.HasExternalRefs / total

	// Calculate overall score (weighted average)
	// PURL and version are essential, others are nice-to-have
	score.Score = (score.HasPURL*0.25 +
		score.HasVersion*0.20 +
		score.HasLicenses*0.15 +
		score.HasHashes*0.15 +
		score.HasCPE*0.10 +
		score.HasSupplier*0.10 +
		score.HasExternalRefs*0.05)

	// NTIA Minimum Elements check
	// https://www.ntia.gov/files/ntia/publications/sbom_minimum_elements_report.pdf
	score.NTIACompliant = true
	score.NTIAMissing = []string{}

	// Required: Supplier name
	if score.HasSupplier < 0.95 {
		score.NTIACompliant = false
		score.NTIAMissing = append(score.NTIAMissing, "supplier name ("+fmt.Sprintf("%.0f%%", score.HasSupplier*100)+" coverage)")
	}

	// Required: Component name (we assume all have names since they're in the SBOM)

	// Required: Version
	if score.HasVersion < 0.95 {
		score.NTIACompliant = false
		score.NTIAMissing = append(score.NTIAMissing, "version ("+fmt.Sprintf("%.0f%%", score.HasVersion*100)+" coverage)")
	}

	// Required: Unique identifier (PURL or CPE)
	if score.HasPURL < 0.95 && score.HasCPE < 0.95 {
		score.NTIACompliant = false
		score.NTIAMissing = append(score.NTIAMissing, "unique identifier (PURL/CPE)")
	}

	// Required: Dependency relationship (we have this via edges)

	// Required: Author of SBOM data (document metadata)
	if doc.Metadata == nil || len(doc.Metadata.Authors) == 0 {
		// Check for tool info as fallback
		if doc.Metadata == nil || len(doc.Metadata.Tools) == 0 {
			score.NTIACompliant = false
			score.NTIAMissing = append(score.NTIAMissing, "SBOM author/tool")
		}
	}

	// Required: Timestamp
	if doc.Metadata == nil || doc.Metadata.Date == nil {
		score.NTIACompliant = false
		score.NTIAMissing = append(score.NTIAMissing, "timestamp")
	}

	return score
}

// hashPatterns for detecting hashes in strings
var (
	sha256Pattern = regexp.MustCompile(`^[a-fA-F0-9]{64}$`)
	sha1Pattern   = regexp.MustCompile(`^[a-fA-F0-9]{40}$`)
	md5Pattern    = regexp.MustCompile(`^[a-fA-F0-9]{32}$`)
)

// DetectHashAlgorithm attempts to detect the hash algorithm from a hash string.
func DetectHashAlgorithm(hash string) sbom.HashAlgorithm {
	hash = strings.TrimSpace(hash)
	switch {
	case sha256Pattern.MatchString(hash):
		return sbom.HashAlgorithm_SHA256
	case sha1Pattern.MatchString(hash):
		return sbom.HashAlgorithm_SHA1
	case md5Pattern.MatchString(hash):
		return sbom.HashAlgorithm_MD5
	default:
		return sbom.HashAlgorithm_UNKNOWN
	}
}

// enrichDependencyEdges adds depends_on edges between SBOM nodes by querying
// deps.dev for each direct dependency's transitive dependencies.
// It returns the number of edges added.
func enrichDependencyEdges(ctx context.Context, client pb.InsightsClient, doc *sbom.Document, concurrency int) (int, error) {
	if doc == nil || doc.NodeList == nil || len(doc.NodeList.Nodes) == 0 {
		return 0, nil
	}

	if concurrency <= 0 {
		concurrency = 10
	}

	// Build a map of PURL -> node ID for quick lookup
	purlToNodeID := make(map[string]string)
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}
		purlStr, ok := node.Identifiers[int32(sbom.SoftwareIdentifierType_PURL)]
		if !ok || purlStr == "" {
			continue
		}
		purlToNodeID[purlStr] = node.Id
	}

	// Track existing edges to avoid duplicates
	existingEdges := make(map[string]bool)
	for _, edge := range doc.NodeList.Edges {
		if edge == nil {
			continue
		}
		for _, to := range edge.To {
			key := edge.From + "->" + to
			existingEdges[key] = true
		}
	}

	// Collect direct dependencies (those marked with deputy:direct property)
	var directDeps []*sbom.Node
	for _, node := range doc.NodeList.Nodes {
		if node == nil {
			continue
		}
		for _, prop := range node.Properties {
			if prop.Name == "deputy:direct" && prop.Data == "true" {
				directDeps = append(directDeps, node)
				break
			}
		}
	}

	// If no direct deps marked, treat all non-root nodes as direct
	if len(directDeps) == 0 {
		rootIDs := make(map[string]bool)
		for _, id := range doc.NodeList.RootElements {
			rootIDs[id] = true
		}
		for _, node := range doc.NodeList.Nodes {
			if node != nil && !rootIDs[node.Id] {
				directDeps = append(directDeps, node)
			}
		}
	}

	// Fetch dependencies for direct deps and create edges
	var (
		mu         sync.Mutex
		wg         sync.WaitGroup
		edgesAdded int
		newEdges   []*sbom.Edge
	)

	sem := make(chan struct{}, concurrency)

	for _, node := range directDeps {
		wg.Add(1)
		go func(n *sbom.Node) {
			defer wg.Done()
			sem <- struct{}{}
			defer func() { <-sem }()

			pu := nodePackageURL(n)
			if pu == nil {
				return
			}

			sys := systemFromPURL(pu)
			if sys == pb.System_SYSTEM_UNSPECIFIED {
				return
			}

			name := packageNameForSystem(pu, sys)
			version := normalizeVersionForSystem(sys, strings.TrimSpace(pu.Version))
			if name == "" || version == "" {
				return
			}

			// Fetch dependencies from deps.dev
			resp, err := client.GetDependencies(ctx, &pb.GetDependenciesRequest{
				VersionKey: &pb.VersionKey{
					System:  sys,
					Name:    name,
					Version: version,
				},
			})
			if err != nil || resp == nil {
				return // Non-fatal: package may not have dependency info
			}

			// Process the dependency graph
			// deps.dev returns a list of nodes where index 0 is the root (the package itself)
			// and edges indicate which packages depend on which
			if len(resp.Nodes) < 2 || len(resp.Edges) == 0 {
				return // No dependencies
			}

			// Build map of node index -> PURL for deps.dev response
			depsDevPURLs := make(map[uint32]string)
			for i, depNode := range resp.Nodes {
				if depNode == nil || depNode.VersionKey == nil {
					continue
				}
				vk := depNode.VersionKey
				depPURL := buildPURLFromVersionKey(vk)
				if depPURL != "" {
					depsDevPURLs[uint32(i)] = depPURL
				}
			}

			// Create edges for direct dependencies of this package
			// (edges where FromNode == 0, meaning from the root package)
			mu.Lock()
			for _, edge := range resp.Edges {
				if edge == nil || edge.FromNode != 0 {
					continue // Only process direct dependencies of this package
				}

				depPURL := depsDevPURLs[edge.ToNode]
				if depPURL == "" {
					continue
				}

				// Find if this dependency exists in our SBOM
				targetNodeID, found := purlToNodeID[depPURL]
				if !found {
					continue
				}

				// Check if edge already exists
				edgeKey := n.Id + "->" + targetNodeID
				if existingEdges[edgeKey] {
					continue
				}
				existingEdges[edgeKey] = true

				newEdges = append(newEdges, &sbom.Edge{
					Type: sbom.Edge_dependsOn,
					From: n.Id,
					To:   []string{targetNodeID},
				})
				edgesAdded++
			}
			mu.Unlock()
		}(node)
	}

	wg.Wait()

	// Add all new edges to the document
	doc.NodeList.Edges = append(doc.NodeList.Edges, newEdges...)

	return edgesAdded, nil
}

// buildPURLFromVersionKey creates a PURL string from a deps.dev VersionKey.
func buildPURLFromVersionKey(vk *pb.VersionKey) string {
	if vk == nil {
		return ""
	}

	var purlType string
	switch vk.System {
	case pb.System_GO:
		purlType = "golang"
	case pb.System_NPM:
		purlType = "npm"
	case pb.System_CARGO:
		purlType = "cargo"
	case pb.System_PYPI:
		purlType = "pypi"
	case pb.System_MAVEN:
		purlType = "maven"
	case pb.System_NUGET:
		purlType = "nuget"
	case pb.System_RUBYGEMS:
		purlType = "gem"
	default:
		return ""
	}

	name := vk.Name
	version := vk.Version

	// Handle namespaced packages
	switch vk.System {
	case pb.System_GO:
		// Go modules: name is the full module path
		// PURL format: pkg:golang/namespace/name@version
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	case pb.System_MAVEN:
		// Maven: name is group:artifact
		parts := strings.SplitN(name, ":", 2)
		if len(parts) == 2 {
			return fmt.Sprintf("pkg:%s/%s/%s@%s", purlType, parts[0], parts[1], version)
		}
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	default:
		return fmt.Sprintf("pkg:%s/%s@%s", purlType, name, version)
	}
}
