package graph

import (
	"bufio"
	"bytes"
	"context"
	"encoding/xml"
	"fmt"
	"io/fs"
	"path"
	"strings"

	pb "deps.dev/api/v3"
)

// MavenResolver resolves dependency edges for Maven/Gradle packages.
// It supports multiple lockfile formats:
//   - pom.xml (Maven project files with dependency declarations)
//   - gradle.lockfile (Gradle dependency lockfiles)
//   - buildscript-gradle.lockfile (Gradle buildscript lockfiles)
//
// For pom.xml files, the resolver parses the XML structure to find dependencies.
// For Gradle lockfiles, it parses the simple "group:artifact:version=checksum" format.
//
// When a DepsDevClient is provided, the resolver can fetch transitive dependency
// information from deps.dev to build more complete graphs.
type MavenResolver struct {
	depsDevClient  *DepsDevClient
	maxConcurrency int
}

// MavenResolverOption configures a MavenResolver.
type MavenResolverOption func(*MavenResolver)

// WithMavenConcurrency sets the maximum concurrency for Maven resolution.
func WithMavenConcurrency(n int) MavenResolverOption {
	return func(r *MavenResolver) {
		if n > 0 {
			r.maxConcurrency = n
		}
	}
}

// WithMavenDepsDevClient sets the deps.dev client for transitive resolution.
func WithMavenDepsDevClient(client *DepsDevClient) MavenResolverOption {
	return func(r *MavenResolver) {
		r.depsDevClient = client
	}
}

// NewMavenResolver creates a new Maven edge resolver.
func NewMavenResolver(opts ...MavenResolverOption) *MavenResolver {
	r := &MavenResolver{
		maxConcurrency: 10,
	}
	for _, opt := range opts {
		opt(r)
	}
	return r
}

// Ecosystem returns "Maven" as the ecosystem identifier.
func (r *MavenResolver) Ecosystem() string {
	return "Maven"
}

// ResolveEdges parses Maven/Gradle files to add dependency edges to the graph.
func (r *MavenResolver) ResolveEdges(ctx context.Context, g *Graph, files FileReader) error {
	// Find all relevant files
	mavenFiles, err := r.findMavenFiles(files)
	if err != nil {
		return fmt.Errorf("finding Maven files: %w", err)
	}

	if len(mavenFiles) == 0 {
		return nil
	}

	// Process each file based on its type
	for _, mf := range mavenFiles {
		var processErr error
		switch mf.fileType {
		case mavenFilePom:
			processErr = r.processPomXML(ctx, g, files, mf.path)
		case mavenFileGradleLock:
			processErr = r.processGradleLockfile(ctx, g, files, mf.path)
		}
		if processErr != nil {
			// Log but continue - partial resolution is better than none
			continue
		}
	}

	// Update depths based on resolved edges
	g.UpdateDepths()

	return nil
}

// mavenFileType indicates the type of Maven-related file.
type mavenFileType int

const (
	mavenFilePom mavenFileType = iota
	mavenFileGradleLock
)

// mavenFileInfo contains information about a discovered Maven file.
type mavenFileInfo struct {
	path     string
	fileType mavenFileType
}

// findMavenFiles locates all Maven-related files accessible via the FileReader.
func (r *MavenResolver) findMavenFiles(files FileReader) ([]mavenFileInfo, error) {
	var mavenFiles []mavenFileInfo

	// Try common locations
	commonPaths := []struct {
		path     string
		fileType mavenFileType
	}{
		{"pom.xml", mavenFilePom},
		{"gradle.lockfile", mavenFileGradleLock},
		{"buildscript-gradle.lockfile", mavenFileGradleLock},
	}

	for _, p := range commonPaths {
		if data, err := files.ReadFile(p.path); err == nil && len(data) > 0 {
			mavenFiles = append(mavenFiles, mavenFileInfo{path: p.path, fileType: p.fileType})
		}
	}

	// If the FileReader also implements fs.FS, walk for nested files
	if fsReader, ok := files.(fs.FS); ok {
		_ = fs.WalkDir(fsReader, ".", func(filePath string, d fs.DirEntry, err error) error {
			if err != nil {
				return nil
			}
			if d.IsDir() {
				name := d.Name()
				if name == ".git" || name == "target" || name == "build" || name == ".gradle" || name == "node_modules" {
					return fs.SkipDir
				}
				return nil
			}

			base := path.Base(filePath)
			var fileType mavenFileType
			switch base {
			case "pom.xml":
				fileType = mavenFilePom
			case "gradle.lockfile", "buildscript-gradle.lockfile":
				fileType = mavenFileGradleLock
			default:
				return nil
			}

			// Avoid duplicates
			for _, existing := range mavenFiles {
				if existing.path == filePath {
					return nil
				}
			}
			mavenFiles = append(mavenFiles, mavenFileInfo{path: filePath, fileType: fileType})
			return nil
		})
	}

	return mavenFiles, nil
}

// pomProject represents a minimal pom.xml structure for dependency extraction.
type pomProject struct {
	XMLName      xml.Name      `xml:"project"`
	GroupID      string        `xml:"groupId"`
	ArtifactID   string        `xml:"artifactId"`
	Version      string        `xml:"version"`
	Packaging    string        `xml:"packaging"`
	Parent       *pomParent    `xml:"parent"`
	Dependencies []pomDep      `xml:"dependencies>dependency"`
	DependencyManagement struct {
		Dependencies []pomDep `xml:"dependencies>dependency"`
	} `xml:"dependencyManagement"`
	Properties pomProperties `xml:"properties"`
}

// pomParent represents a parent POM reference.
type pomParent struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
}

// pomDep represents a dependency in pom.xml.
type pomDep struct {
	GroupID    string `xml:"groupId"`
	ArtifactID string `xml:"artifactId"`
	Version    string `xml:"version"`
	Scope      string `xml:"scope"`
	Type       string `xml:"type"`
	Classifier string `xml:"classifier"`
	Optional   string `xml:"optional"`
	Exclusions []struct {
		GroupID    string `xml:"groupId"`
		ArtifactID string `xml:"artifactId"`
	} `xml:"exclusions>exclusion"`
}

// pomProperties holds property values for variable substitution.
type pomProperties struct {
	Values map[string]string
}

// UnmarshalXML custom unmarshals properties into a map.
func (p *pomProperties) UnmarshalXML(d *xml.Decoder, start xml.StartElement) error {
	p.Values = make(map[string]string)

	for {
		t, err := d.Token()
		if err != nil {
			return err
		}

		switch se := t.(type) {
		case xml.StartElement:
			var value string
			if err := d.DecodeElement(&value, &se); err != nil {
				return err
			}
			p.Values[se.Name.Local] = value
		case xml.EndElement:
			if se.Name == start.Name {
				return nil
			}
		}
	}
}

// processPomXML parses a pom.xml and adds edges to the graph.
func (r *MavenResolver) processPomXML(ctx context.Context, g *Graph, files FileReader, pomPath string) error {
	data, err := files.ReadFile(pomPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", pomPath, err)
	}

	var project pomProject
	if err := xml.Unmarshal(data, &project); err != nil {
		return fmt.Errorf("parsing %s: %w", pomPath, err)
	}

	// Resolve project coordinates (may inherit from parent)
	groupID := project.GroupID
	if groupID == "" && project.Parent != nil {
		groupID = project.Parent.GroupID
	}
	version := project.Version
	if version == "" && project.Parent != nil {
		version = project.Parent.Version
	}

	// Create root node for this project
	var rootPURL string
	if groupID != "" && project.ArtifactID != "" {
		rootPURL = mavenPkgToPURL(groupID, project.ArtifactID, version)
		if g.Node(rootPURL) == nil {
			g.AddNode(&Node{
				Purl:      rootPURL,
				Name:      groupID + ":" + project.ArtifactID,
				Version:   version,
				Ecosystem: "Maven",
				Direct:    true,
				Depth:     DepthSyntheticRoot,
			})
		}
		if !containsRoot(g.roots, rootPURL) {
			g.roots = append(g.roots, rootPURL)
		}
	}

	// Build dependency management map for version resolution
	depMgmt := make(map[string]string)
	for _, dep := range project.DependencyManagement.Dependencies {
		key := dep.GroupID + ":" + dep.ArtifactID
		depMgmt[key] = r.resolveProperty(dep.Version, project.Properties.Values)
	}

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Process dependencies
	for _, dep := range project.Dependencies {
		// Resolve version (from property or dependency management)
		version := r.resolveProperty(dep.Version, project.Properties.Values)
		if version == "" {
			key := dep.GroupID + ":" + dep.ArtifactID
			version = depMgmt[key]
		}

		// Skip dependencies without resolved versions
		if version == "" {
			continue
		}

		// Skip test and provided scopes by default
		scope := strings.ToLower(dep.Scope)
		if scope == "test" || scope == "provided" {
			continue
		}

		purl := mavenPkgToPURL(dep.GroupID, dep.ArtifactID, version)
		name := dep.GroupID + ":" + dep.ArtifactID

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      name,
				Version:   version,
				Ecosystem: "Maven",
				Direct:    true,
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		// Mark as direct and add to roots
		node.Direct = true
		if !containsRoot(g.roots, node.Purl) {
			g.roots = append(g.roots, node.Purl)
		}

		// Add edge from root
		if rootPURL != "" {
			edgeKey := rootPURL + "->" + node.Purl
			if !edgeSet[edgeKey] {
				edgeScope := ScopeRuntime
				if scope == "compile" || scope == "" {
					edgeScope = ScopeRuntime
				} else if scope == "runtime" {
					edgeScope = ScopeRuntime
				} else if dep.Optional == "true" {
					edgeScope = ScopeOptional
				}
				g.AddEdge(&Edge{
					From:       rootPURL,
					To:         node.Purl,
					Constraint: version,
					Scope:      edgeScope,
				})
				edgeSet[edgeKey] = true
			}
		}

		// If we have a deps.dev client, fetch transitive dependencies
		if r.depsDevClient != nil {
			r.resolveTransitiveDeps(ctx, g, dep.GroupID, dep.ArtifactID, version, edgeSet)
		}
	}

	return nil
}

// resolveProperty substitutes ${property} references with their values.
func (r *MavenResolver) resolveProperty(value string, props map[string]string) string {
	if !strings.Contains(value, "${") {
		return value
	}

	result := value
	for key, propValue := range props {
		result = strings.ReplaceAll(result, "${"+key+"}", propValue)
		result = strings.ReplaceAll(result, "${project."+key+"}", propValue)
	}
	return result
}

// processGradleLockfile parses a gradle.lockfile and adds edges to the graph.
func (r *MavenResolver) processGradleLockfile(ctx context.Context, g *Graph, files FileReader, lockPath string) error {
	data, err := files.ReadFile(lockPath)
	if err != nil {
		return fmt.Errorf("reading %s: %w", lockPath, err)
	}

	scanner := bufio.NewScanner(bytes.NewReader(data))

	// Track existing edges
	edgeSet := make(map[string]bool)
	for edge := range g.Edges() {
		edgeSet[edge.From+"->"+edge.To] = true
	}

	// Parse lockfile entries
	// Format: group:artifact:version=hash1,hash2
	var packages []struct {
		groupID    string
		artifactID string
		version    string
		purl       string
	}

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		// Skip comments and empty lines
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		// Skip the empty= line
		if strings.HasPrefix(line, "empty=") {
			continue
		}

		// Parse: group:artifact:version=hash
		parts := strings.SplitN(line, ":", 3)
		if len(parts) < 3 {
			continue
		}

		groupID := parts[0]
		artifactID := parts[1]

		// Version may have =hash suffix
		versionPart := parts[2]
		if idx := strings.Index(versionPart, "="); idx != -1 {
			versionPart = versionPart[:idx]
		}

		name := groupID + ":" + artifactID
		purl := mavenPkgToPURL(groupID, artifactID, versionPart)

		packages = append(packages, struct {
			groupID    string
			artifactID string
			version    string
			purl       string
		}{groupID, artifactID, versionPart, purl})

		// Find or create node
		node := g.Node(purl)
		if node == nil {
			node = r.findNodeByName(g, name)
		}
		if node == nil {
			node = &Node{
				Purl:      purl,
				Name:      name,
				Version:   versionPart,
				Ecosystem: "Maven",
				Direct:    true, // Assume direct for lockfile entries
				Depth:     DepthDisconnected,
			}
			g.AddNode(node)
		}

		if !containsRoot(g.roots, node.Purl) {
			g.roots = append(g.roots, node.Purl)
		}
	}

	// If we have a deps.dev client, fetch transitive dependencies for each package
	if r.depsDevClient != nil {
		for _, pkg := range packages {
			r.resolveTransitiveDeps(ctx, g, pkg.groupID, pkg.artifactID, pkg.version, edgeSet)
		}
	}

	return scanner.Err()
}

// resolveTransitiveDeps fetches transitive dependencies from deps.dev.
func (r *MavenResolver) resolveTransitiveDeps(ctx context.Context, g *Graph, groupID, artifactID, version string, edgeSet map[string]bool) {
	// Maven coordinates in deps.dev: "groupId:artifactId"
	name := groupID + ":" + artifactID

	resp, err := r.depsDevClient.GetDependencies(ctx, pb.System_MAVEN, name, version)
	if err != nil {
		return // Non-fatal, skip
	}

	if resp == nil || len(resp.Nodes) == 0 || len(resp.Edges) == 0 {
		return
	}

	// Build node index -> PURL map
	nodePURLs := make(map[uint32]string)
	for i, node := range resp.Nodes {
		if node == nil || node.VersionKey == nil {
			continue
		}
		vk := node.VersionKey
		if vk.System != pb.System_MAVEN {
			continue
		}

		// Maven name format from deps.dev: "groupId:artifactId"
		purl := mavenNameToPURL(vk.Name, vk.Version)
		nodePURLs[uint32(i)] = purl

		// Ensure node exists in graph
		if g.Node(purl) == nil {
			g.AddNode(&Node{
				Purl:      purl,
				Name:      vk.Name,
				Version:   vk.Version,
				Ecosystem: "Maven",
				Direct:    false,
				Depth:     DepthDisconnected,
			})
		}
	}

	// Add edges from deps.dev response
	for _, edge := range resp.Edges {
		fromPURL := nodePURLs[edge.FromNode]
		toPURL := nodePURLs[edge.ToNode]

		if fromPURL == "" || toPURL == "" {
			continue
		}

		edgeKey := fromPURL + "->" + toPURL
		if edgeSet[edgeKey] {
			continue
		}

		// Only add edge if both nodes exist in our graph
		fromNode := g.Node(fromPURL)
		toNode := g.Node(toPURL)

		if fromNode != nil && toNode != nil {
			g.AddEdge(&Edge{
				From:  fromPURL,
				To:    toPURL,
				Scope: ScopeRuntime,
			})
			edgeSet[edgeKey] = true
		}
	}
}

// findNodeByName finds a node by its Maven coordinates (groupId:artifactId).
func (r *MavenResolver) findNodeByName(g *Graph, name string) *Node {
	lowerName := strings.ToLower(name)
	for node := range g.Nodes() {
		if strings.ToLower(node.Name) == lowerName {
			return node
		}
	}
	return nil
}

// mavenPkgToPURL converts Maven coordinates to a Package URL.
// Format: pkg:maven/groupId/artifactId@version
func mavenPkgToPURL(groupID, artifactID, version string) string {
	if version != "" {
		return fmt.Sprintf("pkg:maven/%s/%s@%s", groupID, artifactID, version)
	}
	return fmt.Sprintf("pkg:maven/%s/%s", groupID, artifactID)
}

// mavenNameToPURL converts a deps.dev Maven name (groupId:artifactId) to PURL.
func mavenNameToPURL(name, version string) string {
	parts := strings.SplitN(name, ":", 2)
	if len(parts) == 2 {
		return mavenPkgToPURL(parts[0], parts[1], version)
	}
	// Fallback for unexpected format
	if version != "" {
		return fmt.Sprintf("pkg:maven/%s@%s", strings.ReplaceAll(name, ":", "/"), version)
	}
	return fmt.Sprintf("pkg:maven/%s", strings.ReplaceAll(name, ":", "/"))
}

// Ensure MavenResolver implements EdgeResolver.
var _ EdgeResolver = (*MavenResolver)(nil)
