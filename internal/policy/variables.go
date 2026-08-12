package policy

// VariableMetadata provides a human- and agent-facing type hint and description
// for a CEL policy variable, so callers do not have to inspect protobuf
// descriptors to understand what a variable holds.
type VariableMetadata struct {
	Type        string
	Description string
}

// variableMetadataByName is the single source of truth for policy variable
// display metadata. It is shared by the policy discovery API, the MCP
// list_policy_entrypoints tool, and the policy LSP so the three surfaces cannot
// describe the same variable differently. Keys are the CEL variable names
// declared by BindingProfiles.
var variableMetadataByName = map[string]VariableMetadata{
	"ancestors":             {Type: "list(graphv1.Node)", Description: "Ancestor nodes for the current graph node"},
	"base_image":            {Type: "string", Description: "Base image reference"},
	"change":                {Type: "object", Description: "Current dependency or package change"},
	"changes":               {Type: "list(object)", Description: "Dependency changes"},
	"cluster":               {Type: "object", Description: "Current triage cluster"},
	"command":               {Type: "list(string)", Description: "Command argv being evaluated (first element is the executable)"},
	"component":             {Type: "dependencyv1.Package", Description: "SBOM component being evaluated"},
	"config_changes":        {Type: "object", Description: "Container image configuration changes"},
	"context":               {Type: "sandboxv1.ExecutionContext", Description: "Context about what triggered the sandbox execution"},
	"dependency":            {Type: "dependencyv1.Package", Description: "Dependency associated with a change"},
	"descendants":           {Type: "list(graphv1.Node)", Description: "Descendant nodes for the current graph node"},
	"dockerfile":            {Type: "object", Description: "Parsed Dockerfile structure"},
	"dockerfile_analysis":   {Type: "object", Description: "Dockerfile analysis results"},
	"edge":                  {Type: "graphv1.Edge", Description: "Current dependency graph edge"},
	"edges":                 {Type: "list(graphv1.Edge)", Description: "Dependency graph edges"},
	"env":                   {Type: "policyv1.Environment", Description: "Execution environment context"},
	"findings":              {Type: "list(object)", Description: "Triage findings"},
	"from_node":             {Type: "graphv1.Node", Description: "Source node for the current graph edge"},
	"graph":                 {Type: "object", Description: "Dependency graph data (nodes and edges)"},
	"host":                  {Type: "string", Description: "Requested network host"},
	"image":                 {Type: "object", Description: "Container image metadata"},
	"image_info":            {Type: "object", Description: "Container image metadata"},
	"jwt":                   {Type: "policyv1.JWTClaims", Description: "JWT claims from authenticated requests"},
	"layer":                 {Type: "object", Description: "Container image layer analysis"},
	"layer_analysis":        {Type: "object", Description: "Layer-by-layer container diff analysis"},
	"licenses":              {Type: "list(string)", Description: "SPDX license identifiers"},
	"node":                  {Type: "graphv1.Node", Description: "Current dependency graph node"},
	"nodes":                 {Type: "list(graphv1.Node)", Description: "Dependency graph nodes"},
	"package_changes":       {Type: "list(object)", Description: "Package changes between container images"},
	"packages":              {Type: "list(dependencyv1.Package)", Description: "Packages in the report"},
	"pkg":                   {Type: "dependencyv1.Package", Description: "Package associated with the current policy item"},
	"plan":                  {Type: "object", Description: "Remediation plan"},
	"port":                  {Type: "int", Description: "Requested network port"},
	"protocol":              {Type: "string", Description: "Requested network protocol"},
	"repo":                  {Type: "string", Description: "Repository path"},
	"report":                {Type: "object", Description: "Scan report data"},
	"top_packages":          {Type: "list(object)", Description: "Triage package summaries, most urgent first"},
	"base_ref":              {Type: "string", Description: "Diff base reference"},
	"base_target":           {Type: "targetv1.Target", Description: "Base side of a diff request, the target being compared from"},
	"target_ref":            {Type: "string", Description: "Diff target reference"},
	"request":               {Type: "object", Description: "Request metadata for proxy or server authorization policies"},
	"requested_config":      {Type: "sandboxv1.SandboxConfig", Description: "Requested sandbox configuration"},
	"roots":                 {Type: "list(string)", Description: "PURLs of direct (depth-0) dependencies"},
	"sandbox_config":        {Type: "sandboxv1.SandboxConfig", Description: "Effective sandbox configuration"},
	"sbom":                  {Type: "object", Description: "SBOM document"},
	"secret":                {Type: "object", Description: "Current secret finding"},
	"secrets":               {Type: "list(object)", Description: "Secrets scan findings"},
	"source":                {Type: "string", Description: "Source of the sandbox execution request"},
	"stage":                 {Type: "object", Description: "Current Dockerfile stage"},
	"stats":                 {Type: "object", Description: "Summary statistics for the current report"},
	"step":                  {Type: "object", Description: "Current remediation plan step"},
	"summary":               {Type: "object", Description: "Container diff summary"},
	"target":                {Type: "targetv1.Target", Description: "Target or provenance metadata"},
	"target_image":          {Type: "string", Description: "Target image reference"},
	"target_target":         {Type: "targetv1.Target", Description: "Target side of a diff request, the target being compared to"},
	"to_node":               {Type: "graphv1.Node", Description: "Target node for the current graph edge"},
	"vulnerability":         {Type: "vulnerabilityv1.Finding", Description: "Current vulnerability finding"},
	"vulnerability_changes": {Type: "list(object)", Description: "Vulnerability changes between container images"},
	"vulnerabilities":       {Type: "list(vulnerabilityv1.Finding)", Description: "Vulnerability findings"},
	"workspace_dir":         {Type: "string", Description: "Workspace directory for sandbox execution"},
}

// VariableInfo returns display metadata for a policy variable. ok is false when
// the variable has no explicit entry; use VariableInfoOrDefault for the
// generic fallback the discovery surfaces present.
func VariableInfo(name string) (VariableMetadata, bool) {
	meta, ok := variableMetadataByName[name]
	return meta, ok
}

// VariableInfoOrDefault returns explicit metadata when available, otherwise a
// generic object descriptor for variables not yet catalogued.
func VariableInfoOrDefault(name string) VariableMetadata {
	if meta, ok := variableMetadataByName[name]; ok {
		return meta
	}
	return VariableMetadata{Type: "object", Description: "Policy variable"}
}
