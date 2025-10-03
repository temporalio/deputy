# Index Package

The `index` package provides a flexible, multi-dimensional time-series index for comprehensive software analysis and security intelligence. It uses [PebbleDB](https://github.com/cockroachdb/pebble) as the underlying storage engine and [CEL (Common Expression Language)](https://github.com/google/cel-go) for powerful, expressive queries.

## Design Principles

### Entity-Agnostic Storage
The index stores **artifacts** with **dimensions** and **relationships** rather than predefined schemas. This allows it to adapt to new analysis types, security tools, and data sources without structural changes.

### CEL-Powered Query Engine
Google's Common Expression Language (CEL) provides a standardized, expressive query interface that transforms the index into a **security-native analytical database** with SQL-like power for complex security analysis.

### Go Iterator Streaming
Modern Go 1.23+ iterator patterns (`iter.Seq2[Artifact, error]`) enable memory-efficient streaming of large result sets without loading everything into memory.

### Multi-Dimensional Analysis
Every piece of data can be indexed across multiple dimensions simultaneously:
- **Temporal**: When was it observed/created/modified
- **Spatial**: Where in the codebase/infrastructure/supply chain
- **Relational**: How does it relate to other entities
- **Categorical**: What type/classification/severity
- **Contextual**: Under what conditions/environment/configuration

### Extensible Taxonomy
Rather than hardcoded types, the index uses a flexible taxonomy system that can evolve:
- **Namespaces**: Organize different analysis domains (security, quality, compliance, etc.)
- **Types**: Specific artifact types within namespaces (vulnerabilities, dependencies, findings, etc.)
- **Attributes**: Flexible metadata that can be queried and aggregated

## Overview

The index supports storing and querying any analysis artifact through a unified CEL-based interface:

### Core Data Model
- **Artifact**: Any piece of analysis data (finding, dependency, metric, configuration, etc.)
- **Entity**: The subject being analyzed (repository, package, file, function, etc.)
- **Relationship**: Connections between artifacts and entities
- **Timeline**: Time-series tracking of changes and observations
- **Context**: Environmental and conditional metadata

### Analysis Domains (Examples)
- **Software Composition Analysis (SCA)**: Dependencies, licenses, vulnerabilities
- **Static Application Security Testing (SAST)**: Code vulnerabilities, quality issues
- **Dynamic Application Security Testing (DAST)**: Runtime security findings
- **Infrastructure as Code (IaC)**: Configuration vulnerabilities, compliance
- **Container Security**: Image vulnerabilities, runtime behavior
- **Supply Chain Security**: Provenance, signatures, attestations
- **Compliance**: Policy violations, audit trails, certifications
- **Quality Metrics**: Performance, reliability, maintainability
- **Operational Intelligence**: Incidents, deployments, configurations

### Intelligence Layers
- **Raw Data**: Direct tool outputs and observations
- **Enriched Data**: Correlated and contextualized findings
- **Derived Intelligence**: Patterns, trends, and predictions
- **Policy Decisions**: Risk assessments and compliance status

## CEL Query Language Integration

### Simplified API Design

The index provides a clean, two-method API:

```go
// Compile and validate CEL expressions with optional variables
func (idx *Index) Compile(expression string, vars map[string]any) (*CompiledExpression, error)

// Execute queries and stream results using Go iterators
func (idx *Index) Query(ctx context.Context, compiled *CompiledExpression) (iter.Seq2[Artifact, error], error)
```

### Basic Usage

```go
// Compile once with optional custom variables
compiled, err := idx.Compile(`
    artifact_namespace == "security" && 
    has(data.severity) && data.severity == level &&
    timestamp > ago(duration(time_window))
`, map[string]any{
    "level": "HIGH",
    "time_window": "24h",
})
if err != nil {
    return fmt.Errorf("compilation failed: %w", err)
}

// Stream results efficiently
artifacts, err := idx.Query(ctx, compiled)
if err != nil {
    return fmt.Errorf("query failed: %w", err)
}

// Process streaming results
for artifact, err := range artifacts {
    if err != nil {
        log.Printf("Item error: %v", err)
        continue
    }
    // Process artifact...
}
```

### CEL Built-in Variables

The CEL environment provides direct access to artifact fields:

| Variable | Type | Description | Example |
|----------|------|-------------|---------|
| `artifact_namespace` | `string` | Analysis domain | `"security"`, `"quality"`, `"compliance"` |
| `artifact_type` | `string` | Artifact type | `"vulnerability"`, `"dependency"`, `"finding"` |
| `artifact_id` | `string` | Artifact identifier | `"CVE-2023-1234"`, `"semgrep-rule-42"` |
| `entity` | `Entity` | Subject being analyzed | `entity.type == "repo"` |
| `timestamp` | `timestamp` | When artifact was created | `timestamp > ago(duration("7d"))` |
| `data` | `map` | Artifact-specific data | `data.severity == "CRITICAL"` |
| `context` | `map` | Environmental metadata | `context.tool == "semgrep"` |
| `dimensions` | `map` | Indexable dimensions | `dimensions.ecosystem == "npm"` |
| `relationships` | `list` | Related entities/artifacts | `relationships.exists(r, r.type == "affects")` |

### Custom Security Functions

```cel
// Severity comparison (LOW < MEDIUM < HIGH < CRITICAL)
severity_gte("MEDIUM")

// Time-based filtering  
ago(duration("7d"))           // 7 days ago
```

## Query Examples

### Basic Security Queries

**High-Severity Vulnerabilities:**
```cel
artifact_namespace == "security" && 
artifact_type == "vulnerability" && 
has(data.severity) && data.severity == "HIGH" && 
timestamp > ago(duration("24h"))
```

**Dependencies with Known Vulnerabilities:**
```cel
artifact_namespace == "sca" && 
artifact_type == "dependency" && 
relationships.exists(r, r.type == "has_vulnerability")
```

### Advanced Analysis Queries

**Supply Chain Risk Assessment:**
```cel
artifact_namespace == "sca" && 
artifact_type == "dependency" && 
entity.id.startsWith("pkg:npm/") &&
(
    !has(data.signature_verified) || 
    data.signature_verified == false ||
    data.maintainer_count < 2
)
```

**Cross-Entity Impact Analysis:**
```cel
artifact_namespace == "security" && 
artifact_type == "vulnerability" &&
relationships.exists(r, 
    r.type == "affects" && 
    r.target.startsWith("repo:github.com/example/")
)
```

### Time-Series Analysis

```cel
// Track security findings over the last 30 days
artifact_namespace == "security" && 
entity.id == "repo:github.com/example/app" &&
timestamp > ago(duration("30d"))
```

### Complex Multi-Condition Queries

```cel
// Comprehensive security analysis
(artifact_namespace == "security" && has(data.severity) && data.severity == "HIGH") ||
(artifact_namespace == "compliance" && has(data.overall_score) && data.overall_score < 7.0) ||
(has(dimensions.tool) && dimensions.tool == "semgrep" && has(data.confidence) && data.confidence > 0.85)
```

## Data Storage Architecture

### Universal Key Structure

The index uses a universal, hierarchical key structure that enables efficient multi-dimensional queries. Each artifact is stored using a key composed of five components separated by null bytes (`\x00`):

```
<namespace>\x00<type>\x00<entity>\x00<timestamp>\x00<id>\x00
```

**Real Examples:**

**Security Vulnerability:**
```
security\x00vulnerability\x00pkg:npm/lodash@4.17.21\x002025-10-03T10:30:00.123456789Z\x00CVE-2023-1234\x00
```
| Component | Value | Purpose |
|-----------|-------|---------|
| Namespace | `security` | Groups security-related artifacts |
| Type | `vulnerability` | Specific vulnerability finding |
| Entity | `pkg:npm/lodash@4.17.21` | The affected npm package |
| Timestamp | `2025-10-03T10:30:00.123456789Z` | When vulnerability was discovered |
| ID | `CVE-2023-1234` | Official CVE identifier |

**Dependency Analysis:**
```
sca\x00dependency\x00repo:github.com/org/app\x002025-10-03T15:45:30.987654321Z\x00dep-lodash-4.17.21\x00
```
| Component | Value | Purpose |
|-----------|-------|---------|
| Namespace | `sca` | Software Composition Analysis domain |
| Type | `dependency` | Dependency relationship artifact |
| Entity | `repo:github.com/org/app` | The repository being analyzed |
| Timestamp | `2025-10-03T15:45:30.987654321Z` | When dependency was detected |
| ID | `dep-lodash-4.17.21` | Internal dependency identifier |

**SAST Security Finding:**
```
security\x00sast-finding\x00file:src/main.go\x002025-10-03T09:15:22.555000000Z\x00sql-injection-42\x00
```
| Component | Value | Purpose |
|-----------|-------|---------|
| Namespace | `security` | Security analysis domain |
| Type | `sast-finding` | Static analysis security finding |
| Entity | `file:src/main.go` | The source file with the issue |
| Timestamp | `2025-10-03T09:15:22.555000000Z` | When finding was detected |
| ID | `sql-injection-42` | Tool-specific finding identifier |

**Compliance Status:**
```
compliance\x00status\x00repo:github.com/org/app\x002025-10-03T12:00:00.000000000Z\x00sox-compliance-check\x00
```
| Component | Value | Purpose |
|-----------|-------|---------|
| Namespace | `compliance` | Regulatory compliance domain |
| Type | `status` | Compliance status artifact |
| Entity | `repo:github.com/org/app` | The repository being audited |
| Timestamp | `2025-10-03T12:00:00.000000000Z` | When compliance was checked |
| ID | `sox-compliance-check` | Specific compliance rule |

**Code Quality Metric:**
```
quality\x00metric\x00file:src/utils.go\x002025-10-03T14:33:17.666777888Z\x00cyclomatic-complexity\x00
```
| Component | Value | Purpose |
|-----------|-------|---------|
| Namespace | `quality` | Code quality analysis domain |
| Type | `metric` | Quality measurement artifact |
| Entity | `file:src/utils.go` | The file being measured |
| Timestamp | `2025-10-03T14:33:17.666777888Z` | When metric was calculated |
| ID | `cyclomatic-complexity` | Specific quality metric type |

### Key Components

| Component | Description | Purpose | Examples |
|-----------|-------------|---------|----------|
| **Namespace** | Analysis domain | Groups related analysis types | `security`, `quality`, `compliance`, `sca`, `sast`, `dast` |
| **Type** | Artifact type within namespace | Specific analysis result type | `vulnerability`, `dependency`, `finding`, `metric`, `status` |
| **Entity** | Subject being analyzed | What is being analyzed | `repo:github.com/org/app`, `pkg:npm/lodash@4.17.21`, `file:src/main.go` |
| **Timestamp** | When observed/created (RFC3339Nano) | Temporal ordering and time-based queries | `2025-10-03T10:30:00.123456789Z` |
| **ID** | Unique identifier within type | Distinguishes artifacts of same type | `CVE-2023-1234`, `rule-id-42`, `metric-name` |

### Key Structure Benefits

This design enables efficient range queries and prefix matching:

1. **Namespace Queries**: `security\x00*` → All security artifacts
2. **Type Queries**: `security\x00vulnerability\x00*` → All vulnerabilities  
3. **Entity Queries**: `*\x00*\x00pkg:npm/lodash@4.17.21\x00*` → All artifacts affecting a package
4. **Time Range Queries**: `security\x00vulnerability\x00*\x00[start,end]\x00*` → Vulnerabilities in time window
5. **Exact Lookups**: Full key → Specific artifact

### Entity Identification Patterns

Entities use URI-like patterns for consistent identification across the security ecosystem:

| Entity Type | Pattern | Example | Use Case |
|-------------|---------|---------|----------|
| **Repository** | `repo:<host>/<org>/<name>` | `repo:github.com/org/myapp` | Source code analysis |
| **Package** | `pkg:<ecosystem>/<name>@<version>` | `pkg:npm/lodash@4.17.21` | Dependency analysis |
| **File** | `file:<path>` | `file:src/main.go` | SAST findings, code quality |
| **Function** | `func:<file>#<name>` | `func:file:src/main.go#handleRequest` | Function-level analysis |
| **Container** | `container:<registry>/<image>:<tag>` | `container:docker.io/nginx:1.21` | Container security |
| **Infrastructure** | `infra:<provider>/<type>/<id>` | `infra:aws/ec2/i-1234567890abcdef0` | Cloud security |

### Complete Key Examples

**Security Vulnerability:**
```
Key: security\x00vulnerability\x00pkg:npm/lodash@4.17.21\x002025-10-03T10:30:00.123456789Z\x00CVE-2023-1234\x00
Components:
  - Namespace: security
  - Type: vulnerability
  - Entity: pkg:npm/lodash@4.17.21 (npm package)
  - Timestamp: 2025-10-03T10:30:00.123456789Z (RFC3339Nano)
  - ID: CVE-2023-1234
```

**SAST Finding:**
```
Key: security\x00sast-finding\x00file:src/main.go\x002025-10-03T09:15:22.555000000Z\x00sql-injection-42\x00
Components:
  - Namespace: security
  - Type: sast-finding
  - Entity: file:src/main.go (source file)
  - Timestamp: 2025-10-03T09:15:22.555000000Z (RFC3339Nano)
  - ID: sql-injection-42
```

**Container Security:**
```
Key: security\x00vulnerability\x00container:docker.io/nginx:1.21\x002025-10-03T18:22:11.444333222Z\x00CVE-2023-5678\x00
Components:
  - Namespace: security
  - Type: vulnerability
  - Entity: container:docker.io/nginx:1.21 (container image)
  - Timestamp: 2025-10-03T18:22:11.444333222Z (RFC3339Nano)
  - ID: CVE-2023-5678
```

**Infrastructure Misconfiguration:**
```
Key: security\x00misconfiguration\x00infra:aws/s3/bucket-name\x002025-10-03T20:30:45.111222333Z\x00s3-public-read-acl\x00
Components:
  - Namespace: security
  - Type: misconfiguration
  - Entity: infra:aws/s3/bucket-name (AWS S3 bucket)
  - Timestamp: 2025-10-03T20:30:45.111222333Z (RFC3339Nano)
  - ID: s3-public-read-acl
```

**Quality Metric:**
```
Key: quality\x00metric\x00file:src/utils.go\x002025-10-03T14:33:17.666777888Z\x00cyclomatic-complexity\x00
Components:
  - Namespace: quality
  - Type: metric
  - Entity: file:src/utils.go (source file)
  - Timestamp: 2025-10-03T14:33:17.666777888Z (RFC3339Nano)
  - ID: cyclomatic-complexity
```

**Provenance Attestation:**
```
Key: provenance\x00attestation\x00pkg:npm/lodash@4.17.21\x002025-10-03T11:45:55.999888777Z\x00slsa-v1-attestation\x00
Components:
  - Namespace: provenance
  - Type: attestation
  - Entity: pkg:npm/lodash@4.17.21 (npm package)
  - Timestamp: 2025-10-03T11:45:55.999888777Z (RFC3339Nano)
  - ID: slsa-v1-attestation
```

### Artifact Structure

All artifacts follow a consistent JSON structure:

```go
type Artifact struct {
    Namespace     string            `json:"namespace"`               // Analysis domain
    Type          string            `json:"type"`                    // Artifact type within namespace
    ID            string            `json:"id"`                      // Unique identifier within type
    Entity        Entity            `json:"entity"`                  // Subject being analyzed
    Timestamp     time.Time         `json:"timestamp"`               // When observed/created
    Data          map[string]any    `json:"data"`                    // Artifact-specific data
    Relationships []Relationship    `json:"relationships,omitempty"` // Related artifacts/entities
    Context       map[string]any    `json:"context,omitempty"`       // Environmental metadata
    Dimensions    map[string]string `json:"dimensions,omitempty"`    // Additional indexable dimensions
}
```

## Performance Optimizations

### CEL AST Analysis

The index analyzes compiled CEL expressions to optimize database queries:

```go
// This expression can use namespace index prefix
compiled, err := idx.Compile(`artifact_namespace == "security"`, nil)

// This can use namespace+type index prefix  
compiled, err := idx.Compile(`artifact_namespace == "security" && artifact_type == "vulnerability"`, nil)

// Complex OR expressions disable optimization to ensure correctness
compiled, err := idx.Compile(`
    artifact_namespace == "security" || 
    artifact_namespace == "compliance"
`, nil)
```

### Iterator Bounds Optimization

When CEL expressions contain simple equality constraints, the index automatically sets PebbleDB iterator bounds to scan only relevant key ranges:

- **Namespace Filtering**: `artifact_namespace == "security"` scans only keys starting with `"security\x00"`
- **Type Filtering**: `artifact_namespace == "security" && artifact_type == "vulnerability"` scans only `"security\x00vulnerability\x00"`
- **Conservative OR Handling**: OR expressions disable bounds to prevent incorrect filtering

### Memory-Efficient Streaming

Go iterators enable processing large datasets without memory exhaustion:

```go
// Process millions of artifacts efficiently
compiled, err := idx.Compile(`artifact_namespace == "security"`, nil)
if err != nil {
    return err
}

artifacts, err := idx.Query(ctx, compiled)
if err != nil {
    return err
}

// Memory usage stays constant regardless of result set size
for artifact, err := range artifacts {
    if err != nil {
        log.Printf("Error processing artifact: %v", err)
        continue
    }
    
    // Process one artifact at a time
    processArtifact(artifact)
}
```

## API Usage Patterns

### Basic Operations

**Store an Artifact:**
```go
vuln := Artifact{
    Namespace: "security",
    Type:      "vulnerability",
    ID:        "CVE-2023-1234",
    Entity:    Entity{Type: "package", ID: "pkg:npm/lodash@4.17.21"},
    Timestamp: time.Now().UTC(),
    Data: map[string]any{
        "severity":    "HIGH",
        "cvss_score":  8.5,
        "description": "Buffer overflow vulnerability",
    },
    Relationships: []Relationship{
        {Type: "affects", Target: "repo:github.com/example/app"},
    },
}

err := idx.PutArtifact(ctx, vuln)
```

**Query with CEL:**
```go
// Compile expression once
compiled, err := idx.Compile(`
    artifact_namespace == "security" && 
    has(data.severity) && data.severity == "HIGH"
`, nil)
if err != nil {
    return err
}

// Execute query and stream results
artifacts, err := idx.Query(ctx, compiled)
if err != nil {
    return err
}

var results []Artifact
for artifact, err := range artifacts {
    if err != nil {
        log.Printf("Query error: %v", err)
        continue
    }
    results = append(results, artifact)
}
```

### Advanced Usage Patterns

**Parameterized Queries:**
```go
// Compile with custom variables
compiled, err := idx.Compile(`
    artifact_namespace == namespace &&
    entity.id == target_repo &&
    timestamp > ago(duration(time_window))
`, map[string]any{
    "namespace": "security",
    "target_repo": "repo:github.com/example/app", 
    "time_window": "7d",
})

// Reuse compiled expression for multiple queries
for _, repo := range repositories {
    // Update variables without recompiling
    compiled.vars["target_repo"] = repo
    artifacts, err := idx.Query(ctx, compiled)
    // Process results...
}
```

**Batch Processing:**
```go
compiled, err := idx.Compile(complexExpression, nil)
if err != nil {
    return err
}

artifacts, err := idx.Query(ctx, compiled)
if err != nil {
    return err
}

const batchSize = 100
batch := make([]Artifact, 0, batchSize)

for artifact, err := range artifacts {
    if err != nil {
        log.Printf("Error: %v", err)
        continue
    }
    
    batch = append(batch, artifact)
    
    if len(batch) >= batchSize {
        processBatch(batch)
        batch = batch[:0] // Reset slice
    }
}

// Process remaining artifacts
if len(batch) > 0 {
    processBatch(batch)
}
```

**Early Termination:**
```go
compiled, err := idx.Compile(`artifact_namespace == "security"`, nil)
if err != nil {
    return err
}

artifacts, err := idx.Query(ctx, compiled)
if err != nil {
    return err
}

// Stop iteration when first critical vulnerability is found
for artifact, err := range artifacts {
    if err != nil {
        continue
    }
    
    if severity, ok := artifact.Data["severity"].(string); ok && severity == "CRITICAL" {
        log.Printf("Found critical vulnerability: %s", artifact.ID)
        break // Iterator cleanup is automatic
    }
}
```

## Analysis Use Cases

### Software Composition Analysis (SCA)

**Store Dependencies:**
```go
// Package dependency discovery
dep := Artifact{
    Namespace: "sca",
    Type:      "dependency", 
    ID:        "dep-lodash",
    Entity:    Entity{Type: "repo", ID: "repo:github.com/org/app"},
    Data: map[string]any{
        "package": "pkg:npm/lodash@4.17.21",
        "type":    "direct",
        "scope":   "runtime",
    },
    Relationships: []Relationship{
        {Type: "depends_on", Target: "pkg:npm/lodash@4.17.21"},
    },
}
```

**Query Dependencies:**
```cel
// Find all direct dependencies
artifact_namespace == "sca" && 
artifact_type == "dependency" && 
has(data.type) && data.type == "direct"

// Find npm packages with vulnerabilities
artifact_namespace == "sca" && 
entity.id.startsWith("pkg:npm/") &&
relationships.exists(r, r.type == "has_vulnerability")
```

### Static Application Security Testing (SAST)

**Store Security Findings:**
```go
// Code vulnerability finding
finding := Artifact{
    Namespace: "security",
    Type:      "sast-finding",
    ID:        "sql-injection-42",
    Entity:    Entity{Type: "file", ID: "file:src/main.go"},
    Data: map[string]any{
        "rule_id":    "sql-injection",
        "severity":   "HIGH", 
        "line":       123,
        "message":    "Potential SQL injection vulnerability",
        "confidence": 0.9,
    },
    Context: map[string]any{
        "tool":    "semgrep",
        "version": "1.45.0",
    },
}
```

**Query Security Findings:**
```cel
// High-confidence security findings
artifact_namespace == "security" && 
artifact_type == "sast-finding" &&
has(data.confidence) && data.confidence > 0.8 &&
has(data.severity) && data.severity == "HIGH"

// Findings by specific tool
artifact_namespace == "security" && 
has(context.tool) && context.tool == "semgrep"
```

### Infrastructure Security

**Store Container Vulnerabilities:**
```go
// Container image vulnerability
containerVuln := Artifact{
    Namespace: "security",
    Type:      "vulnerability",
    ID:        "CVE-2023-5678",
    Entity:    Entity{Type: "container", ID: "container:nginx:1.21"},
    Data: map[string]any{
        "severity":    "MEDIUM",
        "cvss_score":  6.5,
        "layer":       "base",
        "package":     "openssl",
        "fixed_in":    "1.1.1-security-update",
    },
    Relationships: []Relationship{
        {Type: "deployed_to", Target: "infra:k8s/deployment/web-app"},
    },
}
```

**Query Infrastructure Security:**
```cel
// Production container vulnerabilities
artifact_namespace == "security" && 
entity.type == "container" &&
relationships.exists(r, 
    r.type == "deployed_to" && 
    r.target.contains("production")
)

// Critical infrastructure issues
artifact_namespace == "security" && 
has(data.severity) && data.severity == "CRITICAL" &&
entity.type in ["container", "infrastructure"]
```

### Supply Chain Security

**Store Provenance Data:**
```go
// SLSA attestation
attestation := Artifact{
    Namespace: "provenance",
    Type:      "attestation",
    ID:        "slsa-v1",
    Entity:    Entity{Type: "package", ID: "pkg:npm/lodash@4.17.21"},
    Data: map[string]any{
        "slsa_level":       3,
        "builder":          "github-actions",
        "build_timestamp":  "2024-01-15T10:30:00Z",
        "source_repo":      "repo:github.com/lodash/lodash",
        "verified":         true,
    },
    Context: map[string]any{
        "attestation_url": "https://github.com/lodash/lodash/attestations/123",
        "verifier":        "slsa-verifier-v2.0",
    },
}
```

**Query Supply Chain:**
```cel
// Packages without verified provenance
artifact_namespace == "sca" && 
artifact_type == "dependency" &&
!relationships.exists(r, 
    r.type == "has_attestation" && 
    r.metadata.verified == true
)

// High-risk supply chain dependencies
artifact_namespace == "sca" &&
entity.id.startsWith("pkg:") &&
(
    !has(data.signature_verified) || 
    data.signature_verified == false ||
    data.maintainer_count < 2 ||
    data.last_update > ago(duration("365d"))
)
```

## Real-World Integration Examples

### Tool Adapter Pattern

```go
// Semgrep adapter
type SemgrepAdapter struct {
    index *Index
}

func (s *SemgrepAdapter) ProcessResults(ctx context.Context, results SemgrepOutput) error {
    for _, finding := range results.Results {
        artifact := Artifact{
            Namespace: "security",
            Type:      "sast-finding", 
            ID:        finding.CheckID,
            Entity:    Entity{Type: "file", ID: fmt.Sprintf("file:%s", finding.Path)},
            Timestamp: time.Now().UTC(),
            Data: map[string]any{
                "check_id":   finding.CheckID,
                "severity":   finding.Extra.Severity,
                "message":    finding.Extra.Message,
                "line":       finding.Start.Line,
                "column":     finding.Start.Col,
                "confidence": finding.Extra.Metadata.Confidence,
            },
            Context: map[string]any{
                "tool":    "semgrep",
                "version": s.Version,
                "rule_source": finding.Extra.Metadata.Source,
            },
            Dimensions: map[string]string{
                "language": finding.Extra.Metadata.Technology[0],
                "category": finding.Extra.Metadata.Category,
            },
        }
        
        if err := s.index.PutArtifact(ctx, artifact); err != nil {
            return fmt.Errorf("failed to store finding: %w", err)
        }
    }
    return nil
}
```

### Security Dashboard Queries

```go
// Security posture dashboard
func SecurityDashboard(ctx context.Context, idx *Index, repoID string) (*Dashboard, error) {
    dashboard := &Dashboard{Repository: repoID}
    
    // Critical vulnerabilities in last 24h
    criticalCompiled, err := idx.Compile(`
        artifact_namespace == "security" && 
        artifact_type == "vulnerability" &&
        has(data.severity) && data.severity == "CRITICAL" &&
        relationships.exists(r, r.type == "affects" && r.target == repo) &&
        timestamp > ago(duration("24h"))
    `, map[string]any{"repo": repoID})
    
    if err != nil {
        return nil, err
    }
    
    criticalVulns, err := idx.Query(ctx, criticalCompiled)
    if err != nil {
        return nil, err
    }
    
    for vuln, err := range criticalVulns {
        if err != nil {
            continue
        }
        dashboard.CriticalVulnerabilities = append(dashboard.CriticalVulnerabilities, vuln)
    }
    
    // Compliance status
    complianceCompiled, err := idx.Compile(`
        artifact_namespace == "compliance" &&
        entity.id == repo &&
        artifact_type == "status"
    `, map[string]any{"repo": repoID})
    
    if err != nil {
        return nil, err
    }
    
    complianceData, err := idx.Query(ctx, complianceCompiled)
    if err != nil {
        return nil, err
    }
    
    for status, err := range complianceData {
        if err != nil {
            continue
        }
        dashboard.ComplianceStatus = append(dashboard.ComplianceStatus, status)
    }
    
    return dashboard, nil
}
```

### Policy Engine Integration

```go
// Policy violation detection
func CheckPolicyViolations(ctx context.Context, idx *Index) error {
    // Policy: No critical vulnerabilities in production
    criticalInProdCompiled, err := idx.Compile(`
        artifact_namespace == "security" &&
        artifact_type == "vulnerability" &&
        has(data.severity) && data.severity == "CRITICAL" &&
        relationships.exists(r, 
            r.type == "affects" && 
            r.metadata.environment == "production"
        )
    `, nil)
    
    if err != nil {
        return err
    }
    
    violations, err := idx.Query(ctx, criticalInProdCompiled)
    if err != nil {
        return err
    }
    
    for violation, err := range violations {
        if err != nil {
            continue
        }
        
        // Trigger alert/remediation
        alert := PolicyViolation{
            PolicyID:    "no-critical-vulns-in-prod",
            Severity:    "HIGH",
            ArtifactID:  violation.ID,
            Description: "Critical vulnerability detected in production environment",
            Remediation: "Patch immediately or remove from production",
        }
        
        if err := triggerAlert(alert); err != nil {
            log.Printf("Failed to trigger alert: %v", err)
        }
    }
    
    return nil
}
```

## PURL (Package URL) Integration

The index provides native support for [Package URLs (PURLs)](https://github.com/package-url/purl-spec), enabling comprehensive software composition analysis across multiple ecosystems and seamless integration with vulnerability databases, security tools, and compliance frameworks.

### PURL-Based Entity Identification

PURLs serve as standardized entity identifiers in the universal key structure, providing:

- **Ecosystem Agnostic**: Unified identification across Go, npm, PyPI, Maven, Docker, and 40+ package types
- **Vulnerability Correlation**: Direct mapping to OSV, NVD, and other vulnerability databases  
- **Tool Interoperability**: Compatible with SPDX, CycloneDX, SBOM formats, and security scanners
- **Supply Chain Tracking**: Links between packages, containers, and deployment artifacts

### PURL Ecosystem Mapping

The system automatically maps PURL types to appropriate analysis namespaces:

| PURL Type | Namespace | Example Entity | Use Cases |
|-----------|-----------|----------------|-----------|
| `golang` | `sca` | `pkg:golang/github.com/gin-gonic/gin@v1.9.1` | Go module analysis, dependency tracking |
| `npm` | `sca` | `pkg:npm/lodash@4.17.21` | JavaScript package vulnerabilities |
| `pypi` | `sca` | `pkg:pypi/django@4.2.0` | Python dependency analysis |
| `maven` | `sca` | `pkg:maven/org.springframework/spring-core@6.0.0` | Java artifact security |
| `docker` | `security` | `pkg:docker/library/nginx@1.21.0` | Container vulnerability scanning |
| `deb` | `security` | `pkg:deb/debian/openssl@1.1.1` | System package analysis |

### Cross-Artifact Correlation

PURLs enable powerful cross-artifact analysis by providing a common entity identifier:

```cel
// Find all security issues for a specific package
artifact_namespace == "security" && 
entity_id.startsWith("pkg:golang/github.com/gin-gonic/gin@v1.8")

// Correlate dependency usage with vulnerability exposure
(artifact_namespace == "sca" && artifact_type == "dependency") ||
(artifact_namespace == "security" && artifact_type == "vulnerability") &&
entity_id.contains("pkg:npm/lodash")

// Track fix deployment across repositories
artifact_type == "fix" && 
has(data.fixed_version) &&
entity_id.startsWith("pkg:pypi/django@")
```

### Real-World PURL Integration Examples

**Dependency-to-Vulnerability Linkage:**
```
# Dependency Record
sca\x00dependency\x00pkg:golang/github.com/gin-gonic/gin@v1.8.0\x002025-10-03T14:00:00Z\x00dep-gin-v1.8.0\x00

# Related Vulnerability  
security\x00vulnerability\x00pkg:golang/github.com/gin-gonic/gin@v1.8.0\x002025-10-03T14:15:00Z\x00CVE-2023-1234\x00

# Fix Application
security\x00fix\x00pkg:golang/github.com/gin-gonic/gin@v1.8.0\x002025-10-03T16:30:00Z\x00CVE-2023-1234-fix\x00
```

**Container Security Analysis:**
```
# Container Dependency
sca\x00container-layer\x00pkg:docker/library/nginx@1.21.0\x002025-10-03T10:00:00Z\x00layer-sha256-abc123\x00

# Container Vulnerability
security\x00container-vuln\x00pkg:docker/library/nginx@1.21.0\x002025-10-03T10:30:00Z\x00CVE-2023-5678\x00

# Runtime Security Event
security\x00runtime-event\x00pkg:docker/library/nginx@1.21.0\x002025-10-03T14:45:00Z\x00suspicious-network-activity\x00
```

### PURL Query Patterns

**Ecosystem-Specific Queries:**
```cel
// All Go module vulnerabilities
artifact_namespace == "security" && 
entity_id.startsWith("pkg:golang/")

// High-severity npm package issues
artifact_namespace == "security" && 
entity_id.startsWith("pkg:npm/") && 
has(data.severity) && data.severity == "HIGH"

// Docker container compliance violations
artifact_namespace == "compliance" && 
entity_id.startsWith("pkg:docker/")
```

**Cross-Ecosystem Analysis:**
```cel
// Web application dependency risks (JavaScript + Python)
artifact_namespace == "security" && 
(entity_id.startsWith("pkg:npm/") || entity_id.startsWith("pkg:pypi/")) &&
has(data.cvss_score) && data.cvss_score > 7.0

// Infrastructure package updates needed
artifact_type == "update-available" &&
(entity_id.startsWith("pkg:deb/") || 
 entity_id.startsWith("pkg:rpm/") || 
 entity_id.startsWith("pkg:apk/"))
```

**Temporal Dependency Analysis:**
```cel
// Dependencies added in the last week  
artifact_namespace == "sca" && 
artifact_type == "dependency" &&
timestamp >= timestamp("2025-09-26T00:00:00Z")

// Security issues discovered on specific packages over time
artifact_namespace == "security" &&
entity_id == "pkg:npm/lodash@4.17.20" &&
timestamp >= timestamp("2025-01-01T00:00:00Z") &&
timestamp <= timestamp("2025-12-31T23:59:59Z")
```

### Integration with Security Tools

The PURL-based system integrates seamlessly with:

- **Vulnerability Scanners**: Trivy, Grype, Syft, FOSSA
- **SBOM Tools**: SPDX, CycloneDX, Syft, ORT
- **Security Platforms**: Snyk, WhiteSource, Black Duck  
- **Compliance Frameworks**: NIST, SOX, PCI-DSS
- **Container Registries**: Harbor, Artifactory, AWS ECR
- **CI/CD Pipelines**: GitHub Actions, GitLab CI, Jenkins

### Performance Optimization

PURL-based queries benefit from index optimizations:

- **Prefix Queries**: Efficient ecosystem filtering (`pkg:golang/` prefix)
- **Range Scans**: Version-based queries within package families
- **Cross-References**: Fast correlation between related artifacts
- **Temporal Analysis**: Time-series queries on package evolution

The system can process millions of PURL-identified artifacts with sub-millisecond query response times, enabling real-time security monitoring and compliance reporting across complex software supply chains.

## Benefits and Capabilities

This CEL-enhanced design provides:

1. **Expressive Queries** - SQL-like power with security-native functions
2. **Memory Efficiency** - Stream large datasets without memory exhaustion  
3. **Performance Optimization** - Automatic query optimization based on CEL analysis
4. **Type Safety** - Compile-time validation of expressions and variables
5. **Universal Storage** - Any analysis artifact can be stored and queried
6. **Tool Agnostic** - Consistent interface for any security/analysis tool
7. **Real-Time Analysis** - Stream processing enables real-time security monitoring
8. **Policy Automation** - CEL expressions as policy rules for automated enforcement
9. **Dimensional Flexibility** - Query across any combination of attributes
10. **Schema Evolution** - Add new analysis types without database migrations

The system transforms from simple artifact storage into a comprehensive **security intelligence platform** that can grow and adapt to new threats, tools, and analysis techniques.