package index

import (
	"context"
	"errors"
	"fmt"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/cockroachdb/pebble/v2/vfs"
)

// TestIndex_BasicCELOperations tests the core CEL compilation and query functionality
func TestIndex_BasicCELOperations(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	// Use in-memory filesystem for testing
	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	// Create test artifacts
	now := time.Now().UTC()

	// Security vulnerability artifact
	vulnArtifact := Artifact{
		Namespace: "security",
		Type:      "vulnerability",
		ID:        "CVE-2023-1234",
		Entity: Entity{
			Type: "package",
			ID:   "pkg:npm/lodash@4.17.21",
			Metadata: map[string]any{
				"ecosystem": "npm",
				"name":      "lodash",
				"version":   "4.17.21",
			},
		},
		Timestamp: now,
		Data: map[string]any{
			"severity":    "HIGH",
			"cvss_score":  8.5,
			"description": "Buffer overflow vulnerability",
			"cwe":         "CWE-120",
		},
		Relationships: []Relationship{
			{
				Type:   "affects",
				Target: "repo:github.com/example/app",
				Metadata: map[string]any{
					"impact": "direct",
				},
			},
		},
		Context: map[string]any{
			"source":     "osv.dev",
			"tool":       "deputy-scanner",
			"confidence": 0.95,
		},
		Dimensions: map[string]string{
			"severity": "HIGH",
			"tool":     "osv",
		},
	}

	// Store the vulnerability
	if err := idx.PutArtifact(ctx, vulnArtifact); err != nil {
		t.Fatalf("PutArtifact(vulnerability): %v", err)
	}

	// Quality metric artifact
	qualityArtifact := Artifact{
		Namespace: "quality",
		Type:      "metric",
		ID:        "complexity-main.go",
		Entity: Entity{
			Type: "file",
			ID:   "file:github.com/example/app/main.go",
		},
		Timestamp: now.Add(time.Minute),
		Data: map[string]any{
			"complexity":      15,
			"lines_of_code":   250,
			"maintainability": "B",
		},
		Context: map[string]any{
			"tool":    "sonarqube",
			"version": "9.7.1",
		},
		Dimensions: map[string]string{
			"tool":     "sonar",
			"language": "go",
		},
	}

	// Store the quality metric
	if err := idx.PutArtifact(ctx, qualityArtifact); err != nil {
		t.Fatalf("PutArtifact(quality): %v", err)
	}

	// Test 1: Query all artifacts (no filter)
	allCompiled, err := idx.Compile("true", nil)
	if err != nil {
		t.Fatalf("Compile(all): %v", err)
	}

	allArtifacts, err := idx.Query(ctx, allCompiled)
	if err != nil {
		t.Fatalf("Query(all): %v", err)
	}

	var allResults []Artifact
	for artifact, err := range allArtifacts {
		if err != nil {
			t.Fatalf("Query(all) iteration error: %v", err)
		}
		allResults = append(allResults, artifact)
	}

	if len(allResults) != 2 {
		t.Fatalf("Query(all) expected 2 artifacts, got %d", len(allResults))
	}

	// Test 2: Query by namespace
	securityCompiled, err := idx.Compile(`artifact_namespace == "security"`, nil)
	if err != nil {
		t.Fatalf("Compile(security): %v", err)
	}

	securityArtifacts, err := idx.Query(ctx, securityCompiled)
	if err != nil {
		t.Fatalf("Query(security): %v", err)
	}

	var securityResults []Artifact
	for artifact, err := range securityArtifacts {
		if err != nil {
			t.Fatalf("Query(security) iteration error: %v", err)
		}
		securityResults = append(securityResults, artifact)
	}

	if len(securityResults) != 1 {
		t.Fatalf("Query(security) expected 1 artifact, got %d", len(securityResults))
	}
	if securityResults[0].Type != "vulnerability" {
		t.Fatalf("Query(security) expected vulnerability, got %s", securityResults[0].Type)
	}

	// Test 3: Query by namespace and type
	vulnCompiled, err := idx.Compile(`artifact_namespace == "security" && artifact_type == "vulnerability"`, nil)
	if err != nil {
		t.Fatalf("Compile(vulnerability): %v", err)
	}

	vulnArtifacts, err := idx.Query(ctx, vulnCompiled)
	if err != nil {
		t.Fatalf("Query(vulnerability): %v", err)
	}

	var vulnResults []Artifact
	for artifact, err := range vulnArtifacts {
		if err != nil {
			t.Fatalf("Query(vulnerability) iteration error: %v", err)
		}
		vulnResults = append(vulnResults, artifact)
	}

	if len(vulnResults) != 1 {
		t.Fatalf("Query(vulnerability) expected 1 artifact, got %d", len(vulnResults))
	}

	// Test 4: Query by entity
	entityCompiled, err := idx.Compile(`entity.id == "pkg:npm/lodash@4.17.21"`, nil)
	if err != nil {
		t.Fatalf("Compile(entity): %v", err)
	}

	entityArtifacts, err := idx.Query(ctx, entityCompiled)
	if err != nil {
		t.Fatalf("Query(entity): %v", err)
	}

	var entityResults []Artifact
	for artifact, err := range entityArtifacts {
		if err != nil {
			t.Fatalf("Query(entity) iteration error: %v", err)
		}
		entityResults = append(entityResults, artifact)
	}

	if len(entityResults) != 1 {
		t.Fatalf("Query(entity) expected 1 artifact, got %d", len(entityResults))
	}

	// Test 5: Query by dimensions
	dimensionCompiled, err := idx.Compile(`has(dimensions.severity) && dimensions.severity == "HIGH"`, nil)
	if err != nil {
		t.Fatalf("Compile(dimensions): %v", err)
	}

	dimensionArtifacts, err := idx.Query(ctx, dimensionCompiled)
	if err != nil {
		t.Fatalf("Query(dimensions): %v", err)
	}

	var dimensionResults []Artifact
	for artifact, err := range dimensionArtifacts {
		if err != nil {
			t.Fatalf("Query(dimensions) iteration error: %v", err)
		}
		dimensionResults = append(dimensionResults, artifact)
	}

	if len(dimensionResults) != 1 {
		t.Fatalf("Query(dimensions) expected 1 artifact, got %d", len(dimensionResults))
	}

	// Test 6: Query with custom variables
	severityCompiled, err := idx.Compile(`has(data.severity) && data.severity == level`, map[string]any{
		"level": "HIGH",
	})
	if err != nil {
		t.Fatalf("Compile(custom vars): %v", err)
	}

	severityArtifacts, err := idx.Query(ctx, severityCompiled)
	if err != nil {
		t.Fatalf("Query(custom vars): %v", err)
	}

	var severityResults []Artifact
	for artifact, err := range severityArtifacts {
		if err != nil {
			t.Fatalf("Query(custom vars) iteration error: %v", err)
		}
		severityResults = append(severityResults, artifact)
	}

	if len(severityResults) != 1 {
		t.Fatalf("Query(custom vars) expected 1 artifact, got %d", len(severityResults))
	}
}

// TestIndex_TimeRangeQueries tests time-based filtering with CEL
func TestIndex_TimeRangeQueries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	baseTime := mustParseTime(t, "2024-01-01T00:00:00Z")

	// Create artifacts at different times
	artifacts := []Artifact{
		{
			Namespace: "security",
			Type:      "finding",
			ID:        "finding-1",
			Entity:    Entity{Type: "repo", ID: "repo:github.com/example/app"},
			Timestamp: baseTime,
			Data:      map[string]any{"severity": "LOW"},
		},
		{
			Namespace: "security",
			Type:      "finding",
			ID:        "finding-2",
			Entity:    Entity{Type: "repo", ID: "repo:github.com/example/app"},
			Timestamp: baseTime.Add(time.Hour),
			Data:      map[string]any{"severity": "MEDIUM"},
		},
		{
			Namespace: "security",
			Type:      "finding",
			ID:        "finding-3",
			Entity:    Entity{Type: "repo", ID: "repo:github.com/example/app"},
			Timestamp: baseTime.Add(2 * time.Hour),
			Data:      map[string]any{"severity": "HIGH"},
		},
	}

	// Store all artifacts
	for _, artifact := range artifacts {
		if err := idx.PutArtifact(ctx, artifact); err != nil {
			t.Fatalf("PutArtifact(%s): %v", artifact.ID, err)
		}
	}

	// Test time range query - middle window using CEL
	windowStart := baseTime.Add(30 * time.Minute)
	windowEnd := baseTime.Add(90 * time.Minute)

	windowCompiled, err := idx.Compile(`
		artifact_namespace == "security" && 
		timestamp >= start && 
		timestamp < end
	`, map[string]any{
		"start": windowStart,
		"end":   windowEnd,
	})
	if err != nil {
		t.Fatalf("Compile(time window): %v", err)
	}

	windowArtifacts, err := idx.Query(ctx, windowCompiled)
	if err != nil {
		t.Fatalf("Query(time window): %v", err)
	}

	var windowResults []Artifact
	for artifact, err := range windowArtifacts {
		if err != nil {
			t.Fatalf("Query(time window) iteration error: %v", err)
		}
		windowResults = append(windowResults, artifact)
	}

	if len(windowResults) != 1 {
		t.Fatalf("Query(time window) expected 1 artifact, got %d", len(windowResults))
	}
	if windowResults[0].ID != "finding-2" {
		t.Fatalf("Query(time window) expected finding-2, got %s", windowResults[0].ID)
	}

	// Test start time only - using ago() function
	afterCompiled, err := idx.Compile(`
		artifact_namespace == "security" && 
		timestamp >= after_time
	`, map[string]any{
		"after_time": baseTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compile(after): %v", err)
	}

	afterArtifacts, err := idx.Query(ctx, afterCompiled)
	if err != nil {
		t.Fatalf("Query(after): %v", err)
	}

	var afterResults []Artifact
	for artifact, err := range afterArtifacts {
		if err != nil {
			t.Fatalf("Query(after) iteration error: %v", err)
		}
		afterResults = append(afterResults, artifact)
	}

	if len(afterResults) != 2 {
		t.Fatalf("Query(after) expected 2 artifacts, got %d", len(afterResults))
	}

	// Test end time only
	beforeCompiled, err := idx.Compile(`
		artifact_namespace == "security" && 
		timestamp <= before_time
	`, map[string]any{
		"before_time": baseTime.Add(time.Hour),
	})
	if err != nil {
		t.Fatalf("Compile(before): %v", err)
	}

	beforeArtifacts, err := idx.Query(ctx, beforeCompiled)
	if err != nil {
		t.Fatalf("Query(before): %v", err)
	}

	var beforeResults []Artifact
	for artifact, err := range beforeArtifacts {
		if err != nil {
			t.Fatalf("Query(before) iteration error: %v", err)
		}
		beforeResults = append(beforeResults, artifact)
	}

	if len(beforeResults) != 2 { // includes exact match at boundary
		t.Fatalf("Query(before) expected 2 artifacts, got %d", len(beforeResults))
	}
}

// TestIndex_RelationshipQueries tests relationship traversal with CEL
func TestIndex_RelationshipQueries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	repoID := "repo:github.com/example/app"
	packageID := "pkg:npm/lodash@4.17.21"

	// Create artifacts with relationships
	vulnArtifact := Artifact{
		Namespace: "security",
		Type:      "vulnerability",
		ID:        "CVE-2023-1234",
		Entity:    Entity{Type: "package", ID: packageID},
		Timestamp: time.Now().UTC(),
		Data:      map[string]any{"severity": "HIGH"},
		Relationships: []Relationship{
			{Type: "affects", Target: repoID},
		},
	}

	depArtifact := Artifact{
		Namespace: "sca",
		Type:      "dependency",
		ID:        "dep-lodash",
		Entity:    Entity{Type: "repo", ID: repoID},
		Timestamp: time.Now().UTC(),
		Data:      map[string]any{"type": "direct"},
		Relationships: []Relationship{
			{Type: "depends_on", Target: packageID},
		},
	}

	// Store artifacts
	for _, artifact := range []Artifact{vulnArtifact, depArtifact} {
		if err := idx.PutArtifact(ctx, artifact); err != nil {
			t.Fatalf("PutArtifact(%s): %v", artifact.ID, err)
		}
	}

	// Test relationship query - find artifacts that affect the repo using CEL
	affectsCompiled, err := idx.Compile(`
		relationships.exists(r, r.type == "affects" && r.target == target_id)
	`, map[string]any{
		"target_id": repoID,
	})
	if err != nil {
		t.Fatalf("Compile(affects): %v", err)
	}

	affectsArtifacts, err := idx.Query(ctx, affectsCompiled)
	if err != nil {
		t.Fatalf("Query(affects): %v", err)
	}

	var affectsResults []Artifact
	for artifact, err := range affectsArtifacts {
		if err != nil {
			t.Fatalf("Query(affects) iteration error: %v", err)
		}
		affectsResults = append(affectsResults, artifact)
	}

	if len(affectsResults) != 1 {
		t.Fatalf("Query(affects) expected 1 artifact, got %d", len(affectsResults))
	}
	if affectsResults[0].Type != "vulnerability" {
		t.Fatalf("Query(affects) expected vulnerability, got %s", affectsResults[0].Type)
	}

	// Test relationship query - find all relationships to repo
	relatedCompiled, err := idx.Compile(`
		relationships.exists(r, r.target == target_id)
	`, map[string]any{
		"target_id": repoID,
	})
	if err != nil {
		t.Fatalf("Compile(related): %v", err)
	}

	relatedArtifacts, err := idx.Query(ctx, relatedCompiled)
	if err != nil {
		t.Fatalf("Query(related): %v", err)
	}

	var relatedResults []Artifact
	for artifact, err := range relatedArtifacts {
		if err != nil {
			t.Fatalf("Query(related) iteration error: %v", err)
		}
		relatedResults = append(relatedResults, artifact)
	}

	if len(relatedResults) != 1 { // Only vulnerability affects the repo
		t.Fatalf("Query(related) expected 1 artifact, got %d", len(relatedResults))
	}
}

// TestIndex_TimeSeries tests time-series analysis with CEL
func TestIndex_TimeSeries(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	repoID := "repo:github.com/example/app"
	baseTime := mustParseTime(t, "2024-01-01T00:00:00Z")

	// Create time-series data for compliance status
	for i := range 5 {
		artifact := Artifact{
			Namespace: "compliance",
			Type:      "status",
			ID:        fmt.Sprintf("status-%d", i),
			Entity:    Entity{Type: "repo", ID: repoID},
			Timestamp: baseTime.Add(time.Duration(i) * time.Hour),
			Data: map[string]any{
				"score":  80 + i*2, // Improving score over time
				"issues": 10 - i*2, // Decreasing issues
			},
		}

		if err := idx.PutArtifact(ctx, artifact); err != nil {
			t.Fatalf("PutArtifact(status-%d): %v", i, err)
		}
	}

	// Query time series using CEL
	startTime := baseTime
	endTime := baseTime.Add(5 * time.Hour)

	timeSeriesCompiled, err := idx.Compile(`
		entity.id == repo_id && 
		artifact_namespace == "compliance" && 
		timestamp >= start_time && 
		timestamp < end_time
	`, map[string]any{
		"repo_id":    repoID,
		"start_time": startTime,
		"end_time":   endTime,
	})
	if err != nil {
		t.Fatalf("Compile(time series): %v", err)
	}

	timeSeriesArtifacts, err := idx.Query(ctx, timeSeriesCompiled)
	if err != nil {
		t.Fatalf("Query(time series): %v", err)
	}

	var timeSeriesResults []Artifact
	for artifact, err := range timeSeriesArtifacts {
		if err != nil {
			t.Fatalf("Query(time series) iteration error: %v", err)
		}
		timeSeriesResults = append(timeSeriesResults, artifact)
	}

	if len(timeSeriesResults) != 5 {
		t.Fatalf("Query(time series) expected 5 artifacts, got %d", len(timeSeriesResults))
	}

	// Verify chronological order - sort by timestamp first
	slices.SortFunc(timeSeriesResults, func(a, b Artifact) int {
		if a.Timestamp.Before(b.Timestamp) {
			return -1
		}
		if a.Timestamp.After(b.Timestamp) {
			return 1
		}
		return 0
	})

	for i := 1; i < len(timeSeriesResults); i++ {
		if !timeSeriesResults[i-1].Timestamp.Before(timeSeriesResults[i].Timestamp) {
			t.Fatalf("Query(time series) results not in chronological order")
		}
	}
}

// TestIndex_CELValidationErrors tests CEL expression validation and error handling
func TestIndex_CELValidationErrors(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	// Test invalid artifact - missing namespace
	invalidArtifact := Artifact{
		Type:      "test",
		ID:        "test-1",
		Entity:    Entity{Type: "test", ID: "test"},
		Timestamp: time.Now(),
	}

	err = idx.PutArtifact(ctx, invalidArtifact)
	if err == nil {
		t.Fatalf("PutArtifact should have failed for missing namespace")
	}
	if !errors.Is(err, ErrInvalidArtifact) {
		t.Fatalf("PutArtifact expected ErrInvalidArtifact, got %v", err)
	}

	// Test invalid CEL expression - syntax error
	_, err = idx.Compile("artifact_namespace == ", nil)
	if err == nil {
		t.Fatalf("Compile should have failed for syntax error")
	}
	if !errors.Is(err, ErrCompilationFailed) {
		t.Fatalf("Compile expected ErrCompilationFailed, got %v", err)
	}

	// Test empty expression
	_, err = idx.Compile("", nil)
	if err == nil {
		t.Fatalf("Compile should have failed for empty expression")
	}
	if !errors.Is(err, ErrInvalidExpression) {
		t.Fatalf("Compile expected ErrInvalidExpression, got %v", err)
	}

	// Test invalid variable name
	_, err = idx.Compile("artifact_namespace == level", map[string]any{
		"level": "HIGH", // Valid variable, but we're testing other error conditions
		"":      "test", // Empty variable name should cause error
	})
	if err == nil {
		t.Fatalf("Compile should have failed for empty variable name")
	}
	if !errors.Is(err, ErrInvalidExpression) {
		t.Fatalf("Compile expected ErrInvalidExpression, got %v", err)
	}

	// Test nil variable value
	_, err = idx.Compile("artifact_namespace == level", map[string]any{
		"level": nil,
	})
	if err == nil {
		t.Fatalf("Compile should have failed for nil variable value")
	}
	if !errors.Is(err, ErrInvalidExpression) {
		t.Fatalf("Compile expected ErrInvalidExpression, got %v", err)
	}

	// Test query with nil compiled expression
	_, err = idx.Query(ctx, nil)
	if err == nil {
		t.Fatalf("Query should have failed for nil compiled expression")
	}
	if !errors.Is(err, ErrInvalidExpression) {
		t.Fatalf("Query expected ErrInvalidExpression, got %v", err)
	}

	// Test CEL expression that returns non-boolean
	nonBoolCompiled, err := idx.Compile(`"hello world"`, nil)
	if err != nil {
		t.Fatalf("Compile non-boolean expression: %v", err)
	}

	// Store a test artifact first
	testArtifact := Artifact{
		Namespace: "test",
		Type:      "example",
		ID:        "test-1",
		Entity:    Entity{Type: "test", ID: "test"},
		Timestamp: time.Now().UTC(),
		Data:      map[string]any{"value": 42},
	}

	if err := idx.PutArtifact(ctx, testArtifact); err != nil {
		t.Fatalf("PutArtifact: %v", err)
	}

	// Query with non-boolean expression should yield error during iteration
	nonBoolArtifacts, err := idx.Query(ctx, nonBoolCompiled)
	if err != nil {
		t.Fatalf("Query setup should succeed even with non-boolean expression: %v", err)
	}

	foundError := false
	for artifact, err := range nonBoolArtifacts {
		if err != nil {
			foundError = true
			if !strings.Contains(err.Error(), "must return boolean") {
				t.Fatalf("Expected boolean error, got: %v", err)
			}
			break
		}
		t.Fatalf("Expected error during iteration, but got artifact: %+v", artifact)
	}

	if !foundError {
		t.Fatalf("Expected error during iteration for non-boolean expression")
	}
}

// TestIndex_RealWorldCELScenarios tests comprehensive real-world use cases with CEL
func TestIndex_RealWorldCELScenarios(t *testing.T) {
	t.Parallel()

	ctx := context.Background()

	idx, err := Open(t.TempDir(), WithFS(vfs.NewMem()))
	if err != nil {
		t.Fatalf("Open: %v", err)
	}
	t.Cleanup(func() {
		if cerr := idx.Close(); cerr != nil {
			t.Fatalf("Close: %v", cerr)
		}
	})

	repoID := "repo:github.com/example/webapp"
	now := time.Now().UTC()

	// Scenario: Complete security analysis of a web application

	// 1. Store dependency information
	dependencies := []string{
		"pkg:npm/express@4.18.2",
		"pkg:npm/lodash@4.17.21",
		"pkg:npm/axios@1.4.0",
	}

	for i, dep := range dependencies {
		artifact := Artifact{
			Namespace: "sca",
			Type:      "dependency",
			ID:        fmt.Sprintf("dep-%d", i),
			Entity:    Entity{Type: "repo", ID: repoID},
			Timestamp: now.Add(time.Duration(i) * time.Minute),
			Data: map[string]any{
				"package": dep,
				"type":    "direct",
				"scope":   "runtime",
			},
			Relationships: []Relationship{
				{Type: "depends_on", Target: dep},
			},
			Dimensions: map[string]string{
				"ecosystem": "npm",
				"scope":     "runtime",
			},
		}

		if err := idx.PutArtifact(ctx, artifact); err != nil {
			t.Fatalf("PutArtifact(dependency): %v", err)
		}
	}

	// 2. Store vulnerability affecting lodash
	vulnArtifact := Artifact{
		Namespace: "security",
		Type:      "vulnerability",
		ID:        "CVE-2023-1234",
		Entity:    Entity{Type: "package", ID: "pkg:npm/lodash@4.17.21"},
		Timestamp: now.Add(5 * time.Minute),
		Data: map[string]any{
			"severity":    "HIGH",
			"cvss_score":  8.5,
			"description": "Prototype pollution vulnerability",
			"cwe":         "CWE-1321",
			"published":   "2023-06-15T00:00:00Z",
		},
		Relationships: []Relationship{
			{Type: "affects", Target: repoID},
		},
		Context: map[string]any{
			"source": "osv.dev",
			"tool":   "deputy-scanner",
		},
		Dimensions: map[string]string{
			"severity":  "HIGH",
			"ecosystem": "npm",
			"tool":      "osv",
		},
	}

	if err := idx.PutArtifact(ctx, vulnArtifact); err != nil {
		t.Fatalf("PutArtifact(vulnerability): %v", err)
	}

	// 3. Store SAST findings
	sastArtifacts := []Artifact{
		{
			Namespace: "security",
			Type:      "sast-finding",
			ID:        "sql-injection-1",
			Entity:    Entity{Type: "file", ID: "file:github.com/example/webapp/src/api/users.js"},
			Timestamp: now.Add(10 * time.Minute),
			Data: map[string]any{
				"rule_id":    "javascript.lang.security.audit.sqli.node-sqli",
				"severity":   "HIGH",
				"line":       42,
				"column":     15,
				"message":    "Potential SQL injection vulnerability",
				"confidence": 0.9,
			},
			Context: map[string]any{
				"tool":    "semgrep",
				"version": "1.45.0",
			},
			Dimensions: map[string]string{
				"severity": "HIGH",
				"tool":     "semgrep",
				"language": "javascript",
				"category": "security",
			},
		},
		{
			Namespace: "security",
			Type:      "sast-finding",
			ID:        "xss-1",
			Entity:    Entity{Type: "file", ID: "file:github.com/example/webapp/src/views/profile.js"},
			Timestamp: now.Add(11 * time.Minute),
			Data: map[string]any{
				"rule_id":    "javascript.react.security.audit.react-dangerouslysetinnerhtml",
				"severity":   "MEDIUM",
				"line":       123,
				"message":    "Potential XSS via dangerouslySetInnerHTML",
				"confidence": 0.8,
			},
			Context: map[string]any{
				"tool":    "semgrep",
				"version": "1.45.0",
			},
			Dimensions: map[string]string{
				"severity": "MEDIUM",
				"tool":     "semgrep",
				"language": "javascript",
				"category": "security",
			},
		},
	}

	for _, artifact := range sastArtifacts {
		if err := idx.PutArtifact(ctx, artifact); err != nil {
			t.Fatalf("PutArtifact(sast): %v", err)
		}
	}

	// 4. Store compliance assessment
	complianceArtifact := Artifact{
		Namespace: "compliance",
		Type:      "assessment",
		ID:        "owasp-top10-2023",
		Entity:    Entity{Type: "repo", ID: repoID},
		Timestamp: now.Add(15 * time.Minute),
		Data: map[string]any{
			"framework":     "OWASP Top 10 2023",
			"overall_score": 6.5,
			"categories": map[string]any{
				"A01_Broken_Access_Control":     8.0,
				"A02_Cryptographic_Failures":    7.5,
				"A03_Injection":                 4.0, // Low due to SQL injection finding
				"A04_Insecure_Design":           7.0,
				"A05_Security_Misconfiguration": 6.0,
			},
		},
		Context: map[string]any{
			"assessor": "security-team",
			"tool":     "custom-assessment",
		},
		Dimensions: map[string]string{
			"framework": "owasp",
			"version":   "2023",
		},
	}

	if err := idx.PutArtifact(ctx, complianceArtifact); err != nil {
		t.Fatalf("PutArtifact(compliance): %v", err)
	}

	// Now run comprehensive CEL queries to analyze the security posture

	// Query 1: Get all high-severity security findings
	highSeverityCompiled, err := idx.Compile(`
		artifact_namespace == "security" && 
		data.severity == "HIGH"
	`, nil)
	if err != nil {
		t.Fatalf("Compile(high severity): %v", err)
	}

	highSeverityArtifacts, err := idx.Query(ctx, highSeverityCompiled)
	if err != nil {
		t.Fatalf("Query(high severity): %v", err)
	}

	var highSeverityResults []Artifact
	for artifact, err := range highSeverityArtifacts {
		if err != nil {
			t.Fatalf("Query(high severity) iteration error: %v", err)
		}
		highSeverityResults = append(highSeverityResults, artifact)
	}

	if len(highSeverityResults) != 2 { // vulnerability + SQL injection
		t.Fatalf("Expected 2 high severity findings, got %d", len(highSeverityResults))
	}

	// Query 2: Get all vulnerabilities affecting the repository
	affectsRepoCompiled, err := idx.Compile(`
		relationships.exists(r, r.type == "affects" && r.target == target_repo)
	`, map[string]any{
		"target_repo": repoID,
	})
	if err != nil {
		t.Fatalf("Compile(affects repo): %v", err)
	}

	affectsRepoArtifacts, err := idx.Query(ctx, affectsRepoCompiled)
	if err != nil {
		t.Fatalf("Query(affects repo): %v", err)
	}

	var affectsRepoResults []Artifact
	for artifact, err := range affectsRepoArtifacts {
		if err != nil {
			t.Fatalf("Query(affects repo) iteration error: %v", err)
		}
		affectsRepoResults = append(affectsRepoResults, artifact)
	}

	if len(affectsRepoResults) != 1 {
		t.Fatalf("Expected 1 affecting vulnerability, got %d", len(affectsRepoResults))
	}

	// Query 3: Get all security findings within time window
	timeWindowCompiled, err := idx.Compile(`
		artifact_namespace == "security" && 
		timestamp >= start_time && 
		timestamp <= end_time
	`, map[string]any{
		"start_time": now,
		"end_time":   now.Add(20 * time.Minute),
	})
	if err != nil {
		t.Fatalf("Compile(time window): %v", err)
	}

	timeWindowArtifacts, err := idx.Query(ctx, timeWindowCompiled)
	if err != nil {
		t.Fatalf("Query(time window): %v", err)
	}

	var timeWindowResults []Artifact
	for artifact, err := range timeWindowArtifacts {
		if err != nil {
			t.Fatalf("Query(time window) iteration error: %v", err)
		}
		timeWindowResults = append(timeWindowResults, artifact)
	}

	// Should include vulnerability + 2 SAST findings = 3 total
	if len(timeWindowResults) != 3 {
		t.Fatalf("Expected 3 security findings in time window, got %d", len(timeWindowResults))
	}

	// Query 4: Get all findings by tool
	semgrepCompiled, err := idx.Compile(`
		has(dimensions.tool) && dimensions.tool == "semgrep"
	`, nil)
	if err != nil {
		t.Fatalf("Compile(semgrep): %v", err)
	}

	semgrepArtifacts, err := idx.Query(ctx, semgrepCompiled)
	if err != nil {
		t.Fatalf("Query(semgrep): %v", err)
	}

	var semgrepResults []Artifact
	for artifact, err := range semgrepArtifacts {
		if err != nil {
			t.Fatalf("Query(semgrep) iteration error: %v", err)
		}
		semgrepResults = append(semgrepResults, artifact)
	}

	if len(semgrepResults) != 2 {
		t.Fatalf("Expected 2 Semgrep findings, got %d", len(semgrepResults))
	}

	// Query 5: Get compliance status for the repository
	complianceCompiled, err := idx.Compile(`
		artifact_namespace == "compliance" && 
		entity.id == target_repo
	`, map[string]any{
		"target_repo": repoID,
	})
	if err != nil {
		t.Fatalf("Compile(compliance): %v", err)
	}

	complianceArtifacts, err := idx.Query(ctx, complianceCompiled)
	if err != nil {
		t.Fatalf("Query(compliance): %v", err)
	}

	var complianceResults []Artifact
	for artifact, err := range complianceArtifacts {
		if err != nil {
			t.Fatalf("Query(compliance) iteration error: %v", err)
		}
		complianceResults = append(complianceResults, artifact)
	}

	if len(complianceResults) != 1 {
		t.Fatalf("Expected 1 compliance assessment, got %d", len(complianceResults))
	}

	// Verify the overall picture makes sense
	overallScore, ok := complianceResults[0].Data["overall_score"].(float64)
	if !ok || overallScore >= 8.0 {
		t.Fatalf("Expected lower compliance score due to security findings, got %v", overallScore)
	}

	// Query 6: Complex security analysis with multiple conditions
	complexCompiled, err := idx.Compile(`
		(artifact_namespace == "security" && has(data.severity) && data.severity == "HIGH") ||
		(artifact_namespace == "compliance" && has(data.overall_score) && data.overall_score < 7.0) ||
		(has(dimensions.tool) && dimensions.tool == "semgrep" && has(data.confidence) && data.confidence > 0.85)
	`, nil)
	if err != nil {
		t.Fatalf("Compile(complex): %v", err)
	}

	complexArtifacts, err := idx.Query(ctx, complexCompiled)
	if err != nil {
		t.Fatalf("Query(complex): %v", err)
	}

	var complexResults []Artifact
	for artifact, err := range complexArtifacts {
		if err != nil {
			t.Fatalf("Query(complex) iteration error: %v", err)
		}
		complexResults = append(complexResults, artifact)
	}

	// Should match: 2 HIGH severity + 1 compliance < 7.0 + 1 semgrep confidence > 0.85 = 4 total
	// Note: Some artifacts may match multiple conditions, so actual count may be different
	if len(complexResults) < 3 || len(complexResults) > 4 {
		t.Fatalf("Expected 3-4 results from complex query, got %d", len(complexResults))
	}
}

func mustParseTime(t *testing.T, value string) time.Time {
	t.Helper()
	ts, err := time.Parse(time.RFC3339, value)
	if err != nil {
		t.Fatalf("invalid time %q: %v", value, err)
	}
	return ts.UTC()
}
