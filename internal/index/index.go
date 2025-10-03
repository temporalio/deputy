// Package index provides a flexible, multi-dimensional time-series index for
// comprehensive software analysis and security intelligence. It uses PebbleDB
// as the underlying storage engine to efficiently store and query analysis
// artifacts, security findings, and metadata across the entire software
// development lifecycle.
//
// The index stores artifacts with dimensions and relationships rather than
// predefined schemas, allowing it to adapt to new analysis types, security
// tools, and data sources without structural changes.
//
// Core concepts:
//   - Artifact: Any piece of analysis data (finding, dependency, metric, etc.)
//   - Entity: The subject being analyzed (repository, package, file, etc.)
//   - Relationship: Connections between artifacts and entities
//   - Timeline: Time-series tracking of changes and observations
//   - Context: Environmental and conditional metadata
package index

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"iter"
	"time"

	"github.com/cockroachdb/pebble/v2"
	"github.com/cockroachdb/pebble/v2/vfs"
	"github.com/google/cel-go/cel"
	"github.com/google/cel-go/common/operators"
	"github.com/google/cel-go/common/types"
	"github.com/google/cel-go/common/types/ref"
	exprpb "google.golang.org/genproto/googleapis/api/expr/v1alpha1"
)

const (
	// keySep is the null byte separator used between key components
	keySep = byte(0x00)
	// defaultMaxOpenFiles is the default maximum number of open files for PebbleDB
	defaultMaxOpenFiles = 2000
	// timeEncoding specifies the RFC3339Nano format used for time serialization
	timeEncoding = time.RFC3339Nano
)

var (
	// ErrInvalidArtifact is returned when an Artifact is invalid
	ErrInvalidArtifact = errors.New("index: invalid artifact")
	// ErrInvalidQuery is returned when a Query is invalid
	ErrInvalidQuery = errors.New("index: invalid query")
	// ErrInvalidEntity is returned when an Entity identifier is invalid
	ErrInvalidEntity = errors.New("index: invalid entity")
	// ErrInvalidExpression is returned when a CEL expression is invalid
	ErrInvalidExpression = errors.New("index: invalid CEL expression")
	// ErrCompilationFailed is returned when CEL expression compilation fails
	ErrCompilationFailed = errors.New("index: CEL compilation failed")
)

// Option is a function type for configuring PebbleDB options during index creation.
type Option func(*pebble.Options)

// Index represents a flexible, multi-dimensional time-series index for analysis artifacts.
// It wraps a PebbleDB instance to provide efficient storage and retrieval of any analysis
// data organized by namespace, type, entity, time, and custom dimensions.
type Index struct {
	db     *pebble.DB
	celEnv *cel.Env
}

// CompiledExpression represents a compiled CEL expression that can be reused for multiple queries.
type CompiledExpression struct {
	program    cel.Program
	ast        *cel.Ast
	vars       map[string]any
	expression string // Store original expression for optimization analysis
}

// Entity represents any subject that can be analyzed (repository, package, file, etc.).
type Entity struct {
	Type     string         `json:"type"`               // Entity type (repo, package, file, etc.)
	ID       string         `json:"id"`                 // Unique identifier within type
	Metadata map[string]any `json:"metadata,omitempty"` // Additional entity metadata
}

// Relationship represents a connection between artifacts or entities.
type Relationship struct {
	Type     string         `json:"type"`               // Relationship type (affects, depends_on, etc.)
	Target   string         `json:"target"`             // Target entity or artifact ID
	Metadata map[string]any `json:"metadata,omitempty"` // Additional relationship metadata
}

// Artifact represents any piece of analysis data with flexible schema.
type Artifact struct {
	Namespace     string            `json:"namespace"`               // Analysis domain (security, quality, etc.)
	Type          string            `json:"type"`                    // Artifact type within namespace
	ID            string            `json:"id"`                      // Unique identifier within type
	Entity        Entity            `json:"entity"`                  // Subject being analyzed
	Timestamp     time.Time         `json:"timestamp"`               // When observed/created
	Data          map[string]any    `json:"data"`                    // Artifact-specific data
	Relationships []Relationship    `json:"relationships,omitempty"` // Related artifacts/entities
	Context       map[string]any    `json:"context,omitempty"`       // Environmental metadata
	Dimensions    map[string]string `json:"dimensions,omitempty"`    // Additional indexable dimensions
}

// TimeRange represents a time window for filtering queries.
type TimeRange struct {
	Start time.Time `json:"start"` // Start time (inclusive)
	End   time.Time `json:"end"`   // End time (exclusive)
}

// Open creates a new Index instance backed by a PebbleDB database at the specified path.
// It accepts optional configuration functions to customize the underlying database options.
//
// The path parameter specifies where the database files will be stored.
// If the directory doesn't exist, it will be created.
//
// Example:
//
//	idx, err := Open("/path/to/db", WithMaxOpenFiles(1000))
//	if err != nil {
//		log.Fatal(err)
//	}
//	defer idx.Close()
func Open(path string, opts ...Option) (*Index, error) {
	// Start with default PebbleDB configuration
	pebbleOpts := defaultPebbleOptions()
	// Apply any custom options provided by the caller
	for _, opt := range opts {
		opt(pebbleOpts)
	}
	db, err := pebble.Open(path, pebbleOpts)
	if err != nil {
		return nil, fmt.Errorf("open pebble db: %w", err)
	}

	// Initialize CEL environment with artifact-specific types and functions
	celEnv, err := initializeCELEnvironment()
	if err != nil {
		db.Close()
		return nil, fmt.Errorf("initialize CEL environment: %w", err)
	}

	return &Index{
		db:     db,
		celEnv: celEnv,
	}, nil
}

// defaultPebbleOptions returns the default configuration for PebbleDB.
// This includes setting up the default filesystem and reasonable defaults
// for production use.
func defaultPebbleOptions() *pebble.Options {
	return &pebble.Options{
		FS:           vfs.Default,
		MaxOpenFiles: defaultMaxOpenFiles,
	}
}

// initializeCELEnvironment creates a CEL environment with artifact-specific types and functions.
func initializeCELEnvironment() (*cel.Env, error) {
	// Define CEL environment with types for Artifact, Entity, and Relationship
	env, err := cel.NewEnv(
		// Variable declarations for artifact fields - avoid reserved words
		cel.Variable("artifact_namespace", cel.StringType),
		cel.Variable("artifact_type", cel.StringType),
		cel.Variable("artifact_id", cel.StringType),
		cel.Variable("entity", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("timestamp", cel.TimestampType),
		cel.Variable("data", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("context", cel.MapType(cel.StringType, cel.DynType)),
		cel.Variable("dimensions", cel.MapType(cel.StringType, cel.StringType)),
		cel.Variable("relationships", cel.ListType(cel.MapType(cel.StringType, cel.DynType))),

		// Custom security functions
		cel.Function("severity_gte",
			cel.Overload("severity_gte_string", []*cel.Type{cel.StringType}, cel.BoolType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					severity := arg.Value().(string)
					return types.Bool(severityToLevel(severity) >= severityToLevel("MEDIUM"))
				}),
			),
		),

		// Time helper functions
		cel.Function("ago",
			cel.Overload("ago_duration", []*cel.Type{cel.DurationType}, cel.TimestampType,
				cel.UnaryBinding(func(arg ref.Val) ref.Val {
					duration := arg.Value().(time.Duration)
					return types.Timestamp{Time: time.Now().UTC().Add(-duration)}
				}),
			),
		),
	)

	if err != nil {
		return nil, fmt.Errorf("create CEL environment: %w", err)
	}

	return env, nil
}

// severityToLevel converts severity strings to numeric levels for comparison.
func severityToLevel(severity string) int {
	switch severity {
	case "LOW":
		return 1
	case "MEDIUM":
		return 2
	case "HIGH":
		return 3
	case "CRITICAL":
		return 4
	default:
		return 0
	}
}

// WithFS returns an Option that configures the filesystem for PebbleDB.
// This is useful for testing with in-memory filesystems or custom filesystem implementations.
func WithFS(fs vfs.FS) Option {
	return func(o *pebble.Options) {
		o.FS = fs
	}
}

// WithMaxOpenFiles returns an Option that sets the maximum number of open files
// that PebbleDB can have at any given time. Higher values can improve performance
// for large databases at the cost of using more file descriptors.
func WithMaxOpenFiles(n int) Option {
	return func(o *pebble.Options) {
		o.MaxOpenFiles = n
	}
}

// Close safely closes the index and its underlying database connection.
// It's safe to call Close multiple times or on a nil Index.
// This method should be called when the index is no longer needed to free resources.
func (idx *Index) Close() error {
	if idx == nil || idx.db == nil {
		return nil
	}
	return idx.db.Close()
}

// DB returns the underlying PebbleDB instance for advanced operations.
// This method is provided for cases where direct database access is needed,
// but should be used carefully to avoid corrupting the index structure.
// Returns nil if the Index is nil.
func (idx *Index) DB() *pebble.DB {
	if idx == nil {
		return nil
	}
	return idx.db
}

// Compile validates and compiles a CEL expression with optional custom variables.
// The compiled expression can be reused for multiple queries for better performance.
//
// The expression parameter should be a valid CEL expression that operates on artifact fields.
// The vars parameter allows injection of custom variables into the expression context.
//
// Example:
//
//	compiled, err := idx.Compile(`namespace == "security" && data.severity == level`,
//		map[string]any{"level": "HIGH"})
//	if err != nil {
//		log.Fatal(err)
//	}
func (idx *Index) Compile(expression string, vars map[string]any) (*CompiledExpression, error) {
	if idx == nil || idx.celEnv == nil {
		return nil, errors.New("index: nil index or CEL environment")
	}

	if expression == "" {
		return nil, fmt.Errorf("%w: expression cannot be empty", ErrInvalidExpression)
	}

	// Validate variables if provided
	for key, value := range vars {
		if key == "" {
			return nil, fmt.Errorf("%w: variable name cannot be empty", ErrInvalidExpression)
		}
		if value == nil {
			return nil, fmt.Errorf("%w: variable %q cannot be nil", ErrInvalidExpression, key)
		}
	}

	// Create custom environment with user variables
	env := idx.celEnv
	if len(vars) > 0 {
		// Create new environment extending the base environment with user variables
		var options []cel.EnvOption
		for key, value := range vars {
			// Determine CEL type based on Go type
			var celType *cel.Type
			switch value.(type) {
			case string:
				celType = cel.StringType
			case int, int64, int32:
				celType = cel.IntType
			case float64, float32:
				celType = cel.DoubleType
			case bool:
				celType = cel.BoolType
			case time.Time:
				celType = cel.TimestampType
			default:
				celType = cel.DynType // Dynamic type for complex objects
			}
			options = append(options, cel.Variable(key, celType))
		}

		var err error
		env, err = idx.celEnv.Extend(options...)
		if err != nil {
			return nil, fmt.Errorf("%w: extend environment: %v", ErrCompilationFailed, err)
		}
	}

	// Parse the CEL expression
	ast, issues := env.Compile(expression)
	if issues != nil && issues.Err() != nil {
		return nil, fmt.Errorf("%w: %v", ErrCompilationFailed, issues.Err())
	}

	// Create the CEL program
	program, err := env.Program(ast)
	if err != nil {
		return nil, fmt.Errorf("%w: create program: %v", ErrCompilationFailed, err)
	}

	return &CompiledExpression{
		program:    program,
		ast:        ast,
		vars:       vars,
		expression: expression,
	}, nil
}

// Query executes a compiled CEL expression against all artifacts in the index.
// It returns an iterator that yields artifacts matching the expression and any errors encountered.
//
// The first error returned indicates setup/compilation issues.
// The iterator yields individual artifacts and per-item errors during evaluation.
//
// Example:
//
//	artifacts, err := idx.Query(ctx, compiled)
//	if err != nil {
//		log.Fatal("Query setup failed:", err)
//	}
//
//	for artifact, err := range artifacts {
//		if err != nil {
//			log.Printf("Item error: %v", err)
//			continue
//		}
//		// Process artifact...
//	}
func (idx *Index) Query(ctx context.Context, compiled *CompiledExpression) (iter.Seq2[Artifact, error], error) {
	if idx == nil || idx.db == nil {
		return nil, errors.New("index: nil index")
	}

	if compiled == nil {
		return nil, fmt.Errorf("%w: compiled expression cannot be nil", ErrInvalidExpression)
	}

	// Return an iterator function that will be called when range loop starts
	return func(yield func(Artifact, error) bool) {
		// Optimize iterator options based on CEL expression analysis
		iterOpts := idx.optimizeIteratorOptions(compiled)

		iter, err := idx.db.NewIterWithContext(ctx, iterOpts)
		if err != nil {
			yield(Artifact{}, fmt.Errorf("create iterator: %w", err))
			return
		}
		defer iter.Close()

		// Iterate through all artifacts
		for valid := iter.First(); valid; valid = iter.Next() {
			// Check for context cancellation
			if err := checkCtx(ctx); err != nil {
				yield(Artifact{}, err)
				return
			}

			if err := iter.Error(); err != nil {
				yield(Artifact{}, fmt.Errorf("iterate: %w", err))
				return
			}

			raw := iter.Value()
			if raw == nil {
				continue
			}

			// Deserialize artifact
			var artifact Artifact
			if err := json.Unmarshal(raw, &artifact); err != nil {
				if !yield(Artifact{}, fmt.Errorf("unmarshal artifact: %w", err)) {
					return // Consumer requested stop
				}
				continue
			}

			// Evaluate CEL expression against artifact
			matches, err := idx.evaluateExpression(compiled, artifact)
			if err != nil {
				if !yield(artifact, fmt.Errorf("evaluate expression: %w", err)) {
					return // Consumer requested stop
				}
				continue
			}

			// Yield artifact if it matches
			if matches {
				if !yield(artifact, nil) {
					return // Consumer requested stop
				}
			}
		}
	}, nil
}

// optimizeIteratorOptions analyzes the compiled CEL expression to optimize PebbleDB iterator performance.
// It extracts filters from the CEL AST to set bounds and skip functions when possible.
func (idx *Index) optimizeIteratorOptions(compiled *CompiledExpression) *pebble.IterOptions {
	opts := &pebble.IterOptions{}

	// Convert AST to checked expression for analysis
	checkedExpr, err := cel.AstToCheckedExpr(compiled.ast)
	if err != nil {
		// If we can't analyze the AST, fall back to no optimization
		return opts
	}

	// Extract key optimizations from the expression
	if keyConstraints := extractKeyConstraints(checkedExpr.Expr); keyConstraints != nil {
		// Apply namespace bounds if available
		if keyConstraints.namespace != "" {
			lowerBound := makeKey(keyConstraints.namespace)
			upperBound := makeKey(keyConstraints.namespace + "\x01") // Next possible namespace
			opts.LowerBound = lowerBound
			opts.UpperBound = upperBound
		}

		// Apply type bounds if namespace + type are both specified
		if keyConstraints.namespace != "" && keyConstraints.artifactType != "" {
			lowerBound := makeKey(keyConstraints.namespace, keyConstraints.artifactType)
			upperBound := makeKey(keyConstraints.namespace, keyConstraints.artifactType+"\x01")
			opts.LowerBound = lowerBound
			opts.UpperBound = upperBound
		}
	}

	return opts
}

// keyConstraints holds extracted key-level constraints from CEL expressions
type keyConstraints struct {
	namespace    string
	artifactType string
}

// extractKeyConstraints analyzes a CEL expression to find simple equality constraints
// that can be used to optimize database key iteration.
func extractKeyConstraints(expr *exprpb.Expr) *keyConstraints {
	constraints := &keyConstraints{}

	// Walk the expression tree looking for simple equality patterns
	walkExprForConstraints(expr, constraints)

	return constraints
}

// walkExprForConstraints recursively walks the CEL expression tree to find constraints
func walkExprForConstraints(expr *exprpb.Expr, constraints *keyConstraints) {
	if expr == nil {
		return
	}

	switch expr.GetExprKind().(type) {
	case *exprpb.Expr_CallExpr:
		callExpr := expr.GetCallExpr()

		// Handle logical AND - both sides may contain constraints
		if callExpr.Function == operators.LogicalAnd {
			for _, arg := range callExpr.Args {
				walkExprForConstraints(arg, constraints)
			}
			return
		}

		// Handle logical OR - if we see an OR, we need to be conservative
		// and not apply bounds optimization as it might exclude valid results
		if callExpr.Function == operators.LogicalOr {
			// Don't traverse into OR expressions for bounds optimization
			// as they represent alternative conditions that might require different key ranges
			return
		}

		// Handle equality expressions: field == "value"
		if callExpr.Function == operators.Equals && len(callExpr.Args) == 2 {
			if field := getIdentifierName(callExpr.Args[0]); field != "" {
				if value := getStringConstant(callExpr.Args[1]); value != "" {
					switch field {
					case "artifact_namespace":
						// Only set if not already set, to avoid conflicts
						if constraints.namespace == "" {
							constraints.namespace = value
						} else if constraints.namespace != value {
							// Different namespace values found, clear to avoid incorrect bounds
							constraints.namespace = ""
						}
					case "artifact_type":
						if constraints.artifactType == "" {
							constraints.artifactType = value
						} else if constraints.artifactType != value {
							constraints.artifactType = ""
						}
					case "artifact_id":
						// Could be used for exact key lookups in the future
					}
				}
			}
		}

		// Continue walking into arguments for nested expressions (but not OR expressions)
		if callExpr.Function != operators.LogicalOr {
			for _, arg := range callExpr.Args {
				walkExprForConstraints(arg, constraints)
			}
		}
	}
}

// getIdentifierName extracts the identifier name from an expression if it's a simple identifier
func getIdentifierName(expr *exprpb.Expr) string {
	if expr == nil {
		return ""
	}

	if identExpr := expr.GetIdentExpr(); identExpr != nil {
		return identExpr.Name
	}

	return ""
}

// getStringConstant extracts a string constant from an expression if it's a string literal
func getStringConstant(expr *exprpb.Expr) string {
	if expr == nil {
		return ""
	}

	if constExpr := expr.GetConstExpr(); constExpr != nil {
		if strVal := constExpr.GetStringValue(); strVal != "" {
			return strVal
		}
	}

	return ""
}

// evaluateExpression evaluates a compiled CEL expression against an artifact.
func (idx *Index) evaluateExpression(compiled *CompiledExpression, artifact Artifact) (bool, error) {
	// Prepare evaluation context with artifact fields and custom variables
	evalVars := make(map[string]any)

	// Add artifact fields to evaluation context - use non-reserved variable names
	evalVars["artifact_namespace"] = artifact.Namespace
	evalVars["artifact_type"] = artifact.Type
	evalVars["artifact_id"] = artifact.ID
	evalVars["timestamp"] = artifact.Timestamp
	evalVars["data"] = artifact.Data
	evalVars["context"] = artifact.Context
	evalVars["dimensions"] = artifact.Dimensions

	// Convert entity to map for CEL evaluation
	entityMap := map[string]any{
		"type":     artifact.Entity.Type,
		"id":       artifact.Entity.ID,
		"metadata": artifact.Entity.Metadata,
	}
	evalVars["entity"] = entityMap

	// Convert relationships to list of maps for CEL evaluation
	var relationshipsList []any
	for _, rel := range artifact.Relationships {
		relMap := map[string]any{
			"type":     rel.Type,
			"target":   rel.Target,
			"metadata": rel.Metadata,
		}
		relationshipsList = append(relationshipsList, relMap)
	}
	evalVars["relationships"] = relationshipsList

	// Add custom variables from compilation
	for key, value := range compiled.vars {
		evalVars[key] = value
	}

	// Evaluate the expression
	result, _, err := compiled.program.Eval(evalVars)
	if err != nil {
		return false, fmt.Errorf("evaluate CEL expression: %w", err)
	}

	// Convert result to boolean
	boolResult, ok := result.Value().(bool)
	if !ok {
		return false, fmt.Errorf("CEL expression must return boolean, got %T", result.Value())
	}

	return boolResult, nil
}

// normalize ensures the Artifact has valid default values and consistent formatting.
func (a *Artifact) normalize() {
	// Initialize maps if nil
	if a.Data == nil {
		a.Data = make(map[string]any)
	}
	if a.Context == nil {
		a.Context = make(map[string]any)
	}
	if a.Dimensions == nil {
		a.Dimensions = make(map[string]string)
	}
	if a.Entity.Metadata == nil {
		a.Entity.Metadata = make(map[string]any)
	}

	// Normalize timestamp to UTC
	if a.Timestamp.IsZero() {
		a.Timestamp = time.Now().UTC()
	} else {
		a.Timestamp = a.Timestamp.UTC()
	}

	// Initialize relationships slice if nil
	if a.Relationships == nil {
		a.Relationships = make([]Relationship, 0)
	}

	// Normalize relationship metadata
	for i := range a.Relationships {
		if a.Relationships[i].Metadata == nil {
			a.Relationships[i].Metadata = make(map[string]any)
		}
	}
}

// validateArtifact checks that an Artifact has all required fields and valid structure.
func validateArtifact(a Artifact) error {
	if a.Namespace == "" {
		return fmt.Errorf("%w: namespace is required", ErrInvalidArtifact)
	}
	if a.Type == "" {
		return fmt.Errorf("%w: type is required", ErrInvalidArtifact)
	}
	if a.ID == "" {
		return fmt.Errorf("%w: id is required", ErrInvalidArtifact)
	}
	if a.Entity.Type == "" {
		return fmt.Errorf("%w: entity type is required", ErrInvalidArtifact)
	}
	if a.Entity.ID == "" {
		return fmt.Errorf("%w: entity id is required", ErrInvalidArtifact)
	}
	if a.Timestamp.IsZero() {
		return fmt.Errorf("%w: timestamp is required", ErrInvalidArtifact)
	}

	// Validate relationships
	for i, rel := range a.Relationships {
		if rel.Type == "" {
			return fmt.Errorf("%w: relationship[%d] type is required", ErrInvalidArtifact, i)
		}
		if rel.Target == "" {
			return fmt.Errorf("%w: relationship[%d] target is required", ErrInvalidArtifact, i)
		}
	}

	return nil
}

// PutArtifact stores an Artifact in the index.
// The artifact is normalized and validated before storage.
// The key is constructed to enable efficient querying by namespace, type, entity, and time.
//
// The context can be used to cancel the operation if it takes too long.
func (idx *Index) PutArtifact(ctx context.Context, artifact Artifact) error {
	if idx == nil || idx.db == nil {
		return errors.New("index: nil index")
	}

	// Normalize the artifact to ensure consistent data
	artifact.normalize()

	// Validate that all required fields are present
	if err := validateArtifact(artifact); err != nil {
		return err
	}

	// Check if the context has been cancelled
	if err := checkCtx(ctx); err != nil {
		return err
	}

	// Create a key that enables efficient multi-dimensional queries
	key := makeArtifactKey(artifact.Namespace, artifact.Type, artifact.Entity.ID,
		artifact.Timestamp.Format(timeEncoding), artifact.ID)

	// Serialize the artifact as JSON for storage
	value, err := json.Marshal(artifact)
	if err != nil {
		return fmt.Errorf("marshal artifact: %w", err)
	}

	// Store the key-value pair without syncing to disk immediately for performance
	return idx.db.Set(key, value, pebble.NoSync)
}

// Helper functions for key construction

// makeArtifactKey constructs a database key for an artifact.
// The key structure enables efficient multi-dimensional queries:
// namespace\x00type\x00entity\x00timestamp\x00id\x00
func makeArtifactKey(namespace, artifactType, entityID, timestamp, id string) []byte {
	return makeKey(namespace, artifactType, entityID, timestamp, id)
}

// makeKey constructs a database key from string parts.
// Each part is separated by a null byte (keySep), and the key ends with a null byte.
// This ensures lexicographic ordering and prevents key prefix collisions.
//
// Example: makeKey("security", "vulnerability", "CVE-2023-1234") -> "security\x00vulnerability\x00CVE-2023-1234\x00"
func makeKey(parts ...string) []byte {
	// Pre-calculate size to avoid reallocations
	size := 1 // final separator
	for _, part := range parts {
		size += len(part) + 1 // part length + separator
	}
	key := make([]byte, 0, size)

	for _, part := range parts {
		key = append(key, part...)
		key = append(key, keySep)
	}

	return key
}

// checkCtx checks if the provided context has been cancelled or has exceeded its deadline.
// Returns nil if the context is nil or still active, otherwise returns the context's error.
// This allows for cooperative cancellation of long-running operations.
func checkCtx(ctx context.Context) error {
	if ctx == nil {
		return nil
	}
	select {
	case <-ctx.Done():
		return ctx.Err()
	default:
		return nil
	}
}
