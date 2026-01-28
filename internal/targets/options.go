package targets

import (
	"fmt"
	"strings"
)

// Well-known option keys. Use these constants instead of string literals
// for type safety and IDE autocompletion.
const (
	// Filter keys
	KeyNamePattern   = "name_pattern"
	KeyCELExpression = "cel_expression"
	KeyTagPrefix     = "tags."

	// Open behavior keys
	KeySmartDownload    = "smart_download"
	KeyPlatform         = "platform"
	KeyEcosystems       = "ecosystems"
	KeySkipVerification = "skip_verification"

	// AWS context keys (canonical)
	KeyAWSRegion = "aws_region"
	KeyAWSOwner  = "aws_owner"

	// GCP context keys (canonical)
	KeyGCPProject  = "gcp_project"
	KeyGCPLocation = "gcp_location"

	// Azure context keys (canonical)
	KeyAzureSubscription  = "azure_subscription"
	KeyAzureResourceGroup = "azure_resource_group"

	// SCM context keys (canonical)
	KeySCMOrganization = "scm_organization"

	// Common shorthand keys (mapped to canonical)
	KeyRegion       = "region"       // → aws_region
	KeyOwner        = "owner"        // → aws_owner
	KeyProject      = "project"      // → gcp_project
	KeyLocation     = "location"     // → gcp_location
	KeySubscription = "subscription" // → azure_subscription
	KeyResourceGroup = "resource_group" // → azure_resource_group
	KeyOrganization = "organization" // → scm_organization
	KeyOrg          = "org"          // → scm_organization
)

// ListOptions configures collection listing.
// This is the canonical type for list operations within Deputy,
// providing type safety while remaining provider-agnostic.
type ListOptions struct {
	// Context scopes WHERE to list (region, project, etc.)
	Context *ProviderContext

	// Tags filters resources by tag key-value pairs.
	Tags map[string]string

	// NamePattern filters by name using glob patterns (* and ?).
	NamePattern string

	// CELExpression provides advanced filtering via CEL.
	CELExpression string

	// Pagination
	PageSize  int32
	PageToken string
}

// OpenOptions configures how a target is opened/materialized.
type OpenOptions struct {
	// Context scopes WHERE to access the resource.
	Context *ProviderContext

	// SmartDownload enables downloading only necessary blocks.
	// For EBS snapshots, this downloads only blocks containing package databases.
	// Default: true (set via DefaultOpenOptions)
	SmartDownload bool

	// Ecosystems limits scanning to specific package ecosystems.
	// Empty means all ecosystems.
	Ecosystems []string

	// Platform specifies the target platform for multi-arch images.
	// Format: os/arch[/variant], e.g., "linux/amd64", "linux/arm64/v8"
	Platform string

	// SkipVerification skips signature verification (testing only).
	SkipVerification bool
}

// ProviderContext contains provider-specific scoping parameters.
// These define WHERE to look, not WHAT to filter.
//
// Design: Each cloud provider has dedicated fields for common parameters.
// This provides type safety and documentation while Extra allows extensibility.
type ProviderContext struct {
	// AWS
	AWSRegion string // AWS region (us-west-2, eu-west-1, etc.)
	AWSOwner  string // AMI owner filter (self, amazon, aws-marketplace, account ID)

	// GCP
	GCPProject  string // GCP project ID
	GCPLocation string // GCP zone or region

	// Azure
	AzureSubscription  string // Azure subscription ID
	AzureResourceGroup string // Azure resource group name

	// SCM (GitHub, GitLab, etc.)
	Organization string // Organization or group name

	// Extra holds provider-specific fields not covered above.
	// Plugins should document their expected keys.
	Extra map[string]string
}

// DefaultOpenOptions returns sensible defaults for open operations.
func DefaultOpenOptions() *OpenOptions {
	return &OpenOptions{
		SmartDownload: true,
	}
}

// IsEmpty reports whether the context has no values set.
func (c *ProviderContext) IsEmpty() bool {
	if c == nil {
		return true
	}
	return c.AWSRegion == "" && c.AWSOwner == "" &&
		c.GCPProject == "" && c.GCPLocation == "" &&
		c.AzureSubscription == "" && c.AzureResourceGroup == "" &&
		c.Organization == "" && len(c.Extra) == 0
}

// Clone returns a deep copy of the context.
func (c *ProviderContext) Clone() *ProviderContext {
	if c == nil {
		return nil
	}
	clone := *c
	if c.Extra != nil {
		clone.Extra = make(map[string]string, len(c.Extra))
		for k, v := range c.Extra {
			clone.Extra[k] = v
		}
	}
	return &clone
}

// Merge combines two contexts, with other taking precedence for conflicts.
func (c *ProviderContext) Merge(other *ProviderContext) *ProviderContext {
	if c == nil {
		return other.Clone()
	}
	if other == nil {
		return c.Clone()
	}

	result := c.Clone()
	if other.AWSRegion != "" {
		result.AWSRegion = other.AWSRegion
	}
	if other.AWSOwner != "" {
		result.AWSOwner = other.AWSOwner
	}
	if other.GCPProject != "" {
		result.GCPProject = other.GCPProject
	}
	if other.GCPLocation != "" {
		result.GCPLocation = other.GCPLocation
	}
	if other.AzureSubscription != "" {
		result.AzureSubscription = other.AzureSubscription
	}
	if other.AzureResourceGroup != "" {
		result.AzureResourceGroup = other.AzureResourceGroup
	}
	if other.Organization != "" {
		result.Organization = other.Organization
	}
	for k, v := range other.Extra {
		if result.Extra == nil {
			result.Extra = make(map[string]string)
		}
		result.Extra[k] = v
	}
	return result
}

// Validate checks the context for common errors.
func (c *ProviderContext) Validate() error {
	if c == nil {
		return nil
	}
	// Validate AWS region format (basic check)
	if c.AWSRegion != "" && !isValidAWSRegion(c.AWSRegion) {
		return fmt.Errorf("invalid AWS region format: %q", c.AWSRegion)
	}
	return nil
}

// isValidAWSRegion performs basic validation of AWS region format.
func isValidAWSRegion(region string) bool {
	// AWS regions follow pattern: us-east-1, eu-west-2, ap-northeast-1, etc.
	// Also allow special regions like us-gov-west-1, cn-north-1
	if len(region) < 5 || len(region) > 25 {
		return false
	}
	// Must contain at least one hyphen
	return strings.Contains(region, "-")
}

// Builder methods for fluent API construction.
// Example:
//
//	opts := targets.NewListOptions().
//		WithTag("env", "prod").
//		WithAWS("us-west-2", "self").
//		WithNamePattern("my-app-*")

// NewListOptions creates a new ListOptions with optional initial values.
func NewListOptions() *ListOptions {
	return &ListOptions{
		Tags: make(map[string]string),
	}
}

// WithTags sets tag filters.
func (o *ListOptions) WithTags(tags map[string]string) *ListOptions {
	if o.Tags == nil {
		o.Tags = make(map[string]string)
	}
	for k, v := range tags {
		o.Tags[k] = v
	}
	return o
}

// WithTag adds a single tag filter.
func (o *ListOptions) WithTag(key, value string) *ListOptions {
	if o.Tags == nil {
		o.Tags = make(map[string]string)
	}
	o.Tags[key] = value
	return o
}

// WithNamePattern sets the name filter pattern.
func (o *ListOptions) WithNamePattern(pattern string) *ListOptions {
	o.NamePattern = pattern
	return o
}

// WithCEL sets the CEL filter expression.
func (o *ListOptions) WithCEL(expr string) *ListOptions {
	o.CELExpression = expr
	return o
}

// WithContext sets the provider context.
func (o *ListOptions) WithContext(ctx *ProviderContext) *ListOptions {
	o.Context = ctx
	return o
}

// WithAWS configures AWS-specific context.
func (o *ListOptions) WithAWS(region, owner string) *ListOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.AWSRegion = region
	o.Context.AWSOwner = owner
	return o
}

// WithGCP configures GCP-specific context.
func (o *ListOptions) WithGCP(project, location string) *ListOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.GCPProject = project
	o.Context.GCPLocation = location
	return o
}

// WithAzure configures Azure-specific context.
func (o *ListOptions) WithAzure(subscription, resourceGroup string) *ListOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.AzureSubscription = subscription
	o.Context.AzureResourceGroup = resourceGroup
	return o
}

// WithOrganization configures SCM organization context.
func (o *ListOptions) WithOrganization(org string) *ListOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.Organization = org
	return o
}

// WithPageSize sets the page size for pagination.
func (o *ListOptions) WithPageSize(size int32) *ListOptions {
	o.PageSize = size
	return o
}

// WithPageToken sets the page token for pagination continuation.
func (o *ListOptions) WithPageToken(token string) *ListOptions {
	o.PageToken = token
	return o
}

// NewOpenOptions creates a new OpenOptions with sensible defaults.
func NewOpenOptions() *OpenOptions {
	return DefaultOpenOptions()
}

// WithSmartDownload enables or disables smart block downloading.
func (o *OpenOptions) WithSmartDownload(enabled bool) *OpenOptions {
	o.SmartDownload = enabled
	return o
}

// WithPlatform sets the target platform for container images.
func (o *OpenOptions) WithPlatform(platform string) *OpenOptions {
	o.Platform = platform
	return o
}

// WithEcosystems sets the ecosystems to scan.
func (o *OpenOptions) WithEcosystems(ecosystems ...string) *OpenOptions {
	o.Ecosystems = ecosystems
	return o
}

// WithContext sets the provider context.
func (o *OpenOptions) WithContext(ctx *ProviderContext) *OpenOptions {
	o.Context = ctx
	return o
}

// WithAWS configures AWS-specific context.
func (o *OpenOptions) WithAWS(region string) *OpenOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.AWSRegion = region
	return o
}

// WithGCP configures GCP-specific context.
func (o *OpenOptions) WithGCP(project, location string) *OpenOptions {
	if o.Context == nil {
		o.Context = &ProviderContext{}
	}
	o.Context.GCPProject = project
	o.Context.GCPLocation = location
	return o
}

// NewProviderContext creates a new ProviderContext.
func NewProviderContext() *ProviderContext {
	return &ProviderContext{
		Extra: make(map[string]string),
	}
}

// WithAWSRegion sets the AWS region.
func (c *ProviderContext) WithAWSRegion(region string) *ProviderContext {
	c.AWSRegion = region
	return c
}

// WithAWSOwner sets the AWS owner filter.
func (c *ProviderContext) WithAWSOwner(owner string) *ProviderContext {
	c.AWSOwner = owner
	return c
}

// WithGCPProject sets the GCP project.
func (c *ProviderContext) WithGCPProject(project string) *ProviderContext {
	c.GCPProject = project
	return c
}

// WithGCPLocation sets the GCP location.
func (c *ProviderContext) WithGCPLocation(location string) *ProviderContext {
	c.GCPLocation = location
	return c
}

// WithAzureSubscription sets the Azure subscription.
func (c *ProviderContext) WithAzureSubscription(sub string) *ProviderContext {
	c.AzureSubscription = sub
	return c
}

// WithAzureResourceGroup sets the Azure resource group.
func (c *ProviderContext) WithAzureResourceGroup(rg string) *ProviderContext {
	c.AzureResourceGroup = rg
	return c
}

// WithOrganization sets the SCM organization.
func (c *ProviderContext) WithOrganization(org string) *ProviderContext {
	c.Organization = org
	return c
}

// WithExtra adds extra provider-specific fields.
func (c *ProviderContext) WithExtra(key, value string) *ProviderContext {
	if c.Extra == nil {
		c.Extra = make(map[string]string)
	}
	c.Extra[key] = value
	return c
}
