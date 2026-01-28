package aws

import (
	"context"
	"fmt"
	"net/url"
	"strings"

	"github.com/picatz/deputy/internal/cloud"
)

// TargetInfo contains parsed information from an AWS target URI.
type TargetInfo struct {
	// Type is the resource type (ami, ebs-snapshot, lambda, ecr-image).
	Type cloud.ResourceType

	// ResourceID is the AWS resource identifier.
	ResourceID string

	// Region is the AWS region (may be empty if not specified).
	Region string

	// Additional parameters from query string.
	Params map[string]string
}

// CollectionInfo contains parsed information from an AWS collection URI.
// Collection URIs enumerate available resources rather than opening a specific one.
type CollectionInfo struct {
	// Type is the resource type being listed (ami, ebs-snapshot, etc.).
	Type cloud.ResourceType

	// Region is the AWS region to list resources from (may be empty for all regions).
	Region string

	// Owner filters AMIs by owner (self, amazon, aws-marketplace, or account ID).
	Owner string

	// Tags filters resources by tag key-value pairs.
	// Keys are tag names, values are the expected tag values.
	Tags map[string]string

	// Additional parameters from query string.
	Params map[string]string
}

// ParseTarget parses an AWS target URI and returns its components.
//
// Supported formats:
//   - aws://ami/ami-xxx
//   - aws://ami/ami-xxx?region=us-west-2
//   - aws://ebs/snap-xxx
//   - aws://lambda/function-name
//   - aws://lambda/function-name:alias
//   - aws://ecr/account.dkr.ecr.region.amazonaws.com/repo:tag
//
// Also supports bare resource IDs for convenience:
//   - ami-xxx (detected by prefix)
//   - snap-xxx (detected by prefix)
func ParseTarget(target string) (*TargetInfo, error) {
	// Handle bare resource IDs
	if strings.HasPrefix(target, "ami-") {
		return &TargetInfo{
			Type:       cloud.ResourceTypeAWSAMI,
			ResourceID: target,
			Params:     make(map[string]string),
		}, nil
	}
	if strings.HasPrefix(target, "snap-") {
		return &TargetInfo{
			Type:       cloud.ResourceTypeAWSEBSSnapshot,
			ResourceID: target,
			Params:     make(map[string]string),
		}, nil
	}

	// Handle aws:// scheme
	if !strings.HasPrefix(target, "aws://") {
		return nil, fmt.Errorf("%w: expected aws:// scheme", cloud.ErrInvalidTarget)
	}

	// Parse as URL
	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cloud.ErrInvalidTarget, err)
	}

	// URL parsing for aws://type/resource-id:
	// - Host contains "type" (e.g., "ami")
	// - Path contains "/resource-id" (e.g., "/ami-abc123")
	resourceType := u.Host
	resourceID := strings.TrimPrefix(u.Path, "/")
	if resourceID == "" {
		return nil, fmt.Errorf("%w: expected aws://type/resource-id", cloud.ErrInvalidTarget)
	}

	info := &TargetInfo{
		ResourceID: resourceID,
		Region:     u.Query().Get("region"),
		Params:     make(map[string]string),
	}

	// Parse query parameters
	for k, v := range u.Query() {
		if len(v) > 0 {
			info.Params[k] = v[0]
		}
	}

	// Determine resource type
	switch strings.ToLower(resourceType) {
	case "ami":
		info.Type = cloud.ResourceTypeAWSAMI
		if !strings.HasPrefix(info.ResourceID, "ami-") {
			return nil, fmt.Errorf("%w: AMI ID must start with 'ami-'", cloud.ErrInvalidTarget)
		}
	case "ebs", "snapshot":
		info.Type = cloud.ResourceTypeAWSEBSSnapshot
		if !strings.HasPrefix(info.ResourceID, "snap-") {
			return nil, fmt.Errorf("%w: EBS snapshot ID must start with 'snap-'", cloud.ErrInvalidTarget)
		}
	case "lambda", "function":
		info.Type = cloud.ResourceTypeAWSLambda
	case "ecr":
		info.Type = cloud.ResourceTypeAWSECRImage
	default:
		return nil, fmt.Errorf("%w: unknown AWS resource type %q", cloud.ErrInvalidTarget, resourceType)
	}

	return info, nil
}

// Detect returns true if the target looks like an AWS resource.
func Detect(_ context.Context, target string) bool {
	// Explicit scheme
	if strings.HasPrefix(target, "aws://") {
		return true
	}
	// Bare AMI ID
	if strings.HasPrefix(target, "ami-") {
		return true
	}
	// Bare snapshot ID
	if strings.HasPrefix(target, "snap-") {
		return true
	}
	// ECR registry URL
	if strings.Contains(target, ".dkr.ecr.") && strings.Contains(target, ".amazonaws.com") {
		return true
	}
	return false
}

// collectionTypes maps plural collection names to their resource types.
var collectionTypes = map[string]cloud.ResourceType{
	"amis":          cloud.ResourceTypeAWSAMI,
	"ebs-snapshots": cloud.ResourceTypeAWSEBSSnapshot,
	"snapshots":     cloud.ResourceTypeAWSEBSSnapshot,
	"lambdas":       cloud.ResourceTypeAWSLambda,
	"functions":     cloud.ResourceTypeAWSLambda,
	"ecr-images":    cloud.ResourceTypeAWSECRImage,
}

// IsCollection returns true if the target URI represents a collection
// rather than a specific resource.
//
// Collection URIs use plural resource names:
//   - aws://amis                    → list AMIs
//   - aws://amis?owner=self         → list my AMIs
//   - aws://ebs-snapshots           → list EBS snapshots
//   - aws://ebs-snapshots?region=us-west-2&tags.env=prod
func IsCollection(_ context.Context, target string) bool {
	if !strings.HasPrefix(target, "aws://") {
		return false
	}

	// Parse to extract the path
	u, err := url.Parse(target)
	if err != nil {
		return false
	}

	// Extract collection type from path (e.g., "amis" from "aws://amis")
	// The path will be "/amis" or just "amis" depending on parsing
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		// aws://amis parses with Host="amis", Path=""
		path = u.Host
	}

	// Check if it's a known collection type
	_, isCollection := collectionTypes[strings.ToLower(path)]
	return isCollection
}

// ParseCollectionTarget parses an AWS collection URI.
//
// Supported formats:
//   - aws://amis
//   - aws://amis?owner=self
//   - aws://amis?region=us-west-2
//   - aws://amis?owner=self&region=us-west-2&tags.env=prod
//   - aws://ebs-snapshots
//   - aws://ebs-snapshots?tags.backup=daily
func ParseCollectionTarget(target string) (*CollectionInfo, error) {
	if !strings.HasPrefix(target, "aws://") {
		return nil, fmt.Errorf("%w: expected aws:// scheme", cloud.ErrInvalidTarget)
	}

	u, err := url.Parse(target)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cloud.ErrInvalidTarget, err)
	}

	// Extract collection type from path
	// aws://amis parses with Host="amis", Path=""
	path := strings.TrimPrefix(u.Path, "/")
	if path == "" {
		path = u.Host
	}

	resourceType, ok := collectionTypes[strings.ToLower(path)]
	if !ok {
		return nil, fmt.Errorf("%w: unknown collection type %q", cloud.ErrInvalidTarget, path)
	}

	info := &CollectionInfo{
		Type:   resourceType,
		Region: u.Query().Get("region"),
		Owner:  u.Query().Get("owner"),
		Tags:   make(map[string]string),
		Params: make(map[string]string),
	}

	// Parse query parameters, extracting tags.* specially
	for k, v := range u.Query() {
		if len(v) == 0 {
			continue
		}
		if strings.HasPrefix(k, "tags.") {
			tagName := strings.TrimPrefix(k, "tags.")
			info.Tags[tagName] = v[0]
		} else {
			info.Params[k] = v[0]
		}
	}

	return info, nil
}
