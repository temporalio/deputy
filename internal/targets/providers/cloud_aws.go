package providers

import (
	"context"
	"fmt"
	"time"

	"google.golang.org/protobuf/types/known/timestamppb"

	listv1 "github.com/picatz/deputy/gen/deputy/list/v1"
	"github.com/picatz/deputy/internal/cloud"
	"github.com/picatz/deputy/internal/cloud/aws"
	"github.com/picatz/deputy/internal/targets"
)

func init() {
	targets.RegisterProvider(awsCloudProvider{})
}

// priorityCloudAWS determines detection order relative to other providers.
// AWS cloud resources have priority 65, which is:
//   - Lower than VM images (70) - prefer local VM if file exists
//   - Lower than container images (75) - container registries are more common
//   - Higher than directories (50) - prefer cloud if scheme matches
const priorityCloudAWS = 65

// awsCloudProvider implements [targets.Provider] for AWS cloud resources.
type awsCloudProvider struct{}

func (awsCloudProvider) Priority() int { return priorityCloudAWS }

// Detect returns true if the target looks like an AWS resource.
func (awsCloudProvider) Detect(ctx context.Context, target string) bool {
	return aws.Detect(ctx, target)
}

// Open materializes an AWS cloud resource for scanning.
func (awsCloudProvider) Open(ctx context.Context, target string, opts *targets.OpenOptions) (targets.Materialized, error) {
	// Parse the target URI
	info, err := aws.ParseTarget(target)
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("parse AWS target: %w", err)
	}

	// Build cloud options from target options
	cloudOpts := openOptionsToCloudOptions(opts)
	if info.Region != "" {
		cloudOpts.Region = info.Region
	}

	// Create AWS client
	client, err := aws.NewClient(ctx, cloudOpts)
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("create AWS client: %w", err)
	}

	// Open the resource based on type
	var resource cloud.Resource
	switch info.Type {
	case cloud.ResourceTypeAWSAMI:
		resource, err = aws.OpenAMI(ctx, client, info.ResourceID, cloudOpts)
	case cloud.ResourceTypeAWSEBSSnapshot:
		resource, err = aws.OpenEBSSnapshot(ctx, client, info.ResourceID, cloudOpts)
	default:
		return targets.Materialized{}, fmt.Errorf("unsupported AWS resource type: %s", info.Type)
	}
	if err != nil {
		return targets.Materialized{}, fmt.Errorf("open AWS resource: %w", err)
	}

	// Get filesystem view
	fsys, err := resource.FS(ctx)
	if err != nil {
		resource.Close()
		return targets.Materialized{}, fmt.Errorf("get filesystem: %w", err)
	}

	// Build provenance metadata
	provenance := map[string]string{
		"provider":      string(resource.Provider()),
		"resource_type": string(resource.Type()),
		"resource_id":   resource.ID(),
		"region":        resource.Region(),
	}
	if resource.AccountID() != "" {
		provenance["account_id"] = resource.AccountID()
	}
	if resource.Name() != "" {
		provenance["name"] = resource.Name()
	}
	for k, v := range resource.Tags() {
		provenance["tag:"+k] = v
	}

	return targets.Materialized{
		FS:   fsys,
		Path: target,
		Meta: targets.Descriptor{
			Kind:       targets.KindCloudResource,
			Target:     target,
			Options:    opts,
			Provenance: provenance,
		},
		Data:    resource,
		Cleanup: func() { resource.Close() },
	}, nil
}

// IsCollection returns true if the target is a collection URI like aws://amis.
func (awsCloudProvider) IsCollection(ctx context.Context, target string) bool {
	return aws.IsCollection(ctx, target)
}

// List enumerates AWS resources in a collection.
func (awsCloudProvider) List(ctx context.Context, target string, opts *targets.ListOptions) (*targets.ListResult, error) {
	// Check context before starting
	if err := ctx.Err(); err != nil {
		return nil, fmt.Errorf("list AWS resources: %w", err)
	}

	// Parse the collection URI
	info, err := aws.ParseCollectionTarget(target)
	if err != nil {
		return nil, fmt.Errorf("parse AWS collection target: %w", err)
	}

	// Build cloud options from list options
	cloudOpts := listOptionsToCloudOptions(opts)
	if info.Region != "" {
		cloudOpts.Region = info.Region
	}

	// Create AWS client
	client, err := aws.NewClient(ctx, cloudOpts)
	if err != nil {
		return nil, fmt.Errorf("create AWS client: %w", err)
	}

	// Extract pagination options
	var pageSize int32
	var pageToken string
	if opts != nil {
		pageSize = opts.PageSize
		pageToken = opts.PageToken
	}

	// List resources based on type
	var discoveredTargets []*listv1.DiscoveredTarget
	var nextToken string
	switch info.Type {
	case cloud.ResourceTypeAWSAMI:
		discoveredTargets, nextToken, err = listAMIs(ctx, client, info, cloudOpts.Region, pageSize, pageToken)
	case cloud.ResourceTypeAWSEBSSnapshot:
		discoveredTargets, nextToken, err = listSnapshots(ctx, client, info, cloudOpts.Region, pageSize, pageToken)
	default:
		return nil, fmt.Errorf("unsupported AWS collection type: %s", info.Type)
	}
	if err != nil {
		return nil, err
	}

	return &targets.ListResult{
		Targets:       discoveredTargets,
		NextPageToken: nextToken,
	}, nil
}

// listAMIs lists AMIs and converts them to DiscoveredTargets.
func listAMIs(ctx context.Context, client *aws.Client, info *aws.CollectionInfo, region string, pageSize int32, pageToken string) ([]*listv1.DiscoveredTarget, string, error) {
	listOpts := aws.ListAMIsOptions{
		MaxResults: pageSize,
		NextToken:  pageToken,
	}

	// Apply owner filter
	if info.Owner != "" {
		listOpts.OwnerIDs = []string{info.Owner}
	}

	// Apply tag filters
	if len(info.Tags) > 0 {
		listOpts.Filters = make(map[string][]string)
		for k, v := range info.Tags {
			listOpts.Filters["tag:"+k] = []string{v}
		}
	}

	result, err := aws.ListAMIs(ctx, client, listOpts)
	if err != nil {
		return nil, "", fmt.Errorf("list AMIs: %w", err)
	}

	targets := make([]*listv1.DiscoveredTarget, 0, len(result.Summaries))
	for _, s := range result.Summaries {
		t := &listv1.DiscoveredTarget{
			Uri:         fmt.Sprintf("aws://ami/%s", s.ImageID),
			Name:        s.Name,
			Description: s.Description,
			Metadata: map[string]string{
				"image_id":     s.ImageID,
				"architecture": s.Architecture,
				"platform":     s.Platform,
				"owner_id":     s.OwnerID,
				"state":        s.State,
				"region":       region,
			},
		}
		// Parse creation date
		if s.CreationDate != "" {
			if created, err := time.Parse(time.RFC3339, s.CreationDate); err == nil {
				t.CreatedAt = timestamppb.New(created)
			}
		}
		// Add tags to metadata
		for k, v := range s.Tags {
			t.Metadata["tags."+k] = v
		}
		targets = append(targets, t)
	}

	return targets, result.NextToken, nil
}

// listSnapshots lists EBS snapshots and converts them to DiscoveredTargets.
func listSnapshots(ctx context.Context, client *aws.Client, info *aws.CollectionInfo, region string, pageSize int32, pageToken string) ([]*listv1.DiscoveredTarget, string, error) {
	listOpts := aws.ListSnapshotsOptions{
		MaxResults: pageSize,
		NextToken:  pageToken,
	}

	// Apply owner filter
	if info.Owner != "" {
		listOpts.OwnerIDs = []string{info.Owner}
	}

	// Apply tag filters
	if len(info.Tags) > 0 {
		listOpts.Filters = make(map[string][]string)
		for k, v := range info.Tags {
			listOpts.Filters["tag:"+k] = []string{v}
		}
	}

	result, err := aws.ListSnapshots(ctx, client, listOpts)
	if err != nil {
		return nil, "", fmt.Errorf("list snapshots: %w", err)
	}

	targets := make([]*listv1.DiscoveredTarget, 0, len(result.Summaries))
	for _, s := range result.Summaries {
		// Use Name tag if available, otherwise snapshot ID
		name := s.SnapshotID
		if tagName, ok := s.Tags["Name"]; ok && tagName != "" {
			name = tagName
		}

		t := &listv1.DiscoveredTarget{
			Uri:         fmt.Sprintf("aws://ebs-snapshot/%s", s.SnapshotID),
			Name:        name,
			Description: s.Description,
			Metadata: map[string]string{
				"snapshot_id": s.SnapshotID,
				"volume_id":   s.VolumeID,
				"volume_size": fmt.Sprintf("%d", s.VolumeSize),
				"owner_id":    s.OwnerID,
				"state":       s.State,
				"encrypted":   fmt.Sprintf("%t", s.Encrypted),
				"region":      region,
			},
		}
		// Parse start time
		if s.StartTime != "" {
			if started, err := time.Parse(time.RFC3339, s.StartTime); err == nil {
				t.CreatedAt = timestamppb.New(started)
			}
		}
		// Add tags to metadata
		for k, v := range s.Tags {
			t.Metadata["tags."+k] = v
		}
		targets = append(targets, t)
	}

	return targets, result.NextToken, nil
}

// openOptionsToCloudOptions converts targets.OpenOptions to cloud.Options.
func openOptionsToCloudOptions(opts *targets.OpenOptions) cloud.Options {
	cloudOpts := cloud.DefaultOptions()
	if opts == nil {
		return cloudOpts
	}

	cloudOpts.SmartDownload = opts.SmartDownload
	cloudOpts.Ecosystems = opts.Ecosystems

	if opts.Context != nil {
		if opts.Context.AWSRegion != "" {
			cloudOpts.Region = opts.Context.AWSRegion
		}
		// Profile could be in Extra
		if profile := opts.Context.Extra["profile"]; profile != "" {
			cloudOpts.Profile = profile
		}
		// Account ID could be in Extra
		if accountID := opts.Context.Extra["account_id"]; accountID != "" {
			cloudOpts.AccountID = accountID
		}
	}

	return cloudOpts
}

// listOptionsToCloudOptions converts targets.ListOptions to cloud.Options.
func listOptionsToCloudOptions(opts *targets.ListOptions) cloud.Options {
	cloudOpts := cloud.DefaultOptions()
	if opts == nil {
		return cloudOpts
	}

	if opts.Context != nil {
		if opts.Context.AWSRegion != "" {
			cloudOpts.Region = opts.Context.AWSRegion
		}
		// Profile could be in Extra
		if profile := opts.Context.Extra["profile"]; profile != "" {
			cloudOpts.Profile = profile
		}
		// Account ID could be in Extra
		if accountID := opts.Context.Extra["account_id"]; accountID != "" {
			cloudOpts.AccountID = accountID
		}
	}

	return cloudOpts
}

var _ targets.Provider = (*awsCloudProvider)(nil)
var _ targets.PriorityProvider = (*awsCloudProvider)(nil)
var _ targets.CollectionProvider = (*awsCloudProvider)(nil)
