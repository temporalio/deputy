package aws

import (
	"context"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"
	"google.golang.org/protobuf/types/known/timestamppb"

	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
)

// ListAMIsOptions configures AMI listing.
type ListAMIsOptions struct {
	// OwnerIDs filters AMIs by owner. Use "self" for your own AMIs.
	// Empty means all AMIs visible to the account.
	OwnerIDs []string
	// Filters are EC2 filters to apply.
	Filters map[string][]string
	// MaxResults limits the number of results per page. Default is 1000 (AWS max).
	MaxResults int32
	// NextToken continues from a previous list operation.
	NextToken string
}

// ListAMIsResult contains the results of listing AMIs.
type ListAMIsResult struct {
	// Summaries contains the AMI summaries for this page.
	Summaries []AMISummary
	// NextToken is set when more results are available.
	// Pass this value as NextToken in the next request to continue.
	NextToken string
}

// AMISummary provides basic info about an AMI without opening it.
type AMISummary struct {
	ImageID      string
	Name         string
	Description  string
	Architecture string
	Platform     string
	OwnerID      string
	State        string
	CreationDate string
	Tags         map[string]string
}

// ListAMIs lists AMIs accessible to the current credentials.
// Returns a ListAMIsResult with pagination support.
func ListAMIs(ctx context.Context, client *Client, opts ListAMIsOptions) (*ListAMIsResult, error) {
	input := &ec2.DescribeImagesInput{}

	// Apply owner filter
	if len(opts.OwnerIDs) > 0 {
		input.Owners = opts.OwnerIDs
	}

	// Apply custom filters
	if len(opts.Filters) > 0 {
		for name, values := range opts.Filters {
			input.Filters = append(input.Filters, types.Filter{
				Name:   aws.String(name),
				Values: values,
			})
		}
	}

	// Apply max results (default to 100 for reasonable page sizes)
	maxResults := opts.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	input.MaxResults = aws.Int32(maxResults)

	// Apply pagination token
	if opts.NextToken != "" {
		input.NextToken = aws.String(opts.NextToken)
	}

	output, err := client.EC2().DescribeImages(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describe images: %w", err)
	}

	summaries := make([]AMISummary, 0, len(output.Images))
	for _, img := range output.Images {
		summary := AMISummary{
			ImageID:      aws.ToString(img.ImageId),
			Name:         aws.ToString(img.Name),
			Description:  aws.ToString(img.Description),
			Architecture: string(img.Architecture),
			Platform:     aws.ToString(img.PlatformDetails),
			OwnerID:      aws.ToString(img.OwnerId),
			State:        string(img.State),
			CreationDate: aws.ToString(img.CreationDate),
			Tags:         make(map[string]string),
		}
		for _, tag := range img.Tags {
			summary.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		summaries = append(summaries, summary)
	}

	return &ListAMIsResult{
		Summaries: summaries,
		NextToken: aws.ToString(output.NextToken),
	}, nil
}

// ListSnapshotsOptions configures snapshot listing.
type ListSnapshotsOptions struct {
	// OwnerIDs filters snapshots by owner. Use "self" for your own snapshots.
	OwnerIDs []string
	// Filters are EC2 filters to apply.
	Filters map[string][]string
	// MaxResults limits the number of results per page. Default is 1000 (AWS max).
	MaxResults int32
	// NextToken continues from a previous list operation.
	NextToken string
}

// ListSnapshotsResult contains the results of listing snapshots.
type ListSnapshotsResult struct {
	// Summaries contains the snapshot summaries for this page.
	Summaries []SnapshotSummary
	// NextToken is set when more results are available.
	// Pass this value as NextToken in the next request to continue.
	NextToken string
}

// SnapshotSummary provides basic info about an EBS snapshot.
type SnapshotSummary struct {
	SnapshotID  string
	VolumeID    string
	VolumeSize  int32 // GB
	Description string
	OwnerID     string
	State       string
	StartTime   string
	Encrypted   bool
	Tags        map[string]string
}

// ListSnapshots lists EBS snapshots accessible to the current credentials.
// Returns a ListSnapshotsResult with pagination support.
func ListSnapshots(ctx context.Context, client *Client, opts ListSnapshotsOptions) (*ListSnapshotsResult, error) {
	input := &ec2.DescribeSnapshotsInput{}

	// Apply owner filter
	if len(opts.OwnerIDs) > 0 {
		input.OwnerIds = opts.OwnerIDs
	}

	// Apply custom filters
	if len(opts.Filters) > 0 {
		for name, values := range opts.Filters {
			input.Filters = append(input.Filters, types.Filter{
				Name:   aws.String(name),
				Values: values,
			})
		}
	}

	// Apply max results (default to 100 for reasonable page sizes)
	maxResults := opts.MaxResults
	if maxResults <= 0 {
		maxResults = 100
	}
	input.MaxResults = aws.Int32(maxResults)

	// Apply pagination token
	if opts.NextToken != "" {
		input.NextToken = aws.String(opts.NextToken)
	}

	output, err := client.EC2().DescribeSnapshots(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("describe snapshots: %w", err)
	}

	summaries := make([]SnapshotSummary, 0, len(output.Snapshots))
	for _, snap := range output.Snapshots {
		summary := SnapshotSummary{
			SnapshotID:  aws.ToString(snap.SnapshotId),
			VolumeID:    aws.ToString(snap.VolumeId),
			VolumeSize:  aws.ToInt32(snap.VolumeSize),
			Description: aws.ToString(snap.Description),
			OwnerID:     aws.ToString(snap.OwnerId),
			State:       string(snap.State),
			Encrypted:   aws.ToBool(snap.Encrypted),
			Tags:        make(map[string]string),
		}
		if snap.StartTime != nil {
			summary.StartTime = snap.StartTime.Format("2006-01-02T15:04:05Z")
		}
		for _, tag := range snap.Tags {
			summary.Tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
		summaries = append(summaries, summary)
	}

	return &ListSnapshotsResult{
		Summaries: summaries,
		NextToken: aws.ToString(output.NextToken),
	}, nil
}

// ToCloudResource converts an AMISummary to a CloudResource proto.
func (s AMISummary) ToCloudResource(region string) *cloudv1.CloudResource {
	res := &cloudv1.CloudResource{
		Provider:     cloudv1.CloudProvider_CLOUD_PROVIDER_AWS,
		ResourceType: cloudv1.CloudResourceType_CLOUD_RESOURCE_TYPE_AWS_AMI,
		ResourceId:   s.ImageID,
		Region:       region,
		AccountId:    s.OwnerID,
		Name:         s.Name,
		Description:  s.Description,
		Tags:         s.Tags,
	}
	if s.CreationDate != "" {
		if t, err := time.Parse(time.RFC3339, s.CreationDate); err == nil {
			res.CreatedAt = timestamppb.New(t)
		}
	}
	return res
}

// ToCloudResource converts a SnapshotSummary to a CloudResource proto.
func (s SnapshotSummary) ToCloudResource(region string) *cloudv1.CloudResource {
	res := &cloudv1.CloudResource{
		Provider:     cloudv1.CloudProvider_CLOUD_PROVIDER_AWS,
		ResourceType: cloudv1.CloudResourceType_CLOUD_RESOURCE_TYPE_AWS_EBS_SNAPSHOT,
		ResourceId:   s.SnapshotID,
		Region:       region,
		AccountId:    s.OwnerID,
		Name:         s.SnapshotID, // Snapshots often don't have names
		Description:  s.Description,
		Tags:         s.Tags,
	}
	if s.StartTime != "" {
		if t, err := time.Parse(time.RFC3339, s.StartTime); err == nil {
			res.CreatedAt = timestamppb.New(t)
		}
	}
	return res
}
