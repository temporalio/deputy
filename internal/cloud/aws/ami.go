package aws

import (
	"context"
	"fmt"
	"io/fs"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/service/ec2"
	"github.com/aws/aws-sdk-go-v2/service/ec2/types"

	"github.com/picatz/deputy/internal/cloud"
)

// AMI represents an Amazon Machine Image for scanning.
type AMI struct {
	client     *Client
	imageID    string
	image      *types.Image
	snapshotID string
	snapshot   *EBSSnapshot
	opts       cloud.Options
}

// OpenAMI opens an AMI for scanning.
func OpenAMI(ctx context.Context, client *Client, imageID string, opts cloud.Options) (*AMI, error) {
	ami := &AMI{
		client:  client,
		imageID: imageID,
		opts:    opts,
	}

	// Describe the AMI to get its metadata and root device
	if err := ami.resolve(ctx); err != nil {
		return nil, err
	}

	return ami, nil
}

// resolve fetches AMI metadata and identifies the root EBS snapshot.
func (a *AMI) resolve(ctx context.Context) error {
	output, err := a.client.EC2().DescribeImages(ctx, &ec2.DescribeImagesInput{
		ImageIds: []string{a.imageID},
	})
	if err != nil {
		return fmt.Errorf("describe AMI %s: %w", a.imageID, err)
	}

	if len(output.Images) == 0 {
		return fmt.Errorf("%w: AMI %s", cloud.ErrResourceNotFound, a.imageID)
	}

	a.image = &output.Images[0]

	// Find the root device's EBS snapshot
	rootDevice := aws.ToString(a.image.RootDeviceName)
	for _, mapping := range a.image.BlockDeviceMappings {
		deviceName := aws.ToString(mapping.DeviceName)
		if deviceName == rootDevice && mapping.Ebs != nil {
			a.snapshotID = aws.ToString(mapping.Ebs.SnapshotId)
			break
		}
	}

	if a.snapshotID == "" {
		return fmt.Errorf("no root EBS snapshot found for AMI %s", a.imageID)
	}

	return nil
}

// Provider implements cloud.Resource.
func (a *AMI) Provider() cloud.Provider {
	return cloud.ProviderAWS
}

// Type implements cloud.Resource.
func (a *AMI) Type() cloud.ResourceType {
	return cloud.ResourceTypeAWSAMI
}

// ID implements cloud.Resource.
func (a *AMI) ID() string {
	return a.imageID
}

// Region implements cloud.Resource.
func (a *AMI) Region() string {
	return a.client.Region()
}

// AccountID implements cloud.Resource.
func (a *AMI) AccountID() string {
	if a.image != nil {
		return aws.ToString(a.image.OwnerId)
	}
	return ""
}

// Tags implements cloud.Resource.
func (a *AMI) Tags() map[string]string {
	tags := make(map[string]string)
	if a.image != nil {
		for _, tag := range a.image.Tags {
			tags[aws.ToString(tag.Key)] = aws.ToString(tag.Value)
		}
	}
	return tags
}

// Name implements cloud.Resource.
func (a *AMI) Name() string {
	if a.image != nil {
		return aws.ToString(a.image.Name)
	}
	return ""
}

// FS implements cloud.Resource.
// It opens the root EBS snapshot and returns a filesystem view.
func (a *AMI) FS(ctx context.Context) (fs.FS, error) {
	if a.snapshot == nil {
		snapshot, err := OpenEBSSnapshot(ctx, a.client, a.snapshotID, a.opts)
		if err != nil {
			return nil, fmt.Errorf("open root snapshot %s: %w", a.snapshotID, err)
		}
		a.snapshot = snapshot
	}
	return a.snapshot.FS(ctx)
}

// Close implements cloud.Resource.
func (a *AMI) Close() error {
	if a.snapshot != nil {
		return a.snapshot.Close()
	}
	return nil
}

// SnapshotID returns the root EBS snapshot ID.
func (a *AMI) SnapshotID() string {
	return a.snapshotID
}

// Architecture returns the AMI architecture.
func (a *AMI) Architecture() string {
	if a.image != nil {
		return string(a.image.Architecture)
	}
	return ""
}

// Platform returns the AMI platform (e.g., "windows" or empty for Linux).
func (a *AMI) Platform() string {
	if a.image != nil {
		return aws.ToString(a.image.PlatformDetails)
	}
	return ""
}

var _ cloud.Resource = (*AMI)(nil)
