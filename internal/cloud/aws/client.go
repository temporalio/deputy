package aws

import (
	"context"
	"fmt"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/ebs"
	"github.com/aws/aws-sdk-go-v2/service/ec2"

	"github.com/picatz/deputy/internal/cloud"
)

// Client provides access to AWS services for cloud scanning.
type Client struct {
	cfg aws.Config
	ec2 *ec2.Client
	ebs *ebs.Client
}

// NewClient creates a new AWS client with the given options.
//
// Authentication uses the standard AWS SDK v2 credential chain, which tries
// sources in this order:
//  1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY, AWS_SESSION_TOKEN)
//  2. Shared credentials file (~/.aws/credentials)
//  3. Shared config file (~/.aws/config) if AWS_SDK_LOAD_CONFIG is set
//  4. IAM role for Amazon EC2 (instance metadata)
//  5. IAM role for Amazon ECS (container credentials)
//  6. Web Identity Token (for EKS OIDC federation)
//
// This means Deputy "just works" in most deployment scenarios without any
// explicit credential configuration:
//   - Local development: Uses ~/.aws/credentials or environment variables
//   - EC2 instances: Uses the instance's IAM role
//   - EKS pods: Uses IRSA (IAM Roles for Service Accounts) via web identity
//   - GitHub Actions: Uses OIDC federation with AWS
//   - ECS tasks: Uses task IAM role
//
// Use opts.Profile to select a specific profile from ~/.aws/credentials.
// Use opts.Region to override the region (otherwise uses AWS_REGION or profile default).
func NewClient(ctx context.Context, opts cloud.Options) (*Client, error) {
	loadOpts := []func(*config.LoadOptions) error{}

	if opts.Region != "" {
		loadOpts = append(loadOpts, config.WithRegion(opts.Region))
	}

	if opts.Profile != "" {
		loadOpts = append(loadOpts, config.WithSharedConfigProfile(opts.Profile))
	}

	cfg, err := config.LoadDefaultConfig(ctx, loadOpts...)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", cloud.ErrAuthenticationFailed, err)
	}

	return &Client{
		cfg: cfg,
		ec2: ec2.NewFromConfig(cfg),
		ebs: ebs.NewFromConfig(cfg),
	}, nil
}

// EC2 returns the EC2 client.
func (c *Client) EC2() *ec2.Client {
	return c.ec2
}

// EBS returns the EBS client.
func (c *Client) EBS() *ebs.Client {
	return c.ebs
}

// Config returns the underlying AWS config.
func (c *Client) Config() aws.Config {
	return c.cfg
}

// Region returns the configured region.
func (c *Client) Region() string {
	return c.cfg.Region
}

// WithRegion returns a new client configured for a different region.
// The context is accepted for consistency and future tracing/logging support.
func (c *Client) WithRegion(_ context.Context, region string) *Client {
	if region == "" || region == c.cfg.Region {
		return c
	}

	cfg := c.cfg.Copy()
	cfg.Region = region

	return &Client{
		cfg: cfg,
		ec2: ec2.NewFromConfig(cfg),
		ebs: ebs.NewFromConfig(cfg),
	}
}
