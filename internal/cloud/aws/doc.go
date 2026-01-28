// Package aws provides AWS cloud resource scanning for Deputy.
//
// # Supported Resources
//
//   - AMI (Amazon Machine Image): aws://ami/ami-xxx
//   - EBS Snapshot: aws://ebs/snap-xxx
//   - Lambda Function: aws://lambda/function-name
//   - ECR Image: aws://ecr/account.dkr.ecr.region.amazonaws.com/repo:tag
//
// # Authentication
//
// Authentication uses the standard AWS SDK credential chain:
//  1. Environment variables (AWS_ACCESS_KEY_ID, AWS_SECRET_ACCESS_KEY)
//  2. Shared credentials file (~/.aws/credentials)
//  3. IAM instance profile (for EC2/ECS/Lambda)
//
// The --profile flag selects a named profile from ~/.aws/credentials.
// The --region flag overrides the default region.
//
// # Smart Block Downloading
//
// For EBS snapshots, the package uses the EBS Direct API to download only
// blocks containing package databases (dpkg, rpm, apk, etc.). This typically
// reduces download size to ~7% of the total snapshot, dramatically improving
// scan times for large volumes.
//
// The smart download algorithm:
//  1. Parse the ext4 superblock to understand filesystem layout
//  2. Resolve well-known paths (/var/lib/dpkg, /var/lib/rpm, etc.) to inodes
//  3. Map inodes to disk blocks
//  4. Download only those blocks via EBS Direct API
//
// # Required IAM Permissions
//
// For AMI scanning:
//   - ec2:DescribeImages
//   - ec2:DescribeSnapshots
//   - ebs:ListSnapshotBlocks
//   - ebs:GetSnapshotBlock
//
// For Lambda scanning:
//   - lambda:GetFunction
//   - lambda:GetFunctionConfiguration
//
// For ECR scanning:
//   - ecr:GetAuthorizationToken
//   - ecr:BatchGetImage
//   - ecr:GetDownloadUrlForLayer
//
// # URI Format
//
//	aws://ami/ami-0123456789abcdef0
//	aws://ami/ami-0123456789abcdef0?region=us-west-2
//	aws://ebs/snap-0123456789abcdef0
//	aws://lambda/my-function
//	aws://lambda/my-function:$LATEST
//	aws://lambda/arn:aws:lambda:us-east-1:123456789012:function:my-function
//	aws://ecr/123456789012.dkr.ecr.us-east-1.amazonaws.com/my-repo:latest
package aws
