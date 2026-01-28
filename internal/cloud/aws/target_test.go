package aws_test

import (
	"context"
	"testing"

	"github.com/picatz/deputy/internal/cloud"
	"github.com/picatz/deputy/internal/cloud/aws"
)

func TestIsCollection(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// Collection URIs (plural)
		{"amis collection", "aws://amis", true},
		{"amis with owner", "aws://amis?owner=self", true},
		{"amis with region", "aws://amis?region=us-west-2", true},
		{"amis with multiple params", "aws://amis?owner=self&region=us-west-2&tags.env=prod", true},
		{"ebs-snapshots collection", "aws://ebs-snapshots", true},
		{"snapshots alias", "aws://snapshots", true},
		{"snapshots with tags", "aws://snapshots?tags.backup=daily", true},
		{"lambdas collection", "aws://lambdas", true},
		{"functions alias", "aws://functions", true},
		{"ecr-images collection", "aws://ecr-images", true},

		// Specific targets (singular with ID) - NOT collections
		{"specific ami", "aws://ami/ami-0123456789abcdef0", false},
		{"specific ebs", "aws://ebs/snap-0123456789abcdef0", false},
		{"specific snapshot", "aws://snapshot/snap-0123456789abcdef0", false},
		{"specific lambda", "aws://lambda/my-function", false},
		{"specific ecr", "aws://ecr/123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag", false},

		// Non-AWS targets
		{"not aws scheme", "docker://nginx:latest", false},
		{"bare ami id", "ami-0123456789abcdef0", false},
		{"bare snap id", "snap-0123456789abcdef0", false},
		{"github url", "github.com/owner/repo", false},
		{"empty string", "", false},

		// Edge cases
		{"unknown collection type", "aws://unknown-type", false},
		{"aws scheme only", "aws://", false},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := aws.IsCollection(ctx, tt.target)
			if got != tt.want {
				t.Errorf("IsCollection(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}

func TestParseCollectionTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantType   cloud.ResourceType
		wantRegion string
		wantOwner  string
		wantTags   map[string]string
		wantErr    bool
	}{
		{
			name:       "simple amis",
			target:     "aws://amis",
			wantType:   cloud.ResourceTypeAWSAMI,
			wantRegion: "",
			wantOwner:  "",
			wantTags:   map[string]string{},
		},
		{
			name:       "amis with owner",
			target:     "aws://amis?owner=self",
			wantType:   cloud.ResourceTypeAWSAMI,
			wantRegion: "",
			wantOwner:  "self",
			wantTags:   map[string]string{},
		},
		{
			name:       "amis with region",
			target:     "aws://amis?region=us-west-2",
			wantType:   cloud.ResourceTypeAWSAMI,
			wantRegion: "us-west-2",
			wantOwner:  "",
			wantTags:   map[string]string{},
		},
		{
			name:       "amis with all params",
			target:     "aws://amis?owner=self&region=us-east-1&tags.env=prod&tags.team=platform",
			wantType:   cloud.ResourceTypeAWSAMI,
			wantRegion: "us-east-1",
			wantOwner:  "self",
			wantTags:   map[string]string{"env": "prod", "team": "platform"},
		},
		{
			name:       "ebs-snapshots",
			target:     "aws://ebs-snapshots",
			wantType:   cloud.ResourceTypeAWSEBSSnapshot,
			wantRegion: "",
			wantOwner:  "",
			wantTags:   map[string]string{},
		},
		{
			name:       "snapshots alias",
			target:     "aws://snapshots?tags.backup=daily",
			wantType:   cloud.ResourceTypeAWSEBSSnapshot,
			wantRegion: "",
			wantOwner:  "",
			wantTags:   map[string]string{"backup": "daily"},
		},
		{
			name:       "lambdas",
			target:     "aws://lambdas",
			wantType:   cloud.ResourceTypeAWSLambda,
			wantRegion: "",
			wantOwner:  "",
			wantTags:   map[string]string{},
		},
		{
			name:       "functions alias",
			target:     "aws://functions?region=eu-west-1",
			wantType:   cloud.ResourceTypeAWSLambda,
			wantRegion: "eu-west-1",
			wantOwner:  "",
			wantTags:   map[string]string{},
		},

		// Error cases
		{
			name:    "non-aws scheme",
			target:  "docker://nginx",
			wantErr: true,
		},
		{
			name:    "unknown collection type",
			target:  "aws://unknown",
			wantErr: true,
		},
		{
			name:    "specific target not collection",
			target:  "aws://ami/ami-123",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, err := aws.ParseCollectionTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseCollectionTarget(%q) = nil error, want error", tt.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseCollectionTarget(%q) error = %v", tt.target, err)
			}
			if info.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", info.Type, tt.wantType)
			}
			if info.Region != tt.wantRegion {
				t.Errorf("Region = %q, want %q", info.Region, tt.wantRegion)
			}
			if info.Owner != tt.wantOwner {
				t.Errorf("Owner = %q, want %q", info.Owner, tt.wantOwner)
			}
			if len(info.Tags) != len(tt.wantTags) {
				t.Errorf("Tags count = %d, want %d", len(info.Tags), len(tt.wantTags))
			}
			for k, want := range tt.wantTags {
				if got := info.Tags[k]; got != want {
					t.Errorf("Tags[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestParseTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name       string
		target     string
		wantType   cloud.ResourceType
		wantID     string
		wantRegion string
		wantErr    bool
	}{
		// Bare resource IDs
		{
			name:     "bare ami id",
			target:   "ami-0123456789abcdef0",
			wantType: cloud.ResourceTypeAWSAMI,
			wantID:   "ami-0123456789abcdef0",
		},
		{
			name:     "bare snap id",
			target:   "snap-0123456789abcdef0",
			wantType: cloud.ResourceTypeAWSEBSSnapshot,
			wantID:   "snap-0123456789abcdef0",
		},

		// Full URIs
		{
			name:     "ami uri",
			target:   "aws://ami/ami-abc123",
			wantType: cloud.ResourceTypeAWSAMI,
			wantID:   "ami-abc123",
		},
		{
			name:       "ami with region",
			target:     "aws://ami/ami-abc123?region=us-west-2",
			wantType:   cloud.ResourceTypeAWSAMI,
			wantID:     "ami-abc123",
			wantRegion: "us-west-2",
		},
		{
			name:     "ebs snapshot uri",
			target:   "aws://ebs/snap-abc123",
			wantType: cloud.ResourceTypeAWSEBSSnapshot,
			wantID:   "snap-abc123",
		},
		{
			name:     "snapshot alias",
			target:   "aws://snapshot/snap-abc123",
			wantType: cloud.ResourceTypeAWSEBSSnapshot,
			wantID:   "snap-abc123",
		},
		{
			name:     "lambda uri",
			target:   "aws://lambda/my-function",
			wantType: cloud.ResourceTypeAWSLambda,
			wantID:   "my-function",
		},
		{
			name:     "function alias",
			target:   "aws://function/my-function:prod",
			wantType: cloud.ResourceTypeAWSLambda,
			wantID:   "my-function:prod",
		},
		{
			name:     "ecr image",
			target:   "aws://ecr/123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
			wantType: cloud.ResourceTypeAWSECRImage,
			wantID:   "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag",
		},

		// Error cases
		{
			name:    "non-aws scheme",
			target:  "docker://nginx",
			wantErr: true,
		},
		{
			name:    "ami uri without ami- prefix",
			target:  "aws://ami/invalid-id",
			wantErr: true,
		},
		{
			name:    "ebs without snap- prefix",
			target:  "aws://ebs/invalid-id",
			wantErr: true,
		},
		{
			name:    "unknown resource type",
			target:  "aws://unknown/resource-id",
			wantErr: true,
		},
		{
			name:    "missing resource id",
			target:  "aws://ami",
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			info, err := aws.ParseTarget(tt.target)
			if tt.wantErr {
				if err == nil {
					t.Errorf("ParseTarget(%q) = nil error, want error", tt.target)
				}
				return
			}
			if err != nil {
				t.Fatalf("ParseTarget(%q) error = %v", tt.target, err)
			}
			if info.Type != tt.wantType {
				t.Errorf("Type = %v, want %v", info.Type, tt.wantType)
			}
			if info.ResourceID != tt.wantID {
				t.Errorf("ResourceID = %q, want %q", info.ResourceID, tt.wantID)
			}
			if info.Region != tt.wantRegion {
				t.Errorf("Region = %q, want %q", info.Region, tt.wantRegion)
			}
		})
	}
}

func TestDetect(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		target string
		want   bool
	}{
		// AWS targets
		{"aws scheme", "aws://amis", true},
		{"aws ami uri", "aws://ami/ami-123", true},
		{"bare ami id", "ami-0123456789abcdef0", true},
		{"bare snap id", "snap-0123456789abcdef0", true},
		{"ecr registry", "123456789012.dkr.ecr.us-east-1.amazonaws.com/repo:tag", true},

		// Non-AWS targets
		{"docker scheme", "docker://nginx", false},
		{"github url", "github.com/owner/repo", false},
		{"local path", "./src", false},
		{"empty string", "", false},
		{"ghcr image", "ghcr.io/owner/repo:v1", false},
	}

	ctx := context.Background()
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			got := aws.Detect(ctx, tt.target)
			if got != tt.want {
				t.Errorf("Detect(%q) = %v, want %v", tt.target, got, tt.want)
			}
		})
	}
}
