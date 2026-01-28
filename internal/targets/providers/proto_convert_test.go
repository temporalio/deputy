package providers

import (
	"testing"

	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
	"github.com/picatz/deputy/internal/targets"
)

func TestListOptionsToProto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     *targets.ListOptions
		wantNil  bool
		validate func(*testing.T, *cloudv1.ListFilter)
	}{
		{
			name:    "nil opts",
			opts:    nil,
			wantNil: true,
		},
		{
			name:    "empty opts",
			opts:    &targets.ListOptions{},
			wantNil: true,
		},
		{
			name: "with tags",
			opts: &targets.ListOptions{
				Tags: map[string]string{"env": "prod"},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Tags["env"] != "prod" {
					t.Errorf("Tags[env] = %q, want %q", f.Tags["env"], "prod")
				}
			},
		},
		{
			name: "with name pattern",
			opts: &targets.ListOptions{
				NamePattern: "web-*",
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.NamePattern != "web-*" {
					t.Errorf("NamePattern = %q, want %q", f.NamePattern, "web-*")
				}
			},
		},
		{
			name: "with CEL expression",
			opts: &targets.ListOptions{
				CELExpression: "resource.tags.env == 'prod'",
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.CelExpression != "resource.tags.env == 'prod'" {
					t.Errorf("CelExpression = %q, want %q", f.CelExpression, "resource.tags.env == 'prod'")
				}
			},
		},
		{
			name: "with AWS context",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					AWSRegion: "us-west-2",
					AWSOwner:  "self",
				},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if f.Context.AwsRegion != "us-west-2" {
					t.Errorf("AwsRegion = %q, want %q", f.Context.AwsRegion, "us-west-2")
				}
				if f.Context.AwsOwner != "self" {
					t.Errorf("AwsOwner = %q, want %q", f.Context.AwsOwner, "self")
				}
			},
		},
		{
			name: "with GCP context",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					GCPProject:  "my-project",
					GCPLocation: "us-central1",
				},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if f.Context.GcpProject != "my-project" {
					t.Errorf("GcpProject = %q, want %q", f.Context.GcpProject, "my-project")
				}
				if f.Context.GcpLocation != "us-central1" {
					t.Errorf("GcpLocation = %q, want %q", f.Context.GcpLocation, "us-central1")
				}
			},
		},
		{
			name: "with Azure context",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					AzureSubscription:  "sub-123",
					AzureResourceGroup: "rg-prod",
				},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if f.Context.AzureSubscription != "sub-123" {
					t.Errorf("AzureSubscription = %q, want %q", f.Context.AzureSubscription, "sub-123")
				}
				if f.Context.AzureResourceGroup != "rg-prod" {
					t.Errorf("AzureResourceGroup = %q, want %q", f.Context.AzureResourceGroup, "rg-prod")
				}
			},
		},
		{
			name: "with SCM context",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					Organization: "my-org",
				},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if f.Context.ScmOrganization != "my-org" {
					t.Errorf("ScmOrganization = %q, want %q", f.Context.ScmOrganization, "my-org")
				}
			},
		},
		{
			name: "with extra context",
			opts: &targets.ListOptions{
				Context: &targets.ProviderContext{
					Extra: map[string]string{"custom": "value"},
				},
			},
			validate: func(t *testing.T, f *cloudv1.ListFilter) {
				if f.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if f.Context.Extra["custom"] != "value" {
					t.Errorf("Extra[custom] = %q, want %q", f.Context.Extra["custom"], "value")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ListOptionsToProto(tt.opts)
			if tt.wantNil {
				if result != nil {
					t.Errorf("ListOptionsToProto() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("ListOptionsToProto() = nil, want non-nil")
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestOpenOptionsToProto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		opts     *targets.OpenOptions
		wantNil  bool
		validate func(*testing.T, *cloudv1.OpenOptions)
	}{
		{
			name:    "nil opts",
			opts:    nil,
			wantNil: true,
		},
		{
			name: "with smart download",
			opts: &targets.OpenOptions{
				SmartDownload: true,
			},
			validate: func(t *testing.T, o *cloudv1.OpenOptions) {
				if !o.SmartDownload {
					t.Error("expected SmartDownload to be true")
				}
			},
		},
		{
			name: "with platform",
			opts: &targets.OpenOptions{
				Platform: "linux/amd64",
			},
			validate: func(t *testing.T, o *cloudv1.OpenOptions) {
				if o.Platform != "linux/amd64" {
					t.Errorf("Platform = %q, want %q", o.Platform, "linux/amd64")
				}
			},
		},
		{
			name: "with ecosystems",
			opts: &targets.OpenOptions{
				Ecosystems: []string{"go", "npm", "pypi"},
			},
			validate: func(t *testing.T, o *cloudv1.OpenOptions) {
				if len(o.Ecosystems) != 3 {
					t.Errorf("Ecosystems length = %d, want 3", len(o.Ecosystems))
				}
			},
		},
		{
			name: "with skip verification",
			opts: &targets.OpenOptions{
				SkipVerification: true,
			},
			validate: func(t *testing.T, o *cloudv1.OpenOptions) {
				if !o.SkipVerification {
					t.Error("expected SkipVerification to be true")
				}
			},
		},
		{
			name: "with context",
			opts: &targets.OpenOptions{
				Context: &targets.ProviderContext{
					AWSRegion: "us-west-2",
				},
			},
			validate: func(t *testing.T, o *cloudv1.OpenOptions) {
				if o.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if o.Context.AwsRegion != "us-west-2" {
					t.Errorf("AwsRegion = %q, want %q", o.Context.AwsRegion, "us-west-2")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := OpenOptionsToProto(tt.opts)
			if tt.wantNil {
				if result != nil {
					t.Errorf("OpenOptionsToProto() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("OpenOptionsToProto() = nil, want non-nil")
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestListOptionsFromProto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		filter   *cloudv1.ListFilter
		wantNil  bool
		validate func(*testing.T, *targets.ListOptions)
	}{
		{
			name:    "nil filter",
			filter:  nil,
			wantNil: true,
		},
		{
			name: "with tags",
			filter: &cloudv1.ListFilter{
				Tags: map[string]string{"env": "prod"},
			},
			validate: func(t *testing.T, o *targets.ListOptions) {
				if o.Tags["env"] != "prod" {
					t.Errorf("Tags[env] = %q, want %q", o.Tags["env"], "prod")
				}
			},
		},
		{
			name: "with name pattern",
			filter: &cloudv1.ListFilter{
				NamePattern: "web-*",
			},
			validate: func(t *testing.T, o *targets.ListOptions) {
				if o.NamePattern != "web-*" {
					t.Errorf("NamePattern = %q, want %q", o.NamePattern, "web-*")
				}
			},
		},
		{
			name: "with context",
			filter: &cloudv1.ListFilter{
				Context: &cloudv1.ProviderContext{
					AwsRegion: "us-west-2",
				},
			},
			validate: func(t *testing.T, o *targets.ListOptions) {
				if o.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if o.Context.AWSRegion != "us-west-2" {
					t.Errorf("AWSRegion = %q, want %q", o.Context.AWSRegion, "us-west-2")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := ListOptionsFromProto(tt.filter)
			if tt.wantNil {
				if result != nil {
					t.Errorf("ListOptionsFromProto() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("ListOptionsFromProto() = nil, want non-nil")
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestOpenOptionsFromProto(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name     string
		proto    *cloudv1.OpenOptions
		wantNil  bool
		validate func(*testing.T, *targets.OpenOptions)
	}{
		{
			name:    "nil proto",
			proto:   nil,
			wantNil: true,
		},
		{
			name: "with smart download",
			proto: &cloudv1.OpenOptions{
				SmartDownload: true,
			},
			validate: func(t *testing.T, o *targets.OpenOptions) {
				if !o.SmartDownload {
					t.Error("expected SmartDownload to be true")
				}
			},
		},
		{
			name: "with platform",
			proto: &cloudv1.OpenOptions{
				Platform: "linux/amd64",
			},
			validate: func(t *testing.T, o *targets.OpenOptions) {
				if o.Platform != "linux/amd64" {
					t.Errorf("Platform = %q, want %q", o.Platform, "linux/amd64")
				}
			},
		},
		{
			name: "with context",
			proto: &cloudv1.OpenOptions{
				Context: &cloudv1.ProviderContext{
					GcpProject: "my-project",
				},
			},
			validate: func(t *testing.T, o *targets.OpenOptions) {
				if o.Context == nil {
					t.Fatal("expected Context to be set")
				}
				if o.Context.GCPProject != "my-project" {
					t.Errorf("GCPProject = %q, want %q", o.Context.GCPProject, "my-project")
				}
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := OpenOptionsFromProto(tt.proto)
			if tt.wantNil {
				if result != nil {
					t.Errorf("OpenOptionsFromProto() = %v, want nil", result)
				}
				return
			}
			if result == nil {
				t.Fatal("OpenOptionsFromProto() = nil, want non-nil")
			}
			if tt.validate != nil {
				tt.validate(t, result)
			}
		})
	}
}

func TestProtoRoundTrip(t *testing.T) {
	t.Parallel()

	// Test that Deputy types → proto → Deputy types preserves values
	original := &targets.ListOptions{
		Tags:          map[string]string{"env": "prod", "team": "platform"},
		NamePattern:   "web-*",
		CELExpression: "resource.tags.env == 'prod'",
		Context: &targets.ProviderContext{
			AWSRegion:          "us-west-2",
			AWSOwner:           "self",
			GCPProject:         "my-project",
			GCPLocation:        "us-central1",
			AzureSubscription:  "sub-123",
			AzureResourceGroup: "rg-prod",
			Organization:       "my-org",
			Extra:              map[string]string{"custom": "value"},
		},
	}

	// Convert to proto and back
	proto := ListOptionsToProto(original)
	roundTripped := ListOptionsFromProto(proto)

	// Verify values match
	if roundTripped.NamePattern != original.NamePattern {
		t.Errorf("NamePattern = %q, want %q", roundTripped.NamePattern, original.NamePattern)
	}
	if roundTripped.CELExpression != original.CELExpression {
		t.Errorf("CELExpression = %q, want %q", roundTripped.CELExpression, original.CELExpression)
	}
	for k, want := range original.Tags {
		if got := roundTripped.Tags[k]; got != want {
			t.Errorf("Tags[%q] = %q, want %q", k, got, want)
		}
	}

	if roundTripped.Context == nil {
		t.Fatal("expected Context to be preserved")
	}
	if roundTripped.Context.AWSRegion != original.Context.AWSRegion {
		t.Errorf("AWSRegion = %q, want %q", roundTripped.Context.AWSRegion, original.Context.AWSRegion)
	}
	if roundTripped.Context.GCPProject != original.Context.GCPProject {
		t.Errorf("GCPProject = %q, want %q", roundTripped.Context.GCPProject, original.Context.GCPProject)
	}
	if roundTripped.Context.Organization != original.Context.Organization {
		t.Errorf("Organization = %q, want %q", roundTripped.Context.Organization, original.Context.Organization)
	}
}
