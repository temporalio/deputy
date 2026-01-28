package targets_test

import (
	"testing"

	"github.com/picatz/deputy/internal/targets"
)

func TestProviderContext_IsEmpty(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name  string
		ctx   *targets.ProviderContext
		empty bool
	}{
		{"nil", nil, true},
		{"zero value", &targets.ProviderContext{}, true},
		{"with aws_region", &targets.ProviderContext{AWSRegion: "us-west-2"}, false},
		{"with gcp_project", &targets.ProviderContext{GCPProject: "my-project"}, false},
		{"with extra", &targets.ProviderContext{Extra: map[string]string{"foo": "bar"}}, false},
		{"with empty extra", &targets.ProviderContext{Extra: map[string]string{}}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			if got := tt.ctx.IsEmpty(); got != tt.empty {
				t.Errorf("IsEmpty() = %v, want %v", got, tt.empty)
			}
		})
	}
}

func TestProviderContext_Clone(t *testing.T) {
	t.Parallel()

	original := &targets.ProviderContext{
		AWSRegion:  "us-west-2",
		GCPProject: "my-project",
		Extra:      map[string]string{"foo": "bar"},
	}

	clone := original.Clone()

	// Verify values are equal
	if clone.AWSRegion != original.AWSRegion {
		t.Errorf("AWSRegion = %q, want %q", clone.AWSRegion, original.AWSRegion)
	}
	if clone.GCPProject != original.GCPProject {
		t.Errorf("GCPProject = %q, want %q", clone.GCPProject, original.GCPProject)
	}
	if clone.Extra["foo"] != original.Extra["foo"] {
		t.Errorf("Extra[foo] = %q, want %q", clone.Extra["foo"], original.Extra["foo"])
	}

	// Verify it's a deep copy (modifying clone doesn't affect original)
	clone.AWSRegion = "eu-west-1"
	clone.Extra["foo"] = "modified"

	if original.AWSRegion != "us-west-2" {
		t.Errorf("original.AWSRegion was modified")
	}
	if original.Extra["foo"] != "bar" {
		t.Errorf("original.Extra was modified")
	}
}

func TestProviderContext_Merge(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name   string
		base   *targets.ProviderContext
		other  *targets.ProviderContext
		expect *targets.ProviderContext
	}{
		{
			name:   "nil base",
			base:   nil,
			other:  &targets.ProviderContext{AWSRegion: "us-west-2"},
			expect: &targets.ProviderContext{AWSRegion: "us-west-2"},
		},
		{
			name:   "nil other",
			base:   &targets.ProviderContext{AWSRegion: "us-west-2"},
			other:  nil,
			expect: &targets.ProviderContext{AWSRegion: "us-west-2"},
		},
		{
			name:   "other overrides",
			base:   &targets.ProviderContext{AWSRegion: "us-west-2", GCPProject: "base-project"},
			other:  &targets.ProviderContext{AWSRegion: "eu-west-1"},
			expect: &targets.ProviderContext{AWSRegion: "eu-west-1", GCPProject: "base-project"},
		},
		{
			name:   "merge extras",
			base:   &targets.ProviderContext{Extra: map[string]string{"a": "1"}},
			other:  &targets.ProviderContext{Extra: map[string]string{"b": "2"}},
			expect: &targets.ProviderContext{Extra: map[string]string{"a": "1", "b": "2"}},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			result := tt.base.Merge(tt.other)

			if tt.expect == nil {
				if result != nil {
					t.Errorf("Merge() = %v, want nil", result)
				}
				return
			}

			if result.AWSRegion != tt.expect.AWSRegion {
				t.Errorf("AWSRegion = %q, want %q", result.AWSRegion, tt.expect.AWSRegion)
			}
			if result.GCPProject != tt.expect.GCPProject {
				t.Errorf("GCPProject = %q, want %q", result.GCPProject, tt.expect.GCPProject)
			}
			for k, want := range tt.expect.Extra {
				if got := result.Extra[k]; got != want {
					t.Errorf("Extra[%q] = %q, want %q", k, got, want)
				}
			}
		})
	}
}

func TestProviderContext_Validate(t *testing.T) {
	t.Parallel()

	tests := []struct {
		name    string
		ctx     *targets.ProviderContext
		wantErr bool
	}{
		{"nil", nil, false},
		{"empty", &targets.ProviderContext{}, false},
		{"valid aws region", &targets.ProviderContext{AWSRegion: "us-west-2"}, false},
		{"valid aws region eu", &targets.ProviderContext{AWSRegion: "eu-central-1"}, false},
		{"valid aws region gov", &targets.ProviderContext{AWSRegion: "us-gov-west-1"}, false},
		{"invalid aws region too short", &targets.ProviderContext{AWSRegion: "us"}, true},
		{"invalid aws region no hyphen", &targets.ProviderContext{AWSRegion: "uswest2"}, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			t.Parallel()
			err := tt.ctx.Validate()
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestDefaultOpenOptions(t *testing.T) {
	t.Parallel()

	opts := targets.DefaultOpenOptions()

	if !opts.SmartDownload {
		t.Error("SmartDownload should default to true")
	}
	if opts.Platform != "" {
		t.Errorf("Platform should be empty, got %q", opts.Platform)
	}
	if len(opts.Ecosystems) != 0 {
		t.Errorf("Ecosystems should be empty, got %v", opts.Ecosystems)
	}
}

// Builder pattern tests

func TestListOptions_Builders(t *testing.T) {
	t.Parallel()

	t.Run("fluent chain", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewListOptions().
			WithTag("env", "prod").
			WithTag("team", "platform").
			WithNamePattern("web-*").
			WithCEL("resource.created_at > timestamp('2024-01-01')").
			WithAWS("us-west-2", "self")

		// Verify tags
		if opts.Tags["env"] != "prod" {
			t.Errorf("Tags[env] = %q, want %q", opts.Tags["env"], "prod")
		}
		if opts.Tags["team"] != "platform" {
			t.Errorf("Tags[team] = %q, want %q", opts.Tags["team"], "platform")
		}

		// Verify name pattern
		if opts.NamePattern != "web-*" {
			t.Errorf("NamePattern = %q, want %q", opts.NamePattern, "web-*")
		}

		// Verify CEL
		if opts.CELExpression == "" {
			t.Error("CELExpression should be set")
		}

		// Verify AWS context
		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.AWSRegion != "us-west-2" {
			t.Errorf("AWSRegion = %q, want %q", opts.Context.AWSRegion, "us-west-2")
		}
		if opts.Context.AWSOwner != "self" {
			t.Errorf("AWSOwner = %q, want %q", opts.Context.AWSOwner, "self")
		}
	})

	t.Run("WithTags", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewListOptions().
			WithTags(map[string]string{"a": "1", "b": "2"}).
			WithTag("c", "3") // Additional tag via WithTag

		if len(opts.Tags) != 3 {
			t.Errorf("len(Tags) = %d, want 3", len(opts.Tags))
		}
		if opts.Tags["a"] != "1" || opts.Tags["b"] != "2" || opts.Tags["c"] != "3" {
			t.Errorf("Tags = %v, want map with a:1 b:2 c:3", opts.Tags)
		}
	})

	t.Run("WithGCP", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewListOptions().WithGCP("my-project", "us-central1-a")

		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.GCPProject != "my-project" {
			t.Errorf("GCPProject = %q, want %q", opts.Context.GCPProject, "my-project")
		}
		if opts.Context.GCPLocation != "us-central1-a" {
			t.Errorf("GCPLocation = %q, want %q", opts.Context.GCPLocation, "us-central1-a")
		}
	})

	t.Run("WithAzure", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewListOptions().WithAzure("sub-123", "my-rg")

		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.AzureSubscription != "sub-123" {
			t.Errorf("AzureSubscription = %q, want %q", opts.Context.AzureSubscription, "sub-123")
		}
		if opts.Context.AzureResourceGroup != "my-rg" {
			t.Errorf("AzureResourceGroup = %q, want %q", opts.Context.AzureResourceGroup, "my-rg")
		}
	})

	t.Run("WithOrganization", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewListOptions().WithOrganization("my-org")

		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.Organization != "my-org" {
			t.Errorf("Organization = %q, want %q", opts.Context.Organization, "my-org")
		}
	})

	t.Run("WithContext", func(t *testing.T) {
		t.Parallel()

		ctx := &targets.ProviderContext{
			AWSRegion:  "eu-west-1",
			GCPProject: "shared-project",
		}
		opts := targets.NewListOptions().WithContext(ctx)

		if opts.Context != ctx {
			t.Error("Context should be the same reference")
		}
	})
}

func TestOpenOptions_Builders(t *testing.T) {
	t.Parallel()

	t.Run("fluent chain", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewOpenOptions().
			WithSmartDownload(false).
			WithPlatform("linux/arm64").
			WithEcosystems("go", "npm", "pypi").
			WithAWS("us-east-1")

		// Verify smart download
		if opts.SmartDownload {
			t.Error("SmartDownload should be false")
		}

		// Verify platform
		if opts.Platform != "linux/arm64" {
			t.Errorf("Platform = %q, want %q", opts.Platform, "linux/arm64")
		}

		// Verify ecosystems
		if len(opts.Ecosystems) != 3 {
			t.Errorf("len(Ecosystems) = %d, want 3", len(opts.Ecosystems))
		}

		// Verify AWS context
		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.AWSRegion != "us-east-1" {
			t.Errorf("AWSRegion = %q, want %q", opts.Context.AWSRegion, "us-east-1")
		}
	})

	t.Run("default values", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewOpenOptions()

		// SmartDownload should default to true
		if !opts.SmartDownload {
			t.Error("SmartDownload should default to true")
		}
	})

	t.Run("WithGCP", func(t *testing.T) {
		t.Parallel()

		opts := targets.NewOpenOptions().WithGCP("my-project", "us-central1")

		if opts.Context == nil {
			t.Fatal("Context should not be nil")
		}
		if opts.Context.GCPProject != "my-project" {
			t.Errorf("GCPProject = %q, want %q", opts.Context.GCPProject, "my-project")
		}
		if opts.Context.GCPLocation != "us-central1" {
			t.Errorf("GCPLocation = %q, want %q", opts.Context.GCPLocation, "us-central1")
		}
	})

	t.Run("WithContext", func(t *testing.T) {
		t.Parallel()

		ctx := &targets.ProviderContext{
			AzureSubscription: "sub-456",
		}
		opts := targets.NewOpenOptions().WithContext(ctx)

		if opts.Context != ctx {
			t.Error("Context should be the same reference")
		}
	})
}

func TestProviderContext_Builders(t *testing.T) {
	t.Parallel()

	t.Run("fluent chain", func(t *testing.T) {
		t.Parallel()

		ctx := targets.NewProviderContext().
			WithAWSRegion("us-west-2").
			WithAWSOwner("self").
			WithGCPProject("my-project").
			WithGCPLocation("us-central1").
			WithAzureSubscription("sub-123").
			WithAzureResourceGroup("my-rg").
			WithOrganization("my-org").
			WithExtra("custom", "value")

		if ctx.AWSRegion != "us-west-2" {
			t.Errorf("AWSRegion = %q, want %q", ctx.AWSRegion, "us-west-2")
		}
		if ctx.AWSOwner != "self" {
			t.Errorf("AWSOwner = %q, want %q", ctx.AWSOwner, "self")
		}
		if ctx.GCPProject != "my-project" {
			t.Errorf("GCPProject = %q, want %q", ctx.GCPProject, "my-project")
		}
		if ctx.GCPLocation != "us-central1" {
			t.Errorf("GCPLocation = %q, want %q", ctx.GCPLocation, "us-central1")
		}
		if ctx.AzureSubscription != "sub-123" {
			t.Errorf("AzureSubscription = %q, want %q", ctx.AzureSubscription, "sub-123")
		}
		if ctx.AzureResourceGroup != "my-rg" {
			t.Errorf("AzureResourceGroup = %q, want %q", ctx.AzureResourceGroup, "my-rg")
		}
		if ctx.Organization != "my-org" {
			t.Errorf("Organization = %q, want %q", ctx.Organization, "my-org")
		}
		if ctx.Extra["custom"] != "value" {
			t.Errorf("Extra[custom] = %q, want %q", ctx.Extra["custom"], "value")
		}
	})

	t.Run("initialized Extra map", func(t *testing.T) {
		t.Parallel()

		ctx := targets.NewProviderContext()

		if ctx.Extra == nil {
			t.Error("Extra map should be initialized")
		}
	})
}
