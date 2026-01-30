package terraform

import "testing"

func TestMapProviderToGoModule(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"hashicorp/aws", "github.com/hashicorp/terraform-provider-aws"},
		{"hashicorp/google", "github.com/hashicorp/terraform-provider-google"},
		{"hashicorp/vault", "github.com/hashicorp/terraform-provider-vault"},
		{"hashicorp/azurerm", "github.com/hashicorp/terraform-provider-azurerm"},
		{"integrations/github", "github.com/integrations/terraform-provider-github"},
		{"digitalocean/digitalocean", "github.com/digitalocean/terraform-provider-digitalocean"},
		{"", ""},
		{"invalid", ""},
		{"  hashicorp/aws  ", "github.com/hashicorp/terraform-provider-aws"},
		{"  /aws", ""},
		{"hashicorp/  ", ""},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := MapProviderToGoModule(tt.source); got != tt.want {
				t.Errorf("MapProviderToGoModule(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestMapGitModuleToGoModule(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{
			"git::https://github.com/terraform-aws-modules/terraform-aws-eks.git?ref=v19.0.0",
			"github.com/terraform-aws-modules/terraform-aws-eks",
		},
		{
			"github.com/hashicorp/terraform-aws-consul",
			"github.com/hashicorp/terraform-aws-consul",
		},
		{
			"git::https://github.com/org/repo.git",
			"github.com/org/repo",
		},
		{
			"https://github.com/owner/repo",
			"github.com/owner/repo",
		},
		{"", ""},
		{"./local/module", ""},
		{"terraform-aws-modules/vpc/aws", ""},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := MapGitModuleToGoModule(tt.source); got != tt.want {
				t.Errorf("MapGitModuleToGoModule(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestExtractGitRef(t *testing.T) {
	tests := []struct {
		source string
		want   string
	}{
		{"git::https://github.com/org/repo.git?ref=v19.0.0", "v19.0.0"},
		{"git::https://github.com/org/repo.git?ref=main", "main"},
		{"git::https://github.com/org/repo.git?ref=v1.0.0&depth=1", "v1.0.0"},
		{"github.com/org/repo", ""},
		{"", ""},
		{"git::https://github.com/org/repo.git?ref=  v2.0.0  ", "v2.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.source, func(t *testing.T) {
			if got := ExtractGitRef(tt.source); got != tt.want {
				t.Errorf("ExtractGitRef(%q) = %q, want %q", tt.source, got, tt.want)
			}
		})
	}
}

func TestNormalizeGoVersion(t *testing.T) {
	tests := []struct {
		version string
		want    string
	}{
		{"5.31.0", "v5.31.0"},
		{"v5.31.0", "v5.31.0"},
		{"1.0.0", "v1.0.0"},
		{"", ""},
		{"  5.0.0  ", "v5.0.0"},
		{"  v3.0.0  ", "v3.0.0"},
	}

	for _, tt := range tests {
		t.Run(tt.version, func(t *testing.T) {
			if got := NormalizeGoVersion(tt.version); got != tt.want {
				t.Errorf("NormalizeGoVersion(%q) = %q, want %q", tt.version, got, tt.want)
			}
		})
	}
}

func TestGoModulePath(t *testing.T) {
	if GoModulePath != "github.com/hashicorp/terraform" {
		t.Errorf("GoModulePath = %q, want github.com/hashicorp/terraform", GoModulePath)
	}
}
