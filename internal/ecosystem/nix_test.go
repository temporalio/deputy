package ecosystem

import (
	"testing"
)

func TestParseNixPackageName(t *testing.T) {
	tests := []struct {
		name        string
		nixPkgName  string
		version     string
		wantEco     Ecosystem
		wantName    string
		wantMapped  bool
		wantCPE     bool
		wantCPEBase string
	}{
		// Python packages
		{
			name:       "python3Packages",
			nixPkgName: "python3Packages.requests",
			version:    "2.31.0",
			wantEco:    PyPI,
			wantName:   "requests",
			wantMapped: true,
		},
		{
			name:       "python312Packages",
			nixPkgName: "python312Packages.flask",
			version:    "3.0.0",
			wantEco:    PyPI,
			wantName:   "flask",
			wantMapped: true,
		},
		{
			name:       "pythonPackages",
			nixPkgName: "pythonPackages.numpy",
			version:    "1.24.0",
			wantEco:    PyPI,
			wantName:   "numpy",
			wantMapped: true,
		},

		// Node.js packages
		{
			name:       "nodePackages",
			nixPkgName: "nodePackages.typescript",
			version:    "5.0.0",
			wantEco:    NPM,
			wantName:   "typescript",
			wantMapped: true,
		},
		{
			name:       "nodePackages_latest",
			nixPkgName: "nodePackages_latest.pnpm",
			version:    "8.0.0",
			wantEco:    NPM,
			wantName:   "pnpm",
			wantMapped: true,
		},

		// Ruby gems
		{
			name:       "rubyGems",
			nixPkgName: "rubyGems.rails",
			version:    "7.1.0",
			wantEco:    RubyGems,
			wantName:   "rails",
			wantMapped: true,
		},

		// Rust packages
		{
			name:       "rustPackages",
			nixPkgName: "rustPackages.ripgrep",
			version:    "14.0.0",
			wantEco:    Cargo,
			wantName:   "ripgrep",
			wantMapped: true,
		},

		// Elixir/Erlang packages
		{
			name:       "beamPackages",
			nixPkgName: "beamPackages.phoenix",
			version:    "1.7.0",
			wantEco:    Hex,
			wantName:   "phoenix",
			wantMapped: true,
		},
		{
			name:       "elixirPackages",
			nixPkgName: "elixirPackages.ecto",
			version:    "3.10.0",
			wantEco:    Hex,
			wantName:   "ecto",
			wantMapped: true,
		},

		// PHP packages
		{
			name:       "phpPackages",
			nixPkgName: "phpPackages.composer",
			version:    "2.6.0",
			wantEco:    Packagist,
			wantName:   "composer",
			wantMapped: true,
		},

		// Native packages with CPE
		{
			name:        "openssl",
			nixPkgName:  "openssl",
			version:     "3.0.10",
			wantEco:     Unknown,
			wantName:    "openssl",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:openssl:openssl",
		},
		{
			name:        "curl",
			nixPkgName:  "curl",
			version:     "8.4.0",
			wantEco:     Unknown,
			wantName:    "curl",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:curl:curl",
		},
		{
			name:        "zlib",
			nixPkgName:  "zlib",
			version:     "1.3",
			wantEco:     Unknown,
			wantName:    "zlib",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:zlib:zlib",
		},
		{
			name:        "nginx",
			nixPkgName:  "nginx",
			version:     "1.25.0",
			wantEco:     Unknown,
			wantName:    "nginx",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:nginx:nginx",
		},
		{
			name:        "postgresql",
			nixPkgName:  "postgresql",
			version:     "16.0",
			wantEco:     Unknown,
			wantName:    "postgresql",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:postgresql:postgresql",
		},
		{
			name:        "git",
			nixPkgName:  "git",
			version:     "2.43.0",
			wantEco:     Unknown,
			wantName:    "git",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:git:git",
		},
		{
			name:        "ffmpeg",
			nixPkgName:  "ffmpeg",
			version:     "6.1",
			wantEco:     Unknown,
			wantName:    "ffmpeg",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:ffmpeg:ffmpeg",
		},

		// Version suffix stripping for CPE
		{
			name:        "openssl_3",
			nixPkgName:  "openssl_3",
			version:     "3.0.10",
			wantEco:     Unknown,
			wantName:    "openssl",
			wantMapped:  false,
			wantCPE:     true,
			wantCPEBase: "cpe:2.3:a:openssl:openssl",
		},

		// Unknown package (no mapping)
		{
			name:       "unknown custom package",
			nixPkgName: "my-custom-package",
			version:    "1.0.0",
			wantEco:    Unknown,
			wantName:   "my-custom-package",
			wantMapped: false,
			wantCPE:    false,
		},

		// Empty input
		{
			name:       "empty",
			nixPkgName: "",
			version:    "",
			wantEco:    Unknown,
			wantName:   "",
			wantMapped: false,
			wantCPE:    false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			info := ParseNixPackageName(tt.nixPkgName, tt.version)

			if tt.wantMapped && !info.IsMapped {
				t.Errorf("expected IsMapped=true, got false")
			}
			if !tt.wantMapped && info.IsMapped {
				t.Errorf("expected IsMapped=false, got true")
			}

			if tt.wantMapped {
				if info.Ecosystem != tt.wantEco {
					t.Errorf("Ecosystem = %v, want %v", info.Ecosystem, tt.wantEco)
				}
			}

			if info.Name != tt.wantName {
				t.Errorf("Name = %q, want %q", info.Name, tt.wantName)
			}

			if tt.wantCPE {
				if !info.HasCPE() {
					t.Errorf("expected HasCPE()=true, got false")
				}
				if info.CPE != tt.wantCPEBase {
					t.Errorf("CPE = %q, want %q", info.CPE, tt.wantCPEBase)
				}
			} else if tt.wantMapped {
				// Mapped packages shouldn't have CPE
				if info.HasCPE() {
					t.Errorf("expected HasCPE()=false for mapped package, got true")
				}
			}
		})
	}
}

func TestNixUpstreamPURL(t *testing.T) {
	tests := []struct {
		name     string
		info     NixUpstreamInfo
		wantPURL string
	}{
		{
			name: "pypi",
			info: NixUpstreamInfo{
				Ecosystem: PyPI,
				Name:      "requests",
				Version:   "2.31.0",
				IsMapped:  true,
			},
			wantPURL: "pkg:pypi/requests@2.31.0",
		},
		{
			name: "npm",
			info: NixUpstreamInfo{
				Ecosystem: NPM,
				Name:      "typescript",
				Version:   "5.0.0",
				IsMapped:  true,
			},
			wantPURL: "pkg:npm/typescript@5.0.0",
		},
		{
			name: "cargo",
			info: NixUpstreamInfo{
				Ecosystem: Cargo,
				Name:      "serde",
				Version:   "1.0.195",
				IsMapped:  true,
			},
			wantPURL: "pkg:cargo/serde@1.0.195",
		},
		{
			name: "rubygems",
			info: NixUpstreamInfo{
				Ecosystem: RubyGems,
				Name:      "rails",
				Version:   "7.1.0",
				IsMapped:  true,
			},
			wantPURL: "pkg:gem/rails@7.1.0",
		},
		{
			name: "hex",
			info: NixUpstreamInfo{
				Ecosystem: Hex,
				Name:      "phoenix",
				Version:   "1.7.0",
				IsMapped:  true,
			},
			wantPURL: "pkg:hex/phoenix@1.7.0",
		},
		{
			name: "packagist",
			info: NixUpstreamInfo{
				Ecosystem: Packagist,
				Name:      "laravel/framework",
				Version:   "10.0.0",
				IsMapped:  true,
			},
			wantPURL: "pkg:composer/laravel/framework@10.0.0",
		},
		{
			name: "no version",
			info: NixUpstreamInfo{
				Ecosystem: PyPI,
				Name:      "requests",
				IsMapped:  true,
			},
			wantPURL: "pkg:pypi/requests",
		},
		{
			name: "not mapped",
			info: NixUpstreamInfo{
				Name:     "openssl",
				Version:  "3.0.10",
				IsMapped: false,
			},
			wantPURL: "",
		},
		{
			name: "unknown ecosystem",
			info: NixUpstreamInfo{
				Ecosystem: Unknown,
				Name:      "something",
				Version:   "1.0",
				IsMapped:  true,
			},
			wantPURL: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.NixUpstreamPURL()
			if got != tt.wantPURL {
				t.Errorf("NixUpstreamPURL() = %q, want %q", got, tt.wantPURL)
			}
		})
	}
}

func TestNixFullCPE(t *testing.T) {
	tests := []struct {
		name    string
		info    NixUpstreamInfo
		wantCPE string
	}{
		{
			name: "openssl with version",
			info: NixUpstreamInfo{
				Name:    "openssl",
				Version: "3.0.10",
				CPE:     "cpe:2.3:a:openssl:openssl",
			},
			wantCPE: "cpe:2.3:a:openssl:openssl:3.0.10:*:*:*:*:*:*:*",
		},
		{
			name: "curl with version",
			info: NixUpstreamInfo{
				Name:    "curl",
				Version: "8.4.0",
				CPE:     "cpe:2.3:a:curl:curl",
			},
			wantCPE: "cpe:2.3:a:curl:curl:8.4.0:*:*:*:*:*:*:*",
		},
		{
			name: "no version defaults to wildcard",
			info: NixUpstreamInfo{
				Name: "nginx",
				CPE:  "cpe:2.3:a:nginx:nginx",
			},
			wantCPE: "cpe:2.3:a:nginx:nginx:*:*:*:*:*:*:*:*",
		},
		{
			name: "no CPE mapping",
			info: NixUpstreamInfo{
				Name:    "unknown-pkg",
				Version: "1.0.0",
			},
			wantCPE: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.info.FullCPE()
			if got != tt.wantCPE {
				t.Errorf("FullCPE() = %q, want %q", got, tt.wantCPE)
			}
		})
	}
}

func TestNixUpstreamInfo_Helpers(t *testing.T) {
	t.Run("HasUpstreamEcosystem", func(t *testing.T) {
		tests := []struct {
			info NixUpstreamInfo
			want bool
		}{
			{NixUpstreamInfo{Ecosystem: PyPI, IsMapped: true}, true},
			{NixUpstreamInfo{Ecosystem: NPM, IsMapped: true}, true},
			{NixUpstreamInfo{Ecosystem: Unknown, IsMapped: true}, false},
			{NixUpstreamInfo{Ecosystem: PyPI, IsMapped: false}, false},
			{NixUpstreamInfo{}, false},
		}

		for i, tt := range tests {
			if got := tt.info.HasUpstreamEcosystem(); got != tt.want {
				t.Errorf("test %d: HasUpstreamEcosystem() = %v, want %v", i, got, tt.want)
			}
		}
	})

	t.Run("HasCPE", func(t *testing.T) {
		tests := []struct {
			info NixUpstreamInfo
			want bool
		}{
			{NixUpstreamInfo{CPE: "cpe:2.3:a:openssl:openssl"}, true},
			{NixUpstreamInfo{CPE: ""}, false},
			{NixUpstreamInfo{}, false},
		}

		for i, tt := range tests {
			if got := tt.info.HasCPE(); got != tt.want {
				t.Errorf("test %d: HasCPE() = %v, want %v", i, got, tt.want)
			}
		}
	})
}
