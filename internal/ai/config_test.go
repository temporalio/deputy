package ai

import (
	"testing"
)

func TestApprovalConfig_ToPolicy(t *testing.T) {
	tests := []struct {
		name     string
		config   ApprovalConfig
		wantCmd  ApprovalMode
		wantFile ApprovalMode
		wantHigh bool
	}{
		{
			name:     "default config (commands=true, files=false, high=true)",
			config:   DefaultConfig().Approval,
			wantCmd:  ApprovalRequired,
			wantFile: ApprovalNotRequired,
			wantHigh: true,
		},
		{
			name: "required=true overrides everything",
			config: ApprovalConfig{
				Required:   true,
				Commands:   false,
				FileWrites: false,
				HighRisk:   false,
			},
			wantCmd:  ApprovalRequired,
			wantFile: ApprovalRequired,
			wantHigh: false,
		},
		{
			name: "all disabled",
			config: ApprovalConfig{
				Required:   false,
				Commands:   false,
				FileWrites: false,
				HighRisk:   false,
			},
			wantCmd:  ApprovalNotRequired,
			wantFile: ApprovalNotRequired,
			wantHigh: false,
		},
		{
			name: "all enabled",
			config: ApprovalConfig{
				Required:   false,
				Commands:   true,
				FileWrites: true,
				HighRisk:   true,
			},
			wantCmd:  ApprovalRequired,
			wantFile: ApprovalRequired,
			wantHigh: true,
		},
		{
			name: "only file writes",
			config: ApprovalConfig{
				Required:   false,
				Commands:   false,
				FileWrites: true,
				HighRisk:   true,
			},
			wantCmd:  ApprovalNotRequired,
			wantFile: ApprovalRequired,
			wantHigh: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			policy := tt.config.ToPolicy()

			if policy.Commands != tt.wantCmd {
				t.Errorf("Commands = %v, want %v", policy.Commands, tt.wantCmd)
			}
			if policy.FileWrites != tt.wantFile {
				t.Errorf("FileWrites = %v, want %v", policy.FileWrites, tt.wantFile)
			}
			if policy.HighRiskAlways != tt.wantHigh {
				t.Errorf("HighRiskAlways = %v, want %v", policy.HighRiskAlways, tt.wantHigh)
			}
			if policy.Approver != nil {
				t.Error("Approver should be nil (caller must provide)")
			}
		})
	}
}

func TestProviderConfig_Validate(t *testing.T) {
	tests := []struct {
		name    string
		config  ProviderConfig
		wantErr bool
	}{
		{
			name:    "empty config is valid",
			config:  ProviderConfig{},
			wantErr: false,
		},
		{
			name: "valid sandbox modes",
			config: ProviderConfig{
				Sandbox: "workspace-write",
			},
			wantErr: false,
		},
		{
			name: "invalid sandbox",
			config: ProviderConfig{
				Sandbox: "invalid",
			},
			wantErr: true,
		},
		{
			name: "valid temperature",
			config: ProviderConfig{
				Temperature: floatPtr(0.7),
			},
			wantErr: false,
		},
		{
			name: "temperature too high",
			config: ProviderConfig{
				Temperature: floatPtr(2.5),
			},
			wantErr: true,
		},
		{
			name: "temperature too low",
			config: ProviderConfig{
				Temperature: floatPtr(-0.1),
			},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := tt.config.Validate("test")
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestProviderConfig_GetSandbox(t *testing.T) {
	tests := []struct {
		name   string
		config ProviderConfig
		want   Sandbox
	}{
		{
			name:   "empty defaults to workspace-write",
			config: ProviderConfig{},
			want:   SandboxWorkspaceWrite,
		},
		{
			name:   "read-only",
			config: ProviderConfig{Sandbox: "read-only"},
			want:   SandboxReadOnly,
		},
		{
			name:   "full-access",
			config: ProviderConfig{Sandbox: "full-access"},
			want:   SandboxFullAccess,
		},
		{
			name:   "case insensitive",
			config: ProviderConfig{Sandbox: "WORKSPACE-WRITE"},
			want:   SandboxWorkspaceWrite,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.config.GetSandbox()
			if got != tt.want {
				t.Errorf("GetSandbox() = %v, want %v", got, tt.want)
			}
		})
	}
}

func floatPtr(f float64) *float64 {
	return &f
}
