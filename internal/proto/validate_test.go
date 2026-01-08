package proto

import (
	"testing"

	remediationv1 "github.com/picatz/deputy/gen/deputy/remediation/v1"
	scanv1 "github.com/picatz/deputy/gen/deputy/scan/v1"
)

func TestValidate_ExecuteWithAgentRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *remediationv1.ExecuteWithAgentRequest
		wantErr bool
	}{
		{
			name:    "empty agent fails",
			req:     &remediationv1.ExecuteWithAgentRequest{Agent: ""},
			wantErr: true,
		},
		{
			name:    "valid agent passes",
			req:     &remediationv1.ExecuteWithAgentRequest{Agent: "claude"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_ResumeAgentRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *remediationv1.ResumeAgentRequest
		wantErr bool
	}{
		{
			name:    "empty session_id fails",
			req:     &remediationv1.ResumeAgentRequest{SessionId: ""},
			wantErr: true,
		},
		{
			name:    "valid session_id passes",
			req:     &remediationv1.ResumeAgentRequest{SessionId: "session-123"},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_ApproveStepRequest(t *testing.T) {
	tests := []struct {
		name    string
		req     *remediationv1.ApproveStepRequest
		wantErr bool
	}{
		{
			name:    "empty session_id fails",
			req:     &remediationv1.ApproveStepRequest{SessionId: "", StepId: "step-1"},
			wantErr: true,
		},
		{
			name:    "empty step_id fails",
			req:     &remediationv1.ApproveStepRequest{SessionId: "session-123", StepId: ""},
			wantErr: true,
		},
		{
			name:    "valid request passes",
			req:     &remediationv1.ApproveStepRequest{SessionId: "session-123", StepId: "step-1", Approved: true},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_AgentOptions(t *testing.T) {
	tests := []struct {
		name    string
		req     *remediationv1.ExecuteWithAgentRequest
		wantErr bool
	}{
		{
			name: "invalid sandbox fails",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{Sandbox: "invalid-sandbox"},
			},
			wantErr: true,
		},
		{
			name: "valid sandbox read-only passes",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{Sandbox: "read-only"},
			},
			wantErr: false,
		},
		{
			name: "valid sandbox workspace-write passes",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{Sandbox: "workspace-write"},
			},
			wantErr: false,
		},
		{
			name: "valid sandbox full-access passes",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{Sandbox: "full-access"},
			},
			wantErr: false,
		},
		{
			name: "empty sandbox passes (default)",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{Sandbox: ""},
			},
			wantErr: false,
		},
		{
			name: "negative max_turns fails",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{MaxTurns: -1},
			},
			wantErr: true,
		},
		{
			name: "zero max_turns passes (unlimited)",
			req: &remediationv1.ExecuteWithAgentRequest{
				Agent:   "claude",
				Options: &remediationv1.AgentOptions{MaxTurns: 0},
			},
			wantErr: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.req)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestValidate_ScanProgress(t *testing.T) {
	tests := []struct {
		name    string
		msg     *scanv1.ScanProgress
		wantErr bool
	}{
		{
			name:    "valid progress 0",
			msg:     &scanv1.ScanProgress{Progress: 0},
			wantErr: false,
		},
		{
			name:    "valid progress 50",
			msg:     &scanv1.ScanProgress{Progress: 50},
			wantErr: false,
		},
		{
			name:    "valid progress 100",
			msg:     &scanv1.ScanProgress{Progress: 100},
			wantErr: false,
		},
		{
			name:    "invalid progress > 100",
			msg:     &scanv1.ScanProgress{Progress: 101},
			wantErr: true,
		},
		{
			name:    "invalid progress < 0",
			msg:     &scanv1.ScanProgress{Progress: -1},
			wantErr: true,
		},
		{
			name:    "invalid packages_found < 0",
			msg:     &scanv1.ScanProgress{Progress: 50, PackagesFound: -1},
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := Validate(tt.msg)
			if (err != nil) != tt.wantErr {
				t.Errorf("Validate() error = %v, wantErr %v", err, tt.wantErr)
			}
		})
	}
}

func TestIsValid(t *testing.T) {
	valid := &remediationv1.ExecuteWithAgentRequest{Agent: "claude"}
	invalid := &remediationv1.ExecuteWithAgentRequest{Agent: ""}

	if !IsValid(valid) {
		t.Error("IsValid() should return true for valid message")
	}
	if IsValid(invalid) {
		t.Error("IsValid() should return false for invalid message")
	}
}

func TestMustValidate_Panics(t *testing.T) {
	defer func() {
		if r := recover(); r == nil {
			t.Error("MustValidate() should panic for invalid message")
		}
	}()

	invalid := &remediationv1.ExecuteWithAgentRequest{Agent: ""}
	MustValidate(invalid)
}

func TestMustValidate_NoPanic(t *testing.T) {
	defer func() {
		if r := recover(); r != nil {
			t.Error("MustValidate() should not panic for valid message")
		}
	}()

	valid := &remediationv1.ExecuteWithAgentRequest{Agent: "claude"}
	MustValidate(valid)
}
