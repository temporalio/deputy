package cloudplugin

import (
	"context"
	"iter"
	"testing"

	"connectrpc.com/connect"
	cloudv1 "github.com/picatz/deputy/gen/deputy/cloud/v1"
)

// mockProvider implements Provider for testing.
type mockProvider struct {
	info         ProviderInfo
	detectResult *DetectResult
	detectErr    error
	openEvents   []OpenEvent
	closeErr     error
	closeCalled  bool
	closeReqID   string
}

func (m *mockProvider) Info() ProviderInfo {
	return m.info
}

func (m *mockProvider) Detect(ctx context.Context, target string) (*DetectResult, error) {
	if m.detectErr != nil {
		return nil, m.detectErr
	}
	return m.detectResult, nil
}

func (m *mockProvider) Open(ctx context.Context, req OpenRequest) iter.Seq[OpenEvent] {
	return func(yield func(OpenEvent) bool) {
		for _, e := range m.openEvents {
			if !yield(e) {
				return
			}
		}
	}
}

func (m *mockProvider) Close(ctx context.Context, requestID string) error {
	m.closeCalled = true
	m.closeReqID = requestID
	return m.closeErr
}

func TestProviderInfo(t *testing.T) {
	info := ProviderInfo{
		Name:          "test-provider",
		DisplayName:   "Test Provider",
		Version:       "1.0.0",
		Description:   "A test cloud provider",
		Schemes:       []string{"test://"},
		ResourceTypes: []string{"instance", "volume"},
		Capabilities: Capabilities{
			ListResources:     true,
			SmartDownload:     true,
			StreamingProgress: true,
			SecretsScanning:   false,
		},
	}

	if info.Name != "test-provider" {
		t.Errorf("Name = %q, want %q", info.Name, "test-provider")
	}
	if info.Version != "1.0.0" {
		t.Errorf("Version = %q, want %q", info.Version, "1.0.0")
	}
	if len(info.Schemes) != 1 || info.Schemes[0] != "test://" {
		t.Errorf("Schemes = %v, want [test://]", info.Schemes)
	}
	if !info.Capabilities.ListResources {
		t.Error("Capabilities.ListResources = false, want true")
	}
}

func TestDetectResult(t *testing.T) {
	result := &DetectResult{
		Detected:     true,
		Scheme:       "test://",
		ResourceType: "instance",
		ResourceID:   "i-1234567890abcdef0",
	}

	if !result.Detected {
		t.Error("Detected = false, want true")
	}
	if result.Scheme != "test://" {
		t.Errorf("Scheme = %q, want %q", result.Scheme, "test://")
	}
	if result.ResourceID != "i-1234567890abcdef0" {
		t.Errorf("ResourceID = %q, want %q", result.ResourceID, "i-1234567890abcdef0")
	}
}

func TestOpenEvents(t *testing.T) {
	t.Run("ProgressEvent", func(t *testing.T) {
		event := ProgressEvent{
			Phase:            "downloading",
			Message:          "Downloading block 1/100",
			Percent:          1,
			BytesTransferred: 1024,
			BytesTotal:       102400,
		}

		// Verify it implements OpenEvent
		var _ OpenEvent = event

		if event.Phase != "downloading" {
			t.Errorf("Phase = %q, want %q", event.Phase, "downloading")
		}
		if event.Percent != 1 {
			t.Errorf("Percent = %d, want %d", event.Percent, 1)
		}
	})

	t.Run("ReadyEvent", func(t *testing.T) {
		event := ReadyEvent{
			Resource: ResourceInfo{
				Provider:    "test",
				Type:        "instance",
				ID:          "i-123",
				Region:      "us-west-2",
				AccountID:   "123456789012",
				Name:        "my-instance",
				Description: "Test instance",
				Tags:        map[string]string{"env": "test"},
			},
			LocalPath: "/tmp/instance-fs",
		}

		// Verify it implements OpenEvent
		var _ OpenEvent = event

		if event.Resource.ID != "i-123" {
			t.Errorf("Resource.ID = %q, want %q", event.Resource.ID, "i-123")
		}
		if event.LocalPath != "/tmp/instance-fs" {
			t.Errorf("LocalPath = %q, want %q", event.LocalPath, "/tmp/instance-fs")
		}
	})

	t.Run("ErrorEvent", func(t *testing.T) {
		event := ErrorEvent{
			Message:     "permission denied",
			Code:        "ACCESS_DENIED",
			Retriable:   false,
			Remediation: "Check IAM permissions",
		}

		// Verify it implements OpenEvent
		var _ OpenEvent = event

		if event.Code != "ACCESS_DENIED" {
			t.Errorf("Code = %q, want %q", event.Code, "ACCESS_DENIED")
		}
		if event.Retriable {
			t.Error("Retriable = true, want false")
		}
	})
}

func TestResourceInfo(t *testing.T) {
	info := ResourceInfo{
		Provider:    "aws",
		Type:        "ami",
		ID:          "ami-0123456789abcdef0",
		Region:      "us-east-1",
		AccountID:   "123456789012",
		Name:        "my-golden-image",
		Description: "Golden AMI for production",
		Tags: map[string]string{
			"env":     "prod",
			"team":    "platform",
			"version": "1.2.3",
		},
	}

	if info.Provider != "aws" {
		t.Errorf("Provider = %q, want %q", info.Provider, "aws")
	}
	if info.Type != "ami" {
		t.Errorf("Type = %q, want %q", info.Type, "ami")
	}
	if len(info.Tags) != 3 {
		t.Errorf("len(Tags) = %d, want 3", len(info.Tags))
	}
	if info.Tags["env"] != "prod" {
		t.Errorf("Tags[env] = %q, want %q", info.Tags["env"], "prod")
	}
}

func TestProviderAdapter_GetInfo(t *testing.T) {
	mock := &mockProvider{
		info: ProviderInfo{
			Name:          "test-plugin",
			DisplayName:   "Test Plugin",
			Version:       "2.0.0",
			Description:   "Test description",
			Schemes:       []string{"test://", "test2://"},
			ResourceTypes: []string{"widget"},
			Capabilities: Capabilities{
				ListResources:     true,
				SmartDownload:     false,
				StreamingProgress: true,
				SecretsScanning:   true,
			},
		},
	}

	adapter := &providerAdapter{provider: mock}

	resp, err := adapter.GetInfo(context.Background(), connect.NewRequest(&cloudv1.GetProviderInfoRequest{}))
	if err != nil {
		t.Fatalf("GetInfo() error = %v", err)
	}

	msg := resp.Msg
	if msg.Name != "test-plugin" {
		t.Errorf("Name = %q, want %q", msg.Name, "test-plugin")
	}
	if msg.Version != "2.0.0" {
		t.Errorf("Version = %q, want %q", msg.Version, "2.0.0")
	}
	if len(msg.Schemes) != 2 {
		t.Errorf("len(Schemes) = %d, want 2", len(msg.Schemes))
	}
	if msg.Capabilities == nil {
		t.Fatal("Capabilities is nil")
	}
	if !msg.Capabilities.ListResources {
		t.Error("Capabilities.ListResources = false, want true")
	}
	if msg.Capabilities.SmartDownload {
		t.Error("Capabilities.SmartDownload = true, want false")
	}
	if !msg.Capabilities.SecretsScanning {
		t.Error("Capabilities.SecretsScanning = false, want true")
	}
}

func TestProviderAdapter_Detect(t *testing.T) {
	tests := []struct {
		name     string
		target   string
		result   *DetectResult
		wantErr  bool
		detected bool
	}{
		{
			name:   "detected",
			target: "test://instance/i-123",
			result: &DetectResult{
				Detected:     true,
				Scheme:       "test://",
				ResourceType: "instance",
				ResourceID:   "i-123",
			},
			detected: true,
		},
		{
			name:   "not detected",
			target: "unknown://foo",
			result: &DetectResult{
				Detected: false,
			},
			detected: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			mock := &mockProvider{detectResult: tt.result}
			adapter := &providerAdapter{provider: mock}

			resp, err := adapter.Detect(context.Background(), connect.NewRequest(&cloudv1.DetectRequest{
				Target: tt.target,
			}))

			if (err != nil) != tt.wantErr {
				t.Fatalf("Detect() error = %v, wantErr %v", err, tt.wantErr)
			}
			if err != nil {
				return
			}

			if resp.Msg.Detected != tt.detected {
				t.Errorf("Detected = %v, want %v", resp.Msg.Detected, tt.detected)
			}
		})
	}
}

func TestProviderAdapter_Close(t *testing.T) {
	t.Run("success", func(t *testing.T) {
		mock := &mockProvider{}
		adapter := &providerAdapter{provider: mock}

		resp, err := adapter.Close(context.Background(), connect.NewRequest(&cloudv1.CloseResourceRequest{
			RequestId: "req-123",
		}))

		if err != nil {
			t.Fatalf("Close() error = %v", err)
		}
		if !resp.Msg.Success {
			t.Error("Success = false, want true")
		}
		if !mock.closeCalled {
			t.Error("provider.Close() was not called")
		}
		if mock.closeReqID != "req-123" {
			t.Errorf("closeReqID = %q, want %q", mock.closeReqID, "req-123")
		}
	})

	t.Run("error", func(t *testing.T) {
		mock := &mockProvider{closeErr: context.DeadlineExceeded}
		adapter := &providerAdapter{provider: mock}

		resp, err := adapter.Close(context.Background(), connect.NewRequest(&cloudv1.CloseResourceRequest{
			RequestId: "req-456",
		}))

		if err != nil {
			t.Fatalf("Close() error = %v (should return success=false, not error)", err)
		}
		if resp.Msg.Success {
			t.Error("Success = true, want false")
		}
		if resp.Msg.Error == "" {
			t.Error("Error message should not be empty")
		}
	})
}

func TestOpenRequest(t *testing.T) {
	req := OpenRequest{
		Target: "test://instance/i-123",
		OpenOptions: &cloudv1.OpenOptions{
			SmartDownload: true,
			Ecosystems:    []string{"go", "npm"},
			Platform:      "linux/amd64",
		},
		RequestID: "req-abc-123",
	}

	if req.Target != "test://instance/i-123" {
		t.Errorf("Target = %q, want %q", req.Target, "test://instance/i-123")
	}
	if req.RequestID != "req-abc-123" {
		t.Errorf("RequestID = %q, want %q", req.RequestID, "req-abc-123")
	}
	if req.OpenOptions == nil {
		t.Fatal("OpenOptions is nil")
	}
	if !req.OpenOptions.SmartDownload {
		t.Error("SmartDownload = false, want true")
	}
	if len(req.OpenOptions.Ecosystems) != 2 {
		t.Errorf("len(Ecosystems) = %d, want 2", len(req.OpenOptions.Ecosystems))
	}
}

func TestCapabilities(t *testing.T) {
	tests := []struct {
		name string
		caps Capabilities
	}{
		{
			name: "all enabled",
			caps: Capabilities{
				ListResources:     true,
				SmartDownload:     true,
				StreamingProgress: true,
				SecretsScanning:   true,
			},
		},
		{
			name: "minimal",
			caps: Capabilities{
				ListResources:     false,
				SmartDownload:     false,
				StreamingProgress: false,
				SecretsScanning:   false,
			},
		},
		{
			name: "mixed",
			caps: Capabilities{
				ListResources:     true,
				SmartDownload:     false,
				StreamingProgress: true,
				SecretsScanning:   false,
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			// Just verify the struct can be created and accessed
			_ = tt.caps.ListResources
			_ = tt.caps.SmartDownload
			_ = tt.caps.StreamingProgress
			_ = tt.caps.SecretsScanning
		})
	}
}
