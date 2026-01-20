package docker

import (
	"testing"
)

func TestFormatBytes(t *testing.T) {
	tests := []struct {
		name     string
		bytes    int64
		expected string
	}{
		{"zero", 0, "0"},
		{"bytes only", 512, "512"},
		{"exact kilobytes", 1024, "1k"},
		{"exact megabytes", 1024 * 1024, "1m"},
		{"exact gigabytes", 1024 * 1024 * 1024, "1g"},
		{"64 megabytes", 64 * 1024 * 1024, "64m"},
		{"2 gigabytes", 2 * 1024 * 1024 * 1024, "2g"},
		{"512 kilobytes", 512 * 1024, "512k"},
		{"non-aligned bytes", 1500, "1500"},
		{"non-aligned kilobytes", 1024 + 512, "1536"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatBytes(tt.bytes)
			if result != tt.expected {
				t.Errorf("formatBytes(%d) = %q, want %q", tt.bytes, result, tt.expected)
			}
		})
	}
}

func TestUpdateTmpfsSize(t *testing.T) {
	tests := []struct {
		name     string
		opts     string
		newSize  string
		expected string
	}{
		{
			name:     "add size to empty",
			opts:     "",
			newSize:  "64m",
			expected: "size=64m",
		},
		{
			name:     "add size to existing options",
			opts:     "rw,noexec,nosuid",
			newSize:  "128m",
			expected: "rw,noexec,nosuid,size=128m",
		},
		{
			name:     "replace existing size",
			opts:     "rw,noexec,nosuid,size=64m",
			newSize:  "256m",
			expected: "rw,noexec,nosuid,size=256m",
		},
		{
			name:     "replace size at beginning",
			opts:     "size=32m,rw,noexec",
			newSize:  "1g",
			expected: "size=1g,rw,noexec",
		},
		{
			name:     "handle whitespace",
			opts:     "rw, noexec, size=64m",
			newSize:  "128m",
			expected: "rw,noexec,size=128m",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := updateTmpfsSize(tt.opts, tt.newSize)
			if result != tt.expected {
				t.Errorf("updateTmpfsSize(%q, %q) = %q, want %q", tt.opts, tt.newSize, result, tt.expected)
			}
		})
	}
}

func TestParseMemory(t *testing.T) {
	tests := []struct {
		name     string
		input    string
		expected int64
		wantErr  bool
	}{
		{"empty", "", 0, false},
		{"bytes", "1024", 1024, false},
		{"kilobytes lowercase", "512k", 512 * 1024, false},
		{"kilobytes uppercase", "512K", 512 * 1024, false},
		{"kilobytes with b", "512kb", 512 * 1024, false},
		{"megabytes lowercase", "64m", 64 * 1024 * 1024, false},
		{"megabytes uppercase", "64M", 64 * 1024 * 1024, false},
		{"megabytes with b", "64mb", 64 * 1024 * 1024, false},
		{"gigabytes lowercase", "2g", 2 * 1024 * 1024 * 1024, false},
		{"gigabytes uppercase", "2G", 2 * 1024 * 1024 * 1024, false},
		{"gigabytes with b", "2gb", 2 * 1024 * 1024 * 1024, false},
		{"with whitespace", "  512m  ", 512 * 1024 * 1024, false},
		{"invalid", "abc", 0, true},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result, err := parseMemory(tt.input)
			if (err != nil) != tt.wantErr {
				t.Errorf("parseMemory(%q) error = %v, wantErr %v", tt.input, err, tt.wantErr)
				return
			}
			if result != tt.expected {
				t.Errorf("parseMemory(%q) = %d, want %d", tt.input, result, tt.expected)
			}
		})
	}
}

func TestCalculateOverallProgress(t *testing.T) {
	tests := []struct {
		name     string
		layers   map[string]*layerStatus
		expected int32
	}{
		{
			name:     "empty layers",
			layers:   map[string]*layerStatus{},
			expected: 0,
		},
		{
			name: "all complete",
			layers: map[string]*layerStatus{
				"layer1": {status: "Pull complete"},
				"layer2": {status: "Already exists"},
			},
			expected: 20, // 20% from completion status (100% * 0.2)
		},
		{
			name: "downloading 50%",
			layers: map[string]*layerStatus{
				"layer1": {status: "Downloading", current: 50, total: 100},
				"layer2": {status: "Downloading", current: 50, total: 100},
			},
			expected: 40, // 80% weight * 50% progress = 40%
		},
		{
			name: "mixed progress",
			layers: map[string]*layerStatus{
				"layer1": {status: "Pull complete"},
				"layer2": {status: "Downloading", current: 50, total: 100},
				"layer3": {status: "Waiting"},
			},
			expected: 46, // 80% * (50/100) + 20% * (1/3) = 40 + 6.7 = ~46
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := calculateOverallProgress(tt.layers)
			// Allow some tolerance for floating point math
			if result < tt.expected-5 || result > tt.expected+5 {
				t.Errorf("calculateOverallProgress() = %d, want approximately %d", result, tt.expected)
			}
		})
	}
}

func TestFormatPullStatus(t *testing.T) {
	tests := []struct {
		name     string
		layers   map[string]*layerStatus
		image    string
		contains string
	}{
		{
			name: "downloading",
			layers: map[string]*layerStatus{
				"layer1": {status: "Downloading"},
				"layer2": {status: "Pull complete"},
			},
			image:    "alpine:latest",
			contains: "Downloading",
		},
		{
			name: "extracting",
			layers: map[string]*layerStatus{
				"layer1": {status: "Extracting"},
				"layer2": {status: "Pull complete"},
			},
			image:    "alpine:latest",
			contains: "Extracting",
		},
		{
			name: "complete",
			layers: map[string]*layerStatus{
				"layer1": {status: "Pull complete"},
				"layer2": {status: "Already exists"},
			},
			image:    "alpine:latest",
			contains: "complete",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			result := formatPullStatus(tt.layers, tt.image)
			if !contains(result, tt.contains) {
				t.Errorf("formatPullStatus() = %q, want to contain %q", result, tt.contains)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsHelper(s, substr))
}

func containsHelper(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
