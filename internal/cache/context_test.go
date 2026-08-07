package cache

import (
	"context"
	"testing"
)

func TestParseNoCacheFlag(t *testing.T) {
	tests := []struct {
		name        string
		input       string
		wantBypass  bool
		wantSources []string
	}{
		{
			name:        "empty string bypasses all",
			input:       "",
			wantBypass:  true,
			wantSources: nil,
		},
		{
			name:        "true bypasses all",
			input:       "true",
			wantBypass:  true,
			wantSources: nil,
		},
		{
			name:        "false bypasses nothing",
			input:       "false",
			wantBypass:  false,
			wantSources: nil,
		},
		{
			name:        "single source",
			input:       "osv",
			wantBypass:  false,
			wantSources: []string{"osv"},
		},
		{
			name:        "multiple sources",
			input:       "osv,kev,epss",
			wantBypass:  false,
			wantSources: []string{"osv", "kev", "epss"},
		},
		{
			name:        "sources with whitespace",
			input:       " osv , kev ",
			wantBypass:  false,
			wantSources: []string{"osv", "kev"},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			gotBypass, gotSources := ParseNoCacheFlag(tt.input)
			if gotBypass != tt.wantBypass {
				t.Errorf("ParseNoCacheFlag(%q) bypassAll = %v, want %v", tt.input, gotBypass, tt.wantBypass)
			}
			if len(gotSources) != len(tt.wantSources) {
				t.Errorf("ParseNoCacheFlag(%q) sources = %v, want %v", tt.input, gotSources, tt.wantSources)
				return
			}
			for i, s := range gotSources {
				if s != tt.wantSources[i] {
					t.Errorf("ParseNoCacheFlag(%q) sources[%d] = %q, want %q", tt.input, i, s, tt.wantSources[i])
				}
			}
		})
	}
}

func TestShouldBypass(t *testing.T) {
	tests := []struct {
		name string
		ctx  context.Context
		want bool
	}{
		{
			name: "default context",
			ctx:  t.Context(),
			want: false,
		},
		{
			name: "bypass all",
			ctx:  WithBypassAll(t.Context()),
			want: true,
		},
		{
			name: "bypass sources does not set bypass all",
			ctx:  WithBypassSources(t.Context(), []string{"osv"}),
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldBypass(tt.ctx); got != tt.want {
				t.Errorf("ShouldBypass() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestShouldBypassSource(t *testing.T) {
	tests := []struct {
		name   string
		ctx    context.Context
		source string
		want   bool
	}{
		{
			name:   "default context",
			ctx:    t.Context(),
			source: "osv",
			want:   false,
		},
		{
			name:   "bypass all affects any source",
			ctx:    WithBypassAll(t.Context()),
			source: "osv",
			want:   true,
		},
		{
			name:   "bypass specific source matches",
			ctx:    WithBypassSources(t.Context(), []string{"osv", "kev"}),
			source: "osv",
			want:   true,
		},
		{
			name:   "bypass specific source does not match other",
			ctx:    WithBypassSources(t.Context(), []string{"osv", "kev"}),
			source: "epss",
			want:   false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := ShouldBypassSource(tt.ctx, tt.source); got != tt.want {
				t.Errorf("ShouldBypassSource(%q) = %v, want %v", tt.source, got, tt.want)
			}
		})
	}
}

func TestApplyNoCacheFlag(t *testing.T) {
	tests := []struct {
		name        string
		value       string
		checkBypass bool
		checkSource string
		want        bool
	}{
		{
			name:        "empty bypasses all",
			value:       "",
			checkBypass: true,
			want:        true,
		},
		{
			name:        "true bypasses all",
			value:       "true",
			checkBypass: true,
			want:        true,
		},
		{
			name:        "false does nothing",
			value:       "false",
			checkBypass: true,
			want:        false,
		},
		{
			name:        "specific source bypasses that source",
			value:       "osv",
			checkSource: "osv",
			want:        true,
		},
		{
			name:        "specific source does not bypass other",
			value:       "osv",
			checkSource: "kev",
			want:        false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			ctx := ApplyNoCacheFlag(t.Context(), tt.value)
			var got bool
			if tt.checkBypass {
				got = ShouldBypass(ctx)
			} else {
				got = ShouldBypassSource(ctx, tt.checkSource)
			}
			if got != tt.want {
				t.Errorf("ApplyNoCacheFlag(%q) check = %v, want %v", tt.value, got, tt.want)
			}
		})
	}
}
