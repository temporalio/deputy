package compare

import (
	"testing"
)

func TestImageRef_String(t *testing.T) {
	tests := []struct {
		name string
		ref  ImageRef
		want string
	}{
		{
			name: "full reference takes precedence",
			ref: ImageRef{
				Registry:   "gcr.io",
				Repository: "project/image",
				Tag:        "v1.0",
				Reference:  "docker://gcr.io/project/image:v1.0",
			},
			want: "docker://gcr.io/project/image:v1.0",
		},
		{
			name: "registry with tag",
			ref: ImageRef{
				Registry:   "gcr.io",
				Repository: "project/image",
				Tag:        "latest",
			},
			want: "gcr.io/project/image:latest",
		},
		{
			name: "registry with digest",
			ref: ImageRef{
				Registry:   "gcr.io",
				Repository: "project/image",
				Digest:     "sha256:abc123",
			},
			want: "gcr.io/project/image@sha256:abc123",
		},
		{
			name: "digest takes precedence over tag",
			ref: ImageRef{
				Registry:   "gcr.io",
				Repository: "project/image",
				Tag:        "latest",
				Digest:     "sha256:abc123",
			},
			want: "gcr.io/project/image@sha256:abc123",
		},
		{
			name: "repository only",
			ref: ImageRef{
				Repository: "library/alpine",
			},
			want: "library/alpine",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := tt.ref.String()
			if got != tt.want {
				t.Errorf("ImageRef.String() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestCompareImageConfigs(t *testing.T) {
	t.Run("nil inputs return nil", func(t *testing.T) {
		if got := CompareImageConfigs(nil, nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
		if got := CompareImageConfigs(&ImageInput{}, nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("user changed", func(t *testing.T) {
		base := &ImageInput{Config: ImageConfigInput{User: "root", IsRoot: true}}
		target := &ImageInput{Config: ImageConfigInput{User: "nobody", IsRoot: false}}

		diff := CompareImageConfigs(base, target)
		if !diff.UserChanged {
			t.Error("expected UserChanged=true")
		}
		if diff.BaseUser != "root" {
			t.Errorf("BaseUser=%q want=%q", diff.BaseUser, "root")
		}
		if diff.TargetUser != "nobody" {
			t.Errorf("TargetUser=%q want=%q", diff.TargetUser, "nobody")
		}
		if !diff.RootChanged {
			t.Error("expected RootChanged=true")
		}
	})

	t.Run("environment variables", func(t *testing.T) {
		base := &ImageInput{Config: ImageConfigInput{
			Env: []string{"PATH=/usr/bin", "OLD_VAR=value", "CHANGED=old"},
		}}
		target := &ImageInput{Config: ImageConfigInput{
			Env: []string{"PATH=/usr/bin", "NEW_VAR=value", "CHANGED=new"},
		}}

		diff := CompareImageConfigs(base, target)
		if len(diff.EnvChanges) != 3 {
			t.Fatalf("expected 3 env changes, got %d", len(diff.EnvChanges))
		}

		// Check sorted order
		changes := make(map[string]EnvChange)
		for _, c := range diff.EnvChanges {
			changes[c.Name] = c
		}

		if c, ok := changes["OLD_VAR"]; !ok || c.ChangeType != Removed {
			t.Error("expected OLD_VAR to be removed")
		}
		if c, ok := changes["NEW_VAR"]; !ok || c.ChangeType != Added {
			t.Error("expected NEW_VAR to be added")
		}
		if c, ok := changes["CHANGED"]; !ok || c.ChangeType != Updated {
			t.Error("expected CHANGED to be updated")
		}
	})

	t.Run("ports changed", func(t *testing.T) {
		base := &ImageInput{Config: ImageConfigInput{
			ExposedPorts: []string{"8080/tcp", "9090/tcp"},
		}}
		target := &ImageInput{Config: ImageConfigInput{
			ExposedPorts: []string{"8080/tcp", "3000/tcp"},
		}}

		diff := CompareImageConfigs(base, target)
		if !diff.PortsChanged {
			t.Error("expected PortsChanged=true")
		}
		if len(diff.PortsAdded) != 1 || diff.PortsAdded[0] != "3000/tcp" {
			t.Errorf("PortsAdded=%v want=[3000/tcp]", diff.PortsAdded)
		}
		if len(diff.PortsRemoved) != 1 || diff.PortsRemoved[0] != "9090/tcp" {
			t.Errorf("PortsRemoved=%v want=[9090/tcp]", diff.PortsRemoved)
		}
	})

	t.Run("labels changed", func(t *testing.T) {
		base := &ImageInput{Config: ImageConfigInput{
			Labels: map[string]string{"version": "1.0", "old": "value"},
		}}
		target := &ImageInput{Config: ImageConfigInput{
			Labels: map[string]string{"version": "2.0", "new": "value"},
		}}

		diff := CompareImageConfigs(base, target)
		if len(diff.LabelChanges) != 3 {
			t.Fatalf("expected 3 label changes, got %d", len(diff.LabelChanges))
		}
	})

	t.Run("entrypoint and cmd changed", func(t *testing.T) {
		base := &ImageInput{Config: ImageConfigInput{
			Entrypoint: []string{"/bin/sh"},
			Cmd:        []string{"-c", "echo hello"},
		}}
		target := &ImageInput{Config: ImageConfigInput{
			Entrypoint: []string{"/app"},
			Cmd:        []string{"serve"},
		}}

		diff := CompareImageConfigs(base, target)
		if !diff.EntrypointChanged {
			t.Error("expected EntrypointChanged=true")
		}
		if !diff.CmdChanged {
			t.Error("expected CmdChanged=true")
		}
	})
}

func TestAnalyzeLayerDiff(t *testing.T) {
	t.Run("nil inputs return nil", func(t *testing.T) {
		if got := AnalyzeLayerDiff(nil, nil); got != nil {
			t.Errorf("expected nil, got %v", got)
		}
	})

	t.Run("common layers detected", func(t *testing.T) {
		base := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 3},
			History: []ImageHistoryInput{
				{CreatedBy: "/bin/sh -c #(nop) ADD file:abc in /"},
				{CreatedBy: "RUN apt-get update"},
				{CreatedBy: "RUN apt-get install -y curl"},
			},
		}
		target := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 4},
			History: []ImageHistoryInput{
				{CreatedBy: "/bin/sh -c #(nop) ADD file:abc in /"},
				{CreatedBy: "RUN apt-get update"},
				{CreatedBy: "RUN apt-get install -y curl wget"},
				{CreatedBy: "RUN npm install"},
			},
		}

		analysis := AnalyzeLayerDiff(base, target)
		if analysis.BaseLayerCount != 3 {
			t.Errorf("BaseLayerCount=%d want=3", analysis.BaseLayerCount)
		}
		if analysis.TargetLayerCount != 4 {
			t.Errorf("TargetLayerCount=%d want=4", analysis.TargetLayerCount)
		}
		if analysis.CommonLayers != 2 {
			t.Errorf("CommonLayers=%d want=2", analysis.CommonLayers)
		}
	})

	t.Run("layer changes detected", func(t *testing.T) {
		base := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 2},
			History: []ImageHistoryInput{
				{CreatedBy: "ADD base"},
				{CreatedBy: "RUN old command"},
			},
		}
		target := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 3},
			History: []ImageHistoryInput{
				{CreatedBy: "ADD base"},
				{CreatedBy: "RUN new command"},
				{CreatedBy: "RUN another"},
			},
		}

		analysis := AnalyzeLayerDiff(base, target)

		// Should have 2 changes: one modified (index 1) and one added (index 2)
		if len(analysis.LayerChanges) != 2 {
			t.Fatalf("expected 2 layer changes, got %d", len(analysis.LayerChanges))
		}

		// Check modified layer
		var foundModified, foundAdded bool
		for _, lc := range analysis.LayerChanges {
			if lc.ChangeType == LayerModified && lc.Index == 1 {
				foundModified = true
				if lc.BaseCommand != "RUN old command" {
					t.Errorf("modified layer BaseCommand=%q", lc.BaseCommand)
				}
			}
			if lc.ChangeType == LayerAdded && lc.Index == 2 {
				foundAdded = true
			}
		}
		if !foundModified {
			t.Error("expected to find a modified layer at index 1")
		}
		if !foundAdded {
			t.Error("expected to find an added layer at index 2")
		}
	})

	t.Run("empty layers excluded", func(t *testing.T) {
		base := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 2},
			History: []ImageHistoryInput{
				{CreatedBy: "ADD base"},
				{CreatedBy: "ENV PATH=/usr/bin", EmptyLayer: true},
			},
		}
		target := &ImageInput{
			Metadata: ImageMetadataInput{LayerCount: 2},
			History: []ImageHistoryInput{
				{CreatedBy: "ADD base"},
				{CreatedBy: "ENV PATH=/usr/local/bin", EmptyLayer: true},
			},
		}

		analysis := AnalyzeLayerDiff(base, target)
		// Empty layers with same CreatedBy should count as common
		if analysis.CommonLayers != 1 {
			t.Errorf("CommonLayers=%d want=1 (only non-empty base layer)", analysis.CommonLayers)
		}
	})
}

func TestCalculateImageDiffSummary(t *testing.T) {
	report := &ImageDiffReport{
		PackageChanges: []ImagePackageChange{
			{ChangeType: Added},
			{ChangeType: Added},
			{ChangeType: Removed},
			{ChangeType: Upgraded},
			{ChangeType: Downgraded},
		},
		VulnerabilityChanges: []VulnerabilityChange{
			{ChangeType: VulnAdded},
			{ChangeType: VulnRemoved},
			{ChangeType: VulnFixed},
			{ChangeType: VulnFixed},
		},
		LayerAnalysis: &LayerDiffAnalysis{
			LayerChanges: []LayerChange{
				{ChangeType: LayerAdded},
				{ChangeType: LayerAdded},
				{ChangeType: LayerRemoved},
				{ChangeType: LayerModified},
			},
		},
		ConfigChanges: &ImageConfigDiff{
			UserChanged: true,
		},
	}

	summary := CalculateImageDiffSummary(report)

	if summary.PackagesAdded != 2 {
		t.Errorf("PackagesAdded=%d want=2", summary.PackagesAdded)
	}
	if summary.PackagesRemoved != 1 {
		t.Errorf("PackagesRemoved=%d want=1", summary.PackagesRemoved)
	}
	if summary.PackagesUpgraded != 1 {
		t.Errorf("PackagesUpgraded=%d want=1", summary.PackagesUpgraded)
	}
	if summary.PackagesDowngraded != 1 {
		t.Errorf("PackagesDowngraded=%d want=1", summary.PackagesDowngraded)
	}
	if summary.VulnerabilitiesAdded != 1 {
		t.Errorf("VulnerabilitiesAdded=%d want=1", summary.VulnerabilitiesAdded)
	}
	if summary.VulnerabilitiesRemoved != 1 {
		t.Errorf("VulnerabilitiesRemoved=%d want=1", summary.VulnerabilitiesRemoved)
	}
	if summary.VulnerabilitiesFixed != 2 {
		t.Errorf("VulnerabilitiesFixed=%d want=2", summary.VulnerabilitiesFixed)
	}
	if summary.LayersAdded != 2 {
		t.Errorf("LayersAdded=%d want=2", summary.LayersAdded)
	}
	if summary.LayersRemoved != 1 {
		t.Errorf("LayersRemoved=%d want=1", summary.LayersRemoved)
	}
	if !summary.ConfigChanged {
		t.Error("expected ConfigChanged=true")
	}
}

func TestVulnChangeType_String(t *testing.T) {
	tests := []struct {
		ct   VulnChangeType
		want string
	}{
		{VulnAdded, "added"},
		{VulnRemoved, "removed"},
		{VulnFixed, "fixed"},
		{VulnPersisted, "persisted"},
		{VulnChangeType(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("VulnChangeType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestLayerChangeType_String(t *testing.T) {
	tests := []struct {
		ct   LayerChangeType
		want string
	}{
		{LayerSame, "same"},
		{LayerAdded, "added"},
		{LayerRemoved, "removed"},
		{LayerModified, "modified"},
		{LayerChangeType(99), "unknown"},
	}

	for _, tt := range tests {
		if got := tt.ct.String(); got != tt.want {
			t.Errorf("LayerChangeType(%d).String() = %q, want %q", tt.ct, got, tt.want)
		}
	}
}

func TestCompareEnvVars_SensitiveDetection(t *testing.T) {
	base := []string{"PATH=/usr/bin", "SECRET_KEY=old_secret"}
	target := []string{"PATH=/usr/bin", "SECRET_KEY=new_secret", "API_TOKEN=abc123"}
	sensitive := []string{"SECRET_KEY", "API_TOKEN"}

	changes := compareEnvVars(base, target, sensitive)

	sensitiveChanges := 0
	for _, c := range changes {
		if c.IsSensitive {
			sensitiveChanges++
		}
	}

	if sensitiveChanges != 2 {
		t.Errorf("expected 2 sensitive env changes, got %d", sensitiveChanges)
	}
}

func TestDiffSets(t *testing.T) {
	base := map[string]bool{"a": true, "b": true, "c": true}
	target := map[string]bool{"b": true, "c": true, "d": true, "e": true}

	added, removed := diffSets(base, target)

	if len(added) != 2 || added[0] != "d" || added[1] != "e" {
		t.Errorf("added=%v want=[d e]", added)
	}
	if len(removed) != 1 || removed[0] != "a" {
		t.Errorf("removed=%v want=[a]", removed)
	}
}
