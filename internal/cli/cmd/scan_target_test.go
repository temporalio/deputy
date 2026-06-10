package cmd

import "testing"

func TestLooksLikeContainerReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{input: "alpine", want: true},
		{input: "alpine:3.18", want: true},
		{input: "library/alpine", want: false},
		{input: "library/alpine:3.18", want: true},
		{input: "owner/repo", want: false},
		{input: "owner/repo:v1", want: true},
		{input: "ghcr.io/owner/app:1.2.3", want: true},
		{input: "docker.io/library/alpine:3.18", want: true},
		{input: "localhost:5000/app:latest", want: true},
		{input: "github.com/owner/repo", want: false},
		{input: "git@github.com:owner/repo", want: false},
		{input: "https://github.com/owner/repo", want: false},
		{input: "pkg:npm/lodash@4.17.21", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := looksLikeContainerReference(tt.input); got != tt.want {
				t.Fatalf("looksLikeContainerReference(%q)=%t, want %t", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsImageTargetScheme(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{input: "docker://ghcr.io/owner/app:1.2.3", want: true},
		{input: "oci://ghcr.io/owner/app@sha256:deadbeef", want: true},
		{input: "docker-daemon://app:latest", want: true},
		{input: "container://nginx:1.25", want: true},
		{input: "tarball:///path/to/image.tar", want: true},
		{input: "oci-archive:///path/to/oci.tar", want: true},
		{input: "oci-layout:///path/to/layout", want: true},
		{input: "https://github.com/owner/repo", want: false},
		{input: "pkg:npm/lodash@4.17.21", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := isImageTargetScheme(tt.input); got != tt.want {
				t.Fatalf("isImageTargetScheme(%q)=%t, want %t", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsAmbiguousDockerHubReference(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		{input: "owner/repo", want: true},
		{input: "library/ubuntu", want: true},
		{input: "owner/repo:1.0.0", want: false},
		{input: "alpine", want: false},
		{input: "ghcr.io/owner/app:1.2.3", want: false},
		{input: "github.com/owner/repo", want: false},
		{input: "pkg:npm/lodash@4.17.21", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := isAmbiguousDockerHubReference(tt.input); got != tt.want {
				t.Fatalf("isAmbiguousDockerHubReference(%q)=%t, want %t", tt.input, got, tt.want)
			}
		})
	}
}

func TestIsVMImageTarget(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input string
		want  bool
	}{
		// VM schemes
		{input: "vm:///path/to/disk.qcow2", want: true},
		{input: "vm://disk.img", want: true},
		{input: "rootfs:///path/to/rootfs.ext4", want: true},
		{input: "rootfs://rootfs.img", want: true},

		// VM file extensions
		{input: "/path/to/disk.qcow2", want: true},
		{input: "/path/to/disk.qcow", want: true},
		{input: "/path/to/disk.vmdk", want: true},
		{input: "/path/to/disk.vhd", want: true},
		{input: "/path/to/disk.vhdx", want: true},
		{input: "/path/to/disk.vdi", want: true},
		{input: "/path/to/rootfs.ext4", want: true},
		{input: "disk.QCOW2", want: true},
		{input: "disk.VMDK", want: true},

		// Not VM targets
		{input: "/path/to/project", want: false},
		{input: "alpine:latest", want: false},
		{input: "docker://nginx:1.25", want: false},
		{input: "pkg:npm/lodash@4.17.21", want: false},
		{input: "github.com/owner/repo", want: false},
		{input: "/path/to/file.tar", want: false},
		{input: "/path/to/image.iso", want: false},
		{input: "", want: false},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			if got := isVMImageTarget(tt.input); got != tt.want {
				t.Fatalf("isVMImageTarget(%q)=%t, want %t", tt.input, got, tt.want)
			}
		})
	}
}

func TestResolveSourceOverride(t *testing.T) {
	t.Parallel()

	tests := []struct {
		input       string
		wantKind    string
		wantImgSrc  string
		expectError bool
	}{
		{input: "", wantKind: "", wantImgSrc: "", expectError: false},
		{input: "auto", wantKind: "", wantImgSrc: "", expectError: false},
		{input: "purl", wantKind: "purl", wantImgSrc: "", expectError: false},
		{input: "sbom", wantKind: "sbom", wantImgSrc: "", expectError: false},
		{input: "dir", wantKind: "dir", wantImgSrc: "", expectError: false},
		{input: "git", wantKind: "git", wantImgSrc: "", expectError: false},
		{input: "remote", wantKind: "image", wantImgSrc: "remote", expectError: false},
		{input: "image", wantKind: "image", wantImgSrc: "remote", expectError: false},
		{input: "docker-daemon", wantKind: "image", wantImgSrc: "docker-daemon", expectError: false},
		{input: "tarball", wantKind: "image", wantImgSrc: "tarball", expectError: false},
		{input: "oci-layout", wantKind: "image", wantImgSrc: "oci-layout", expectError: false},
		{input: "layout", wantKind: "image", wantImgSrc: "oci-layout", expectError: false},
		{input: "vm", wantKind: "vm", wantImgSrc: "", expectError: false},
		{input: "vm-image", wantKind: "vm", wantImgSrc: "", expectError: false},
		{input: "disk-image", wantKind: "vm", wantImgSrc: "", expectError: false},
		{input: "rootfs", wantKind: "rootfs", wantImgSrc: "", expectError: false},
		{input: "filesystem", wantKind: "rootfs", wantImgSrc: "", expectError: false},
		{input: "unknown", expectError: true},
	}
	for _, tt := range tests {
		t.Run(tt.input, func(t *testing.T) {
			t.Parallel()
			gotKind, gotImgSrc, err := resolveSourceOverride(tt.input)
			if tt.expectError {
				if err == nil {
					t.Fatalf("resolveSourceOverride(%q) expected error", tt.input)
				}
				return
			}
			if err != nil {
				t.Fatalf("resolveSourceOverride(%q): %v", tt.input, err)
			}
			if gotKind != tt.wantKind || gotImgSrc != tt.wantImgSrc {
				t.Fatalf("resolveSourceOverride(%q)=(%q,%q), want (%q,%q)", tt.input, gotKind, gotImgSrc, tt.wantKind, tt.wantImgSrc)
			}
		})
	}
}
