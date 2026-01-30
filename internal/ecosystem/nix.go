// Package ecosystem provides Nix-specific utilities for mapping Nix packages
// to their upstream ecosystems.
//
// Nix packages are meta-packages that wrap upstream software from other ecosystems.
// By detecting the upstream ecosystem from the Nix package name pattern, we can:
//   - Query the upstream registry (PyPI, npm, crates.io, etc.) for license info
//   - Query OSV for vulnerabilities using the upstream PURL
//   - Fall back to CPE matching for native packages (openssl, curl, zlib)

package ecosystem

import (
	"regexp"
	"strings"
)

// NixUpstreamInfo contains information about the upstream package that a Nix
// package wraps. This enables vulnerability and license lookups via the
// upstream ecosystem's registry and OSV data.
type NixUpstreamInfo struct {
	// Ecosystem is the upstream ecosystem (e.g., PyPI, npm, Cargo).
	Ecosystem Ecosystem

	// Name is the upstream package name (e.g., "requests" from python3Packages.requests).
	Name string

	// Version is preserved from the Nix package version.
	Version string

	// CPE is set for native packages that don't map to a language ecosystem.
	// Format: cpe:2.3:a:vendor:product (without version, which is added at query time).
	CPE string

	// IsMapped indicates whether the Nix package was successfully mapped to an upstream.
	IsMapped bool
}

// NixPackagePrefix represents a Nix package set prefix and its upstream ecosystem.
type NixPackagePrefix struct {
	// Pattern is a regex pattern to match Nix package names.
	Pattern *regexp.Regexp

	// Ecosystem is the upstream ecosystem this prefix maps to.
	Ecosystem Ecosystem

	// StripPrefix is the literal prefix to strip from the package name.
	// If empty, the regex match group 1 is used as the package name.
	StripPrefix string
}

// nixPackagePrefixes maps Nix package naming patterns to upstream ecosystems.
// Order matters: more specific patterns should come before general ones.
var nixPackagePrefixes = []NixPackagePrefix{
	// Python packages: python3Packages.foo, python312Packages.foo, pythonPackages.foo
	{
		Pattern:   regexp.MustCompile(`^python\d*Packages\.(.+)$`),
		Ecosystem: PyPI,
	},
	// Node.js packages: nodePackages.foo, nodePackages_latest.foo
	{
		Pattern:   regexp.MustCompile(`^nodePackages(?:_latest)?\.(.+)$`),
		Ecosystem: NPM,
	},
	// Ruby gems: rubyGems.foo, ruby_3_2.gems.foo
	{
		Pattern:   regexp.MustCompile(`^(?:rubyGems|ruby_?\d*(?:_\d+)*\.gems)\.(.+)$`),
		Ecosystem: RubyGems,
	},
	// Perl packages: perlPackages.foo, perl538Packages.foo
	{
		Pattern:   regexp.MustCompile(`^perl\d*Packages\.(.+)$`),
		Ecosystem: Unknown, // CPAN not yet supported in Deputy
	},
	// Rust packages: rustPackages.foo (note: rare, most Rust in Nix uses buildRustPackage)
	{
		Pattern:   regexp.MustCompile(`^rustPackages\.(.+)$`),
		Ecosystem: Cargo,
	},
	// Haskell packages: haskellPackages.foo, haskell.packages.ghc965.foo
	{
		Pattern:   regexp.MustCompile(`^(?:haskellPackages|haskell\.packages\.[^.]+)\.(.+)$`),
		Ecosystem: Unknown, // Hackage not yet fully supported
	},
	// Lua packages: luaPackages.foo, lua54Packages.foo
	{
		Pattern:   regexp.MustCompile(`^lua\d*Packages\.(.+)$`),
		Ecosystem: Unknown, // LuaRocks not yet supported
	},
	// R packages: rPackages.foo
	{
		Pattern:   regexp.MustCompile(`^rPackages\.(.+)$`),
		Ecosystem: Unknown, // CRAN not yet supported
	},
	// Elixir/Erlang packages: beamPackages.foo, elixirPackages.foo
	{
		Pattern:   regexp.MustCompile(`^(?:beamPackages|elixirPackages|erlangPackages)\.(.+)$`),
		Ecosystem: Hex,
	},
	// OCaml packages: ocamlPackages.foo
	{
		Pattern:   regexp.MustCompile(`^ocaml\d*Packages\.(.+)$`),
		Ecosystem: Unknown, // opam not yet supported
	},
	// PHP packages: phpPackages.foo
	{
		Pattern:   regexp.MustCompile(`^php\d*Packages\.(.+)$`),
		Ecosystem: Packagist,
	},
	// Go packages: go-packages.foo (rare pattern, most Go in Nix uses buildGoModule)
	{
		Pattern:   regexp.MustCompile(`^go-?packages\.(.+)$`),
		Ecosystem: Go,
	},
}

// nixCPEMappings maps common native Nix packages to CPE identifiers.
// These are packages without a language ecosystem that need CVE/NVD matching.
// CPE format: cpe:2.3:a:vendor:product (version added at query time).
var nixCPEMappings = map[string]string{
	// Cryptography and TLS
	"openssl":    "cpe:2.3:a:openssl:openssl",
	"libressl":   "cpe:2.3:a:openbsd:libressl",
	"gnutls":     "cpe:2.3:a:gnu:gnutls",
	"nss":        "cpe:2.3:a:mozilla:nss",
	"mbedtls":    "cpe:2.3:a:arm:mbed_tls",
	"wolfssl":    "cpe:2.3:a:wolfssl:wolfssl",
	"boringssl":  "cpe:2.3:a:google:boringssl",
	"libsodium":  "cpe:2.3:a:libsodium:libsodium",
	"libgcrypt":  "cpe:2.3:a:gnupg:libgcrypt",
	"nettle":     "cpe:2.3:a:nettle_project:nettle",
	"gpgme":      "cpe:2.3:a:gnupg:gpgme",
	"gnupg":      "cpe:2.3:a:gnupg:gnupg",
	"openssh":    "cpe:2.3:a:openbsd:openssh",
	"libssh":     "cpe:2.3:a:libssh:libssh",
	"libssh2":    "cpe:2.3:a:libssh2:libssh2",
	"stunnel":    "cpe:2.3:a:stunnel:stunnel",
	"cryptsetup": "cpe:2.3:a:cryptsetup_project:cryptsetup",
	"veracrypt":  "cpe:2.3:a:idrix:veracrypt",
	"hashcat":    "cpe:2.3:a:hashcat:hashcat",
	"john":       "cpe:2.3:a:openwall:john_the_ripper",
	"openvpn":    "cpe:2.3:a:openvpn:openvpn",
	"wireguard":  "cpe:2.3:a:wireguard:wireguard",
	"strongswan": "cpe:2.3:a:strongswan:strongswan",
	"libreswan":  "cpe:2.3:a:libreswan:libreswan",

	// Compression
	"zlib":       "cpe:2.3:a:zlib:zlib",
	"zstd":       "cpe:2.3:a:facebook:zstandard",
	"lz4":        "cpe:2.3:a:lz4_project:lz4",
	"xz":         "cpe:2.3:a:xz_project:xz",
	"bzip2":      "cpe:2.3:a:bzip:bzip2",
	"gzip":       "cpe:2.3:a:gnu:gzip",
	"brotli":     "cpe:2.3:a:google:brotli",
	"libzip":     "cpe:2.3:a:libzip:libzip",
	"libarchive": "cpe:2.3:a:libarchive:libarchive",
	"unzip":      "cpe:2.3:a:info-zip:unzip",
	"p7zip":      "cpe:2.3:a:7-zip:p7zip",

	// Networking
	"curl":      "cpe:2.3:a:curl:curl",
	"wget":      "cpe:2.3:a:gnu:wget",
	"libcurl":   "cpe:2.3:a:curl:libcurl",
	"nghttp2":   "cpe:2.3:a:nghttp2:nghttp2",
	"nginx":     "cpe:2.3:a:nginx:nginx",
	"apache":    "cpe:2.3:a:apache:http_server",
	"httpd":     "cpe:2.3:a:apache:http_server",
	"haproxy":   "cpe:2.3:a:haproxy:haproxy",
	"traefik":   "cpe:2.3:a:traefik:traefik",
	"caddy":     "cpe:2.3:a:caddyserver:caddy",
	"bind":      "cpe:2.3:a:isc:bind",
	"dnsmasq":   "cpe:2.3:a:dnsmasq:dnsmasq",
	"unbound":   "cpe:2.3:a:nlnetlabs:unbound",
	"nsd":       "cpe:2.3:a:nlnetlabs:nsd",
	"knot-dns":  "cpe:2.3:a:nic:knot_dns",
	"powerdns":  "cpe:2.3:a:powerdns:pdns",
	"dhcpcd":    "cpe:2.3:a:dhcpcd_project:dhcpcd",
	"isc-dhcp":  "cpe:2.3:a:isc:dhcp",
	"tcpdump":   "cpe:2.3:a:tcpdump:tcpdump",
	"wireshark": "cpe:2.3:a:wireshark:wireshark",
	"nmap":      "cpe:2.3:a:nmap:nmap",
	"iperf":     "cpe:2.3:a:iperf:iperf",
	"iperf3":    "cpe:2.3:a:es:iperf3",
	"netcat":    "cpe:2.3:a:netcat_project:netcat",
	"socat":     "cpe:2.3:a:socat:socat",
	"iproute2":  "cpe:2.3:a:linux:iproute2",
	"iptables":  "cpe:2.3:a:netfilter:iptables",
	"nftables":  "cpe:2.3:a:netfilter:nftables",
	"ipset":     "cpe:2.3:a:ipset_project:ipset",

	// Databases
	"postgresql":    "cpe:2.3:a:postgresql:postgresql",
	"mysql":         "cpe:2.3:a:mysql:mysql",
	"mariadb":       "cpe:2.3:a:mariadb:mariadb",
	"sqlite":        "cpe:2.3:a:sqlite:sqlite",
	"redis":         "cpe:2.3:a:redis:redis",
	"memcached":     "cpe:2.3:a:memcached:memcached",
	"mongodb":       "cpe:2.3:a:mongodb:mongodb",
	"elasticsearch": "cpe:2.3:a:elastic:elasticsearch",
	"opensearch":    "cpe:2.3:a:amazon:opensearch",
	"couchdb":       "cpe:2.3:a:apache:couchdb",
	"cassandra":     "cpe:2.3:a:apache:cassandra",
	"clickhouse":    "cpe:2.3:a:clickhouse:clickhouse",
	"influxdb":      "cpe:2.3:a:influxdata:influxdb",
	"etcd":          "cpe:2.3:a:etcd:etcd",
	"consul":        "cpe:2.3:a:hashicorp:consul",
	"vault":         "cpe:2.3:a:hashicorp:vault",

	// Image/media processing
	"imagemagick":    "cpe:2.3:a:imagemagick:imagemagick",
	"graphicsmagick": "cpe:2.3:a:graphicsmagick:graphicsmagick",
	"libpng":         "cpe:2.3:a:libpng:libpng",
	"libjpeg":        "cpe:2.3:a:libjpeg-turbo:libjpeg-turbo",
	"libtiff":        "cpe:2.3:a:libtiff:libtiff",
	"libwebp":        "cpe:2.3:a:google:libwebp",
	"giflib":         "cpe:2.3:a:giflib_project:giflib",
	"libheif":        "cpe:2.3:a:strukturag:libheif",
	"libavif":        "cpe:2.3:a:aomedia:libavif",
	"ffmpeg":         "cpe:2.3:a:ffmpeg:ffmpeg",
	"gstreamer":      "cpe:2.3:a:gstreamer:gstreamer",
	"vlc":            "cpe:2.3:a:videolan:vlc_media_player",
	"mpv":            "cpe:2.3:a:mpv:mpv",
	"exiftool":       "cpe:2.3:a:exiftool:exiftool",

	// Document processing
	"poppler":     "cpe:2.3:a:poppler:poppler",
	"ghostscript": "cpe:2.3:a:artifex:ghostscript",
	"libreoffice": "cpe:2.3:a:libreoffice:libreoffice",
	"pandoc":      "cpe:2.3:a:pandoc:pandoc",
	"texlive":     "cpe:2.3:a:tug:texlive",

	// XML/JSON processing
	"libxml2":  "cpe:2.3:a:xmlsoft:libxml2",
	"libxslt":  "cpe:2.3:a:xmlsoft:libxslt",
	"expat":    "cpe:2.3:a:libexpat_project:libexpat",
	"xerces-c": "cpe:2.3:a:apache:xerces-c%2b%2b",
	"jq":       "cpe:2.3:a:jqlang:jq",
	"yq":       "cpe:2.3:a:mikefarah:yq",

	// Version control
	"git":        "cpe:2.3:a:git:git",
	"mercurial":  "cpe:2.3:a:mercurial:mercurial",
	"subversion": "cpe:2.3:a:apache:subversion",

	// Build tools
	"cmake":      "cpe:2.3:a:cmake:cmake",
	"make":       "cpe:2.3:a:gnu:make",
	"ninja":      "cpe:2.3:a:ninja-build:ninja",
	"meson":      "cpe:2.3:a:mesonbuild:meson",
	"autoconf":   "cpe:2.3:a:gnu:autoconf",
	"automake":   "cpe:2.3:a:gnu:automake",
	"libtool":    "cpe:2.3:a:gnu:libtool",
	"pkg-config": "cpe:2.3:a:freedesktop:pkg-config",

	// Compilers and runtimes
	"gcc":      "cpe:2.3:a:gnu:gcc",
	"clang":    "cpe:2.3:a:llvm:clang",
	"llvm":     "cpe:2.3:a:llvm:llvm",
	"rustc":    "cpe:2.3:a:rust-lang:rust",
	"glibc":    "cpe:2.3:a:gnu:glibc",
	"musl":     "cpe:2.3:a:musl-libc:musl",
	"binutils": "cpe:2.3:a:gnu:binutils",
	"gdb":      "cpe:2.3:a:gnu:gdb",
	"valgrind": "cpe:2.3:a:valgrind:valgrind",

	// Shells and terminals
	"bash":   "cpe:2.3:a:gnu:bash",
	"zsh":    "cpe:2.3:a:zsh:zsh",
	"fish":   "cpe:2.3:a:fishshell:fish",
	"tmux":   "cpe:2.3:a:tmux:tmux",
	"screen": "cpe:2.3:a:gnu:screen",

	// Core utilities
	"coreutils": "cpe:2.3:a:gnu:coreutils",
	"findutils": "cpe:2.3:a:gnu:findutils",
	"diffutils": "cpe:2.3:a:gnu:diffutils",
	"grep":      "cpe:2.3:a:gnu:grep",
	"sed":       "cpe:2.3:a:gnu:sed",
	"gawk":      "cpe:2.3:a:gnu:gawk",
	"less":      "cpe:2.3:a:gnu:less",
	"file":      "cpe:2.3:a:file_project:file",

	// System utilities
	"sudo":       "cpe:2.3:a:sudo_project:sudo",
	"doas":       "cpe:2.3:a:openbsd:doas",
	"polkit":     "cpe:2.3:a:polkit_project:polkit",
	"systemd":    "cpe:2.3:a:systemd_project:systemd",
	"util-linux": "cpe:2.3:a:kernel:util-linux",
	"procps":     "cpe:2.3:a:procps-ng:procps-ng",
	"psmisc":     "cpe:2.3:a:psmisc:psmisc",
	"lsof":       "cpe:2.3:a:lsof:lsof",
	"strace":     "cpe:2.3:a:strace:strace",
	"ltrace":     "cpe:2.3:a:ltrace:ltrace",
	"htop":       "cpe:2.3:a:htop:htop",
	"atop":       "cpe:2.3:a:atop:atop",

	// Container/virtualization
	"docker":     "cpe:2.3:a:docker:docker",
	"containerd": "cpe:2.3:a:linuxfoundation:containerd",
	"runc":       "cpe:2.3:a:linuxfoundation:runc",
	"podman":     "cpe:2.3:a:podman_project:podman",
	"buildah":    "cpe:2.3:a:buildah_project:buildah",
	"skopeo":     "cpe:2.3:a:skopeo_project:skopeo",
	"qemu":       "cpe:2.3:a:qemu:qemu",
	"libvirt":    "cpe:2.3:a:redhat:libvirt",
	"virtualbox": "cpe:2.3:a:oracle:virtualbox",

	// Kubernetes ecosystem
	"kubernetes": "cpe:2.3:a:kubernetes:kubernetes",
	"kubectl":    "cpe:2.3:a:kubernetes:kubectl",
	"helm":       "cpe:2.3:a:helm:helm",
	"kustomize":  "cpe:2.3:a:kubernetes:kustomize",
	"minikube":   "cpe:2.3:a:kubernetes:minikube",
	"k3s":        "cpe:2.3:a:rancher:k3s",
	"k9s":        "cpe:2.3:a:derailed:k9s",

	// Other common packages
	"linux":      "cpe:2.3:o:linux:linux_kernel",
	"dbus":       "cpe:2.3:a:freedesktop:dbus",
	"avahi":      "cpe:2.3:a:avahi:avahi",
	"cups":       "cpe:2.3:a:apple:cups",
	"samba":      "cpe:2.3:a:samba:samba",
	"nfs-utils":  "cpe:2.3:a:linux-nfs:nfs-utils",
	"rsync":      "cpe:2.3:a:rsync:rsync",
	"rclone":     "cpe:2.3:a:rclone:rclone",
	"restic":     "cpe:2.3:a:restic:restic",
	"borg":       "cpe:2.3:a:borgbackup:borg",
	"borgbackup": "cpe:2.3:a:borgbackup:borg",
	"duplicity":  "cpe:2.3:a:duplicity:duplicity",
}

// ParseNixPackageName extracts upstream ecosystem information from a Nix package name.
// It returns NixUpstreamInfo with IsMapped=true if the package could be mapped to
// an upstream ecosystem, or IsMapped=false with CPE info for native packages.
//
// Examples:
//   - "python3Packages.requests" → PyPI ecosystem, name "requests"
//   - "nodePackages.typescript" → npm ecosystem, name "typescript"
//   - "openssl" → CPE "cpe:2.3:a:openssl:openssl", no ecosystem
//   - "my-custom-pkg" → IsMapped=false, no CPE
func ParseNixPackageName(nixPkgName, version string) NixUpstreamInfo {
	nixPkgName = strings.TrimSpace(nixPkgName)
	version = strings.TrimSpace(version)

	if nixPkgName == "" {
		return NixUpstreamInfo{}
	}

	// Try language ecosystem patterns first
	for _, prefix := range nixPackagePrefixes {
		matches := prefix.Pattern.FindStringSubmatch(nixPkgName)
		if len(matches) >= 2 {
			upstreamName := matches[1]
			if prefix.Ecosystem != Unknown {
				return NixUpstreamInfo{
					Ecosystem: prefix.Ecosystem,
					Name:      upstreamName,
					Version:   version,
					IsMapped:  true,
				}
			}
			// Pattern matched but ecosystem not supported - return unmapped
			return NixUpstreamInfo{
				Name:    upstreamName,
				Version: version,
			}
		}
	}

	// Try CPE mapping for native packages
	// Normalize: strip version suffixes like "openssl_3" or "python312"
	baseName := nixPkgName
	// Handle common suffixes like "_3", "-3.0", etc.
	if idx := strings.LastIndexAny(baseName, "_-"); idx > 0 {
		suffix := baseName[idx+1:]
		// If suffix looks like a version number, strip it
		if len(suffix) > 0 && (suffix[0] >= '0' && suffix[0] <= '9') {
			baseName = baseName[:idx]
		}
	}
	baseName = strings.ToLower(baseName)

	if cpe, ok := nixCPEMappings[baseName]; ok {
		return NixUpstreamInfo{
			Name:    baseName,
			Version: version,
			CPE:     cpe,
		}
	}

	// Also try the original name in case normalization removed too much
	if cpe, ok := nixCPEMappings[strings.ToLower(nixPkgName)]; ok {
		return NixUpstreamInfo{
			Name:    strings.ToLower(nixPkgName),
			Version: version,
			CPE:     cpe,
		}
	}

	// No mapping found
	return NixUpstreamInfo{
		Name:    nixPkgName,
		Version: version,
	}
}

// NixUpstreamPURL generates a Package URL for the upstream ecosystem.
// Returns empty string if the package couldn't be mapped to an upstream ecosystem.
//
// Examples:
//   - PyPI ecosystem, name "requests", version "2.31.0" → "pkg:pypi/requests@2.31.0"
//   - npm ecosystem, name "typescript", version "5.0.0" → "pkg:npm/typescript@5.0.0"
func (info NixUpstreamInfo) NixUpstreamPURL() string {
	if !info.IsMapped || info.Ecosystem == Unknown {
		return ""
	}

	purlType := ""
	switch info.Ecosystem {
	case PyPI:
		purlType = "pypi"
	case NPM:
		purlType = "npm"
	case RubyGems:
		purlType = "gem"
	case Cargo:
		purlType = "cargo"
	case Maven:
		purlType = "maven"
	case Go:
		purlType = "golang"
	case Hex:
		purlType = "hex"
	case Pub:
		purlType = "pub"
	case NuGet:
		purlType = "nuget"
	case CocoaPods:
		purlType = "cocoapods"
	case Packagist:
		purlType = "composer"
	default:
		return ""
	}

	if info.Version != "" {
		return "pkg:" + purlType + "/" + info.Name + "@" + info.Version
	}
	return "pkg:" + purlType + "/" + info.Name
}

// HasUpstreamEcosystem returns true if the Nix package maps to a language ecosystem
// supported by OSV (enabling vulnerability lookups via the OSV API).
func (info NixUpstreamInfo) HasUpstreamEcosystem() bool {
	return info.IsMapped && info.Ecosystem != Unknown
}

// HasCPE returns true if the Nix package has a CPE mapping for native package
// vulnerability lookups (via NVD/CVE databases).
func (info NixUpstreamInfo) HasCPE() bool {
	return info.CPE != ""
}

// FullCPE returns the complete CPE 2.3 string including version.
// Returns empty string if no CPE mapping exists.
//
// Example: "cpe:2.3:a:openssl:openssl:3.0.10:*:*:*:*:*:*:*"
func (info NixUpstreamInfo) FullCPE() string {
	if info.CPE == "" {
		return ""
	}
	version := info.Version
	if version == "" {
		version = "*"
	}
	// CPE 2.3 format: cpe:2.3:part:vendor:product:version:update:edition:language:sw_edition:target_sw:target_hw:other
	return info.CPE + ":" + version + ":*:*:*:*:*:*:*"
}
