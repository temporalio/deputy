package targets

import (
	"fmt"
	"net/netip"
	"strings"
)

// RemoteTargetPolicy configures allowlists for remote server mode.
// It is used to permit explicit internal hosts or CIDR ranges while keeping
// default SSRF protections enabled.
type RemoteTargetPolicy struct {
	// AllowedHosts is a list of hostnames allowed to resolve to private IPs.
	// Entries may be exact hosts or suffixes prefixed with a dot (e.g., ".corp.local").
	AllowedHosts []string

	// AllowedCIDRs is a list of CIDR ranges allowed for outbound connections.
	AllowedCIDRs []netip.Prefix

	// AllowSSH permits SSH-style git targets (ssh://, git@host:repo).
	AllowSSH bool

	// AllowLoopback permits loopback targets in remote server mode.
	AllowLoopback bool

	// AllowLinkLocal permits link-local targets in remote server mode.
	AllowLinkLocal bool
}

// ParseCIDRs parses CIDR strings into netip prefixes.
func ParseCIDRs(values []string) ([]netip.Prefix, error) {
	if len(values) == 0 {
		return nil, nil
	}
	out := make([]netip.Prefix, 0, len(values))
	for _, raw := range values {
		cidr := strings.TrimSpace(raw)
		if cidr == "" {
			continue
		}
		prefix, err := netip.ParsePrefix(cidr)
		if err != nil {
			return nil, fmt.Errorf("invalid CIDR %q: %w", cidr, err)
		}
		out = append(out, prefix)
	}
	return out, nil
}

func (p *RemoteTargetPolicy) allowsHost(host string) bool {
	if p == nil || len(p.AllowedHosts) == 0 {
		return false
	}
	normalized := normalizeHost(host)
	if normalized == "" {
		return false
	}
	for _, entry := range p.AllowedHosts {
		entry = normalizeHost(entry)
		if entry == "" {
			continue
		}
		if entry == normalized {
			return true
		}
		if strings.HasPrefix(entry, "*.") {
			entry = strings.TrimPrefix(entry, "*")
		}
		if after, ok := strings.CutPrefix(entry, "."); ok {
			if normalized == after {
				return true
			}
			if strings.HasSuffix(normalized, entry) {
				return true
			}
		}
	}
	return false
}

func (p *RemoteTargetPolicy) allowsAddr(addr netip.Addr) bool {
	if p == nil {
		return false
	}
	for _, prefix := range p.AllowedCIDRs {
		if prefix.Contains(addr) {
			return true
		}
	}
	if addr.IsLoopback() || addr.IsUnspecified() {
		return p.AllowLoopback
	}
	if addr.IsLinkLocalUnicast() {
		return p.AllowLinkLocal
	}
	return false
}

func normalizeHost(host string) string {
	host = strings.TrimSpace(strings.ToLower(host))
	if host == "" {
		return ""
	}
	host = strings.TrimSuffix(host, ".")
	host = strings.TrimPrefix(strings.TrimSuffix(host, "]"), "[")
	return host
}
