package cloud

import "strings"

// Options configures cloud resource operations.
// This is the internal options type used by the cloud package.
// For the canonical target options, see targets.OpenOptions.
type Options struct {
	// Region overrides the default region.
	Region string

	// Profile specifies the credential profile to use.
	// For AWS: profile name from ~/.aws/credentials
	// For Azure: subscription ID
	// For GCP: project ID
	Profile string

	// AccountID overrides account/subscription/project detection.
	AccountID string

	// SmartDownload enables downloading only necessary blocks.
	// When true, the EBS Direct API downloads only blocks containing
	// package databases, reducing transfer time significantly (~7% of total).
	// Default: true
	SmartDownload bool

	// Ecosystems limits scanning to specific package ecosystems.
	// Empty means scan all ecosystems.
	Ecosystems []string
}

// DefaultOptions returns sensible defaults for cloud operations.
func DefaultOptions() Options {
	return Options{
		SmartDownload: true,
	}
}

// WithRegion returns a copy of opts with the region set.
func (o Options) WithRegion(region string) Options {
	o.Region = region
	return o
}

// WithProfile returns a copy of opts with the profile set.
func (o Options) WithProfile(profile string) Options {
	o.Profile = profile
	return o
}

// WithSmartDownload returns a copy of opts with smart download set.
func (o Options) WithSmartDownload(enabled bool) Options {
	o.SmartDownload = enabled
	return o
}

// WithEcosystems returns a copy of opts with ecosystems set.
func (o Options) WithEcosystems(ecosystems []string) Options {
	o.Ecosystems = ecosystems
	return o
}

// OptionsFromMap creates Options from a string map (e.g., from target options).
// This uses the canonical key names defined in targets package.
//
// Recognized keys:
//   - region, aws_region: Region override
//   - profile: Credential profile
//   - account, account_id: Account ID override
//   - smart_download: Enable smart block downloading
//   - ecosystems: Comma-separated ecosystem list
func OptionsFromMap(m map[string]string) Options {
	opts := DefaultOptions()

	// Region (check canonical key first, then shorthand)
	if v := m["aws_region"]; v != "" {
		opts.Region = v
	} else if v := m["region"]; v != "" {
		opts.Region = v
	}

	// Profile
	if v := m["profile"]; v != "" {
		opts.Profile = v
	}

	// Account ID (check both variations)
	if v := m["account_id"]; v != "" {
		opts.AccountID = v
	} else if v := m["account"]; v != "" {
		opts.AccountID = v
	}

	// Smart download (default true, explicit false disables)
	if v, ok := m["smart_download"]; ok {
		opts.SmartDownload = v != "false" && v != "0"
	}

	// Ecosystems
	if v := m["ecosystems"]; v != "" {
		opts.Ecosystems = strings.Split(v, ",")
	}

	return opts
}
