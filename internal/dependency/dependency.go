package dependency

// ID captures the identity of a dependency independently of a scan.
type ID struct {
	Name      string
	Ecosystem string
	PURL      string
}

// ManifestRef describes where a dependency is declared in a manifest or lockfile.
type ManifestRef struct {
	Path    string
	Manager string
	Groups  []string
}
