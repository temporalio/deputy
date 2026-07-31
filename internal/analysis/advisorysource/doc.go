// Package advisorysource defines Deputy's advisory-source seam: the abstraction
// over components that, given a set of packages, return known advisories
// (vulnerabilities and malware) affecting them.
//
// A [Source] is any advisory provider: the built-in OSV source today, and
// external threat-feed or vendor plugins in the future. Every source implements
// the same contract and returns the same proto types (deputy.plugin.v1 and
// deputy.vulnerability.v1), so built-in and plugin sources are interchangeable;
// this mirrors how Deputy's inventory extractors achieve built-in/plugin parity.
//
// A [Registry] aggregates sources: it routes each package only to sources whose
// declared [Capabilities] cover the package's ecosystem and artifact kind, runs
// them concurrently, merges findings with union-with-provenance semantics (a
// finding corroborated by several sources records each in Finding.sources), and
// reports coverage, including the (ecosystem, artifact) combinations no source
// could answer for, so callers can tell a genuinely clean result from an
// unqueried one instead of failing the whole scan.
//
// Advisory records (the shared descriptions keyed by advisory ID) merge
// first-source-wins in registration order: when two sources return the same
// advisory ID with different record contents, the earlier-registered source's
// record is kept whole, with the built-in OSV source registered first by
// default. Provenance for who reported a finding lives on Finding.sources, not
// on the advisory record.
//
// External sources are trusted components: a plugin subprocess runs with
// Deputy's operating-system privileges and a source's findings feed policy and
// remediation decisions verbatim, which is why sources only ever load by
// explicit opt-in (config file or DEPUTY_ADVISORY_SOURCES), never by PATH
// discovery.
package advisorysource
