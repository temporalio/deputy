// Package alpine compares installed Alpine packages against the newest build
// their release branch publishes.
//
// Advisory sources for Alpine (OSV's Alpine feed among them) are built from
// the distribution's secfixes annotations, which land after a security release
// does: for a window that can last weeks, the branch already ships the fixed
// build while every feed still reports the older build as clean. The branch
// index (APKINDEX) has no such lag, since a build is in it the moment it ships.
// Comparing installed versions against it does not say which CVEs a newer
// build fixes, so the result is a [vulnerabilityv1.DistroUpdate] signal that
// the advisory answer may be incomplete, never a confirmed vulnerability.
package alpine
