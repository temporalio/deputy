// Package distroeol identifies operating system releases and reports their
// end-of-life status from a vendored, dated snapshot of endoflife.date.
//
// An end-of-life release stops receiving security fixes, and its advisory feed
// stops growing, so a vulnerability scan of it understates its risk more each
// day. This package answers two questions without network access: which
// release does an inventory describe (from OS package metadata, or from a
// container image reference whose tag names a release), and is that release
// still supported on a given date.
//
// The dataset lives in data/releases.json with its snapshot date. A release the
// dataset does not know is reported as unknown; nothing here guesses.
//
// Regenerating the dataset: fetch
// https://endoflife.date/api/v1/products/{alpine-linux,debian,ubuntu}/, keep
// release, codename (first word, lowercased), releaseDate, eolFrom, eoesFrom,
// isLts, and latest.name, and set "snapshot" to the capture date.
package distroeol
