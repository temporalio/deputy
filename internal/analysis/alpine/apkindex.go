package alpine

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
)

// maxIndexBytes bounds how much decompressed index data is read, so a hostile
// or corrupt mirror response cannot exhaust memory. A branch's main index is
// a few megabytes.
const maxIndexBytes = 64 << 20

// indexEntry is one package stanza from an APKINDEX: the binary package, the
// build version, and the origin (source) package it was built from.
type indexEntry struct {
	Name    string
	Version string
	Origin  string
}

// parseAPKINDEX reads an APKINDEX.tar.gz and returns its package entries.
//
// The archive is a signature segment followed by the index segment, each its
// own gzip member; the signature tar carries no end-of-archive marker, so the
// members read as one tar stream. Only the APKINDEX member is parsed.
func parseAPKINDEX(r io.Reader) ([]indexEntry, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("open APKINDEX gzip: %w", err)
	}
	defer gz.Close()

	tr := tar.NewReader(io.LimitReader(gz, maxIndexBytes))
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil, errors.New("APKINDEX member not found in archive")
		}
		if err != nil {
			return nil, fmt.Errorf("read APKINDEX archive: %w", err)
		}
		if hdr.Name == "APKINDEX" {
			return parseIndexText(tr)
		}
	}
}

// parseIndexText parses the APKINDEX text format: blank-line separated
// stanzas of single-letter "K:value" fields. P is the package name, V the
// version, o the origin.
func parseIndexText(r io.Reader) ([]indexEntry, error) {
	var entries []indexEntry
	var cur indexEntry
	flush := func() {
		if cur.Name != "" && cur.Version != "" {
			if cur.Origin == "" {
				cur.Origin = cur.Name
			}
			entries = append(entries, cur)
		}
		cur = indexEntry{}
	}

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1<<20)
	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			flush()
			continue
		}
		key, val, ok := strings.Cut(line, ":")
		if !ok {
			continue
		}
		switch key {
		case "P":
			cur.Name = val
		case "V":
			cur.Version = val
		case "o":
			cur.Origin = val
		}
	}
	if err := sc.Err(); err != nil {
		return nil, fmt.Errorf("parse APKINDEX: %w", err)
	}
	flush()
	return entries, nil
}
