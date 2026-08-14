package mise

import "testing"

// FuzzParse exercises the mise/.tool-versions parser on arbitrary input. Config
// files are untrusted and feed scanning and pinning, so parsing must never panic
// and any returned config must be self-consistent.
func FuzzParse(f *testing.F) {
	seeds := []string{
		"[tools]\nnode = \"20.11.0\"\n",
		"[tools]\npython = [\"3.11\", \"3.12\"]\n\"npm:prettier\" = \"latest\"\nripgrep = { version = \"14\" }\n[settings]\nlockfile = true\nminimum_release_age = \"14d\"\n",
		"node 22.5.0\npython 3.11 3.12  # comment\nnpm:prettier latest\n",
		"",
		"[tools]",
		"= = =",
		"node = 20",
	}
	for _, s := range seeds {
		f.Add("mise.toml", s)
		f.Add(".tool-versions", s)
	}
	f.Fuzz(func(t *testing.T, path, data string) {
		cfg, err := Parse(path, []byte(data))
		if err != nil {
			return // parse errors are acceptable; a panic is not
		}
		if cfg == nil {
			t.Fatal("nil config with nil error")
		}
		for _, ts := range cfg.Tools {
			if ts.Key == "" {
				t.Errorf("tool entry has empty Key: %+v", ts)
			}
			// IsExactVersion must tolerate any parsed version string.
			for _, v := range ts.Versions {
				_ = IsExactVersion(v)
			}
		}
	})
}

// FuzzParseLock exercises the mise.lock parser and lookups on arbitrary input.
func FuzzParseLock(f *testing.F) {
	f.Add(sampleLock)
	f.Add(realLock) // real mise format: [tools."key"."platforms.os-arch"]
	f.Add("")
	f.Add("[[tools.node]]\nversion = \"20.11.0\"\nbackend = \"core:node\"\n")
	f.Add("[[tools.x]]\n[tools.x.platforms.linux-x64]\nchecksum = \"sha256:abc\"\n")
	f.Fuzz(func(t *testing.T, data string) {
		lf, err := ParseLock("mise.lock", []byte(data))
		if err != nil {
			return
		}
		if lf == nil {
			t.Fatal("nil lockfile with nil error")
		}
		// Lookups and accessors must not panic on any parsed lockfile.
		_ = lf.First("node")
		_ = lf.Locked("node", "20.11.0")
		_ = lf.Lookup(ToolSpec{Name: "node", Key: "node"}, "20", nil)
	})
}
