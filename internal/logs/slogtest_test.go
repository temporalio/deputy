package logs

import (
	"bytes"
	"encoding/json"
	"log/slog"
	"testing"
	"testing/slogtest"
)

func TestSlogCompliance(t *testing.T) {
	var buf bytes.Buffer

	// We manually construct a ColorHandler wrapping a JSONHandler.
	// This allows us to use slogtest (which parses JSON) to verify
	// that ColorHandler correctly delegates WithAttrs, WithGroup, etc.
	//
	// Note: colorWriter won't trigger on JSON output because it looks for "level=INFO",
	// whereas JSON has "level":"INFO". This is fine; we are testing the handler delegation logic.
	h := &ColorHandler{
		internal: slog.NewJSONHandler(&buf, nil),
	}

	results := func() []map[string]any {
		var ms []map[string]any
		for line := range bytes.SplitSeq(buf.Bytes(), []byte{'\n'}) {
			if len(line) == 0 {
				continue
			}
			var m map[string]any
			if err := json.Unmarshal(line, &m); err != nil {
				t.Fatalf("json unmarshal error: %v", err)
			}
			ms = append(ms, m)
		}
		buf.Reset() // Clear buffer for next test case
		return ms
	}

	if err := slogtest.TestHandler(h, results); err != nil {
		t.Fatalf("slogtest failed: %v", err)
	}
}
