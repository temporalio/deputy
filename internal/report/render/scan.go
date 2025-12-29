package render

import (
	"strings"

	"github.com/picatz/deputy/internal/output"
)

// ScanResultsHeaderDoc builds the scan header block shown in text output.
func ScanResultsHeaderDoc(target, ref, commitHash, originURL string) output.Doc {
	var doc output.Doc
	doc.AddBlank()
	doc.AddLine(output.Span{Text: "Scan Results:", Style: output.StyleHeader})
	doc.AddLine(output.Span{Text: "  Target: "}, output.Span{Text: target, Style: output.StylePackageName})
	if strings.TrimSpace(ref) != "" {
		spans := []output.Span{
			{Text: "  Ref: "},
			{Text: ref, Style: output.StyleVersion},
		}
		if strings.TrimSpace(commitHash) != "" {
			spans = append(spans,
				output.Span{Text: " ("},
				output.Span{Text: commitHash, Style: output.StyleVersion},
				output.Span{Text: ")"},
			)
		}
		doc.AddLine(spans...)
	}
	if strings.TrimSpace(originURL) != "" {
		doc.AddLine(output.Span{Text: "  Origin: "}, output.Span{Text: originURL, Style: output.StyleMeta})
	}
	return doc
}
