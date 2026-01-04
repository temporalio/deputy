package render

import (
	"fmt"
	"strings"

	"github.com/picatz/deputy/internal/output"
	"github.com/picatz/deputy/internal/scan"
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

// ContainerScanHeaderDoc builds a container-specific scan header block with image metadata.
func ContainerScanHeaderDoc(target string, imageInfo *scan.ImageInfo) output.Doc {
	var doc output.Doc
	doc.AddBlank()
	doc.AddLine(output.Span{Text: "Container Scan Results:", Style: output.StyleHeader})
	doc.AddLine(output.Span{Text: "  Image: "}, output.Span{Text: target, Style: output.StylePackageName})

	if imageInfo == nil {
		return doc
	}

	// Digest
	if imageInfo.Metadata.Digest != "" {
		doc.AddLine(
			output.Span{Text: "  Digest: "},
			output.Span{Text: imageInfo.Metadata.Digest, Style: output.StyleVersion},
		)
	}

	// Platform info (arch/os)
	if imageInfo.Metadata.Architecture != "" || imageInfo.Metadata.OS != "" {
		platform := imageInfo.Metadata.OS
		if imageInfo.Metadata.Architecture != "" {
			if platform != "" {
				platform += "/"
			}
			platform += imageInfo.Metadata.Architecture
		}
		if imageInfo.Metadata.Variant != "" {
			platform += "/" + imageInfo.Metadata.Variant
		}
		doc.AddLine(
			output.Span{Text: "  Platform: "},
			output.Span{Text: platform, Style: output.StyleVersion},
		)
	}

	// Layer count and size
	var metaParts []string
	if imageInfo.Metadata.LayerCount > 0 {
		metaParts = append(metaParts, fmt.Sprintf("%d layers", imageInfo.Metadata.LayerCount))
	}
	if imageInfo.Metadata.Size > 0 {
		metaParts = append(metaParts, formatSize(imageInfo.Metadata.Size))
	}
	if len(metaParts) > 0 {
		doc.AddLine(
			output.Span{Text: "  Size: "},
			output.Span{Text: strings.Join(metaParts, ", "), Style: output.StyleMeta},
		)
	}

	// Created time
	if !imageInfo.Metadata.Created.IsZero() {
		doc.AddLine(
			output.Span{Text: "  Created: "},
			output.Span{Text: imageInfo.Metadata.Created.Format("2006-01-02 15:04:05"), Style: output.StyleMeta},
		)
	}

	return doc
}

// ImageSecuritySummaryDoc builds a summary of image configuration security issues.
func ImageSecuritySummaryDoc(imageInfo *scan.ImageInfo) output.Doc {
	var doc output.Doc
	if imageInfo == nil {
		return doc
	}

	var issues []output.Line

	// Check for root user
	if imageInfo.Config.IsRootUser() {
		issues = append(issues, output.Line{
			output.Span{Text: "  "},
			output.Span{Text: "!", Style: output.StyleRemoved},
			output.Span{Text: " Runs as "},
			output.Span{Text: "root", Style: output.StyleRemoved},
			output.Span{Text: " user"},
		})
	}

	// Check for sensitive environment variables
	if sensitiveEnv := imageInfo.Config.HasSensitiveEnv(); len(sensitiveEnv) > 0 {
		envStr := strings.Join(sensitiveEnv, ", ")
		if len(envStr) > 60 {
			envStr = envStr[:57] + "..."
		}
		issues = append(issues, output.Line{
			output.Span{Text: "  "},
			output.Span{Text: "!", Style: output.StyleRemoved},
			output.Span{Text: " Sensitive env vars: "},
			output.Span{Text: envStr, Style: output.StyleRemoved},
		})
	}

	// Check for missing healthcheck
	if imageInfo.Config.Healthcheck == nil {
		issues = append(issues, output.Line{
			output.Span{Text: "  "},
			output.Span{Text: "-", Style: output.StyleMeta},
			output.Span{Text: " No healthcheck defined"},
		})
	}

	// Check for excessive layers
	if imageInfo.Metadata.LayerCount > 25 {
		issues = append(issues, output.Line{
			output.Span{Text: "  "},
			output.Span{Text: "-", Style: output.StyleMeta},
			output.Span{Text: fmt.Sprintf(" Excessive layers (%d) - consider optimizing", imageInfo.Metadata.LayerCount)},
		})
	}

	// Check for large image size (>1GB)
	if imageInfo.Metadata.Size > 1073741824 {
		issues = append(issues, output.Line{
			output.Span{Text: "  "},
			output.Span{Text: "-", Style: output.StyleMeta},
			output.Span{Text: fmt.Sprintf(" Large image size (%s) - consider using smaller base", formatSize(imageInfo.Metadata.Size))},
		})
	}

	if len(issues) == 0 {
		return doc
	}

	doc.AddBlank()
	doc.AddLine(output.Span{Text: "Image Configuration:", Style: output.StyleHeader})
	for _, issue := range issues {
		doc.Lines = append(doc.Lines, issue)
	}

	return doc
}

// formatSize formats bytes into human-readable size.
func formatSize(bytes int64) string {
	const (
		KB = 1024
		MB = KB * 1024
		GB = MB * 1024
	)
	switch {
	case bytes >= GB:
		return fmt.Sprintf("%.1f GB", float64(bytes)/GB)
	case bytes >= MB:
		return fmt.Sprintf("%.1f MB", float64(bytes)/MB)
	case bytes >= KB:
		return fmt.Sprintf("%.1f KB", float64(bytes)/KB)
	default:
		return fmt.Sprintf("%d B", bytes)
	}
}
