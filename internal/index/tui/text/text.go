package text

import (
    "strings"
    runewidth "github.com/mattn/go-runewidth"
)

// TruncateEnd truncates the string to width with an ellipsis if needed.
func TruncateEnd(s string, width int) string {
    if width <= 0 {
        return ""
    }
    w := runewidth.StringWidth(s)
    if w <= width {
        return s
    }
    if width <= 1 {
        return runewidth.Truncate(s, width, "")
    }
    // leave space for ellipsis
    return runewidth.Truncate(s, width-1, "") + "…"
}

// TruncateMiddle truncates the middle with an ellipsis to fit width.
func TruncateMiddle(s string, width int) string {
    if width <= 0 {
        return ""
    }
    if runewidth.StringWidth(s) <= width {
        return s
    }
    if width <= 1 {
        return runewidth.Truncate(s, width, "")
    }
    // Split roughly in half and insert ellipsis
    left := (width - 1) / 2
    right := width - 1 - left
    prefix := runewidth.Truncate(s, left, "")
    // Reverse for suffix-safe truncation
    rev := reverse(s)
    suffixRev := runewidth.Truncate(rev, right, "")
    suffix := reverse(suffixRev)
    return prefix + "…" + suffix
}

// PadEnd pads the string on the right to the display width using spaces.
func PadEnd(s string, width int) string {
    if width <= 0 { return "" }
    return runewidth.FillRight(s, width)
}

func reverse(s string) string {
    var b strings.Builder
    b.Grow(len(s))
    r := []rune(s)
    for i := len(r) - 1; i >= 0; i-- {
        b.WriteRune(r[i])
    }
    return b.String()
}
