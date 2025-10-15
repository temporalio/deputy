package tui

import (
    "strconv"
    "strings"
    tea "github.com/charmbracelet/bubbletea/v2"
    "github.com/charmbracelet/bubbles/v2/textinput"
)

// Live budget event
type LiveBudgetSet struct{ MaxPerMin int }
func (LiveBudgetSet) isEvent() {}

type paletteOverlay struct {
    ti      textinput.Model
    eventCh chan event
    errMsg  string
    sugg    []sugg
}

func newPalette(ch chan event) *paletteOverlay {
    ti := textinput.New()
    ti.Prompt = ":"
    ti.Placeholder = "set live-query true | set budget 20"
    ti.Focus()
    return &paletteOverlay{ ti: ti, eventCh: ch }
}

func (p *paletteOverlay) View(w, h int) string {
    // recompute suggestions for current input
    p.sugg = suggest(p.ti.Value())
    content := "COMMAND PALETTE\n\n" + p.ti.View()
    if len(p.sugg) > 0 {
        content += "\n\n" + styleDim.Render("Suggestions:") + "\n"
        max := 8
        if len(p.sugg) < max { max = len(p.sugg) }
        for i := 0; i < max; i++ {
            s := p.sugg[i]
            content += "  " + styleTabsActive.Render(s.text)
            if s.desc != "" { content += "  " + styleDim.Render(s.desc) }
            content += "\n"
        }
    }
    if p.errMsg != "" { content += "\n" + styleError.Render(p.errMsg) }
    return stylePane.Width(max(0, w-2)).Render(content)
}

func (p *paletteOverlay) HandleKey(msg tea.KeyPressMsg) bool {
    s := msg.String()
    switch s {
    case "esc":
        return true
    case "tab":
        // accept the first suggestion, if any
        if list := suggest(p.ti.Value()); len(list) > 0 {
            p.ti.SetValue(fillSuggestion(p.ti.Value(), list[0].text))
        }
        return false
    case "enter":
        line := strings.TrimSpace(strings.TrimPrefix(p.ti.Value(), ":"))
        if line == "" { return true }
        p.parseAndEmit(line)
        return true
    default:
        var cmd tea.Cmd
        p.ti, cmd = p.ti.Update(msg)
        _ = cmd
        return false
    }
}

func (p *paletteOverlay) parseAndEmit(line string) {
    toks := strings.Fields(line)
    if len(toks) == 0 { return }
    switch toks[0] {
    case "set":
        if len(toks) < 3 { p.errMsg = "usage: set <option> <value>"; return }
        opt := strings.ToLower(toks[1])
        val := strings.ToLower(toks[2])
        switch opt {
        case "live-query":
            on := val == "true" || val == "1" || val == "on"
            p.eventCh <- LiveQueryToggled{ On: on }
        case "budget":
            n, err := strconv.Atoi(toks[2])
            if err != nil || n < 0 { p.errMsg = "budget must be an integer"; return }
            p.eventCh <- LiveBudgetSet{ MaxPerMin: n }
        default:
            p.errMsg = "unknown option"
        }
    case "help":
        // No-op; show help overlay would be nicer
        p.eventCh <- FilterFailed{ Generation: 0, Err: nil }
    case "diag", "diagnostics":
        p.eventCh <- DiagnosticsRequested{}
    }
}

// Suggestion items for the palette
type sugg struct{ text string; desc string }

func suggest(raw string) []sugg {
    s := strings.TrimSpace(strings.TrimPrefix(raw, ":"))
    if s == "" {
        return []sugg{{"set", "Configure options"}, {"diagnostics", "Open diagnostics"}, {"help", "Help"}}
    }
    parts := strings.Fields(s)
    switch parts[0] {
    case "set":
        if len(parts) == 1 {
            return []sugg{{"set live-query ", "true|false"}, {"set budget ", "per-minute integer"}}
        }
        opt := parts[1]
        if len(parts) == 2 {
            switch opt {
            case "live-query":
                return []sugg{{"set live-query true", "Enable live queries"}, {"set live-query false", "Disable live queries"}}
            case "budget":
                return []sugg{{"set budget 10", "Lower throughput"}, {"set budget 20", "Default"}, {"set budget 50", "Higher throughput"}}
            }
        }
    case "diag":
        fallthrough
    case "diagnostics":
        return []sugg{{"diagnostics", "Open diagnostics overlay"}}
    case "help":
        return []sugg{{"help", "Show help"}}
    }
    return nil
}

// fillSuggestion replaces the current token with the suggestion text.
func fillSuggestion(raw, suggestion string) string {
    v := strings.TrimPrefix(raw, ":")
    cur := strings.Fields(v)
    // if empty, just use suggestion
    if len(cur) == 0 { return suggestion }
    // replace last token
    idx := strings.LastIndexFunc(v, func(r rune) bool { return r == ' ' || r == '\t' })
    if idx < 0 {
        return suggestion
    }
    prefix := strings.TrimSpace(v[:idx])
    if prefix == "" { return suggestion }
    return prefix + " " + suggestion
}
