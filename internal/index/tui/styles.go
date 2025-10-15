package tui

import (
    lipgloss "github.com/charmbracelet/lipgloss/v2"
)

// Ultraviolet-inspired palette (dark)
var (
    colBgBase      = lipgloss.Color("#1f2430")
    colBgSurface   = lipgloss.Color("#2b303b")
    colAccentPri   = lipgloss.Color("#8fbcbb")
    colAccentSec   = lipgloss.Color("#b48ead")
    colTextHigh    = lipgloss.Color("#eceff4")
    colTextLow     = lipgloss.Color("#a6accd")
    colStatusGood  = lipgloss.Color("#a3be8c")
    colStatusWarn  = lipgloss.Color("#ebcb8b")
    colStatusErr   = lipgloss.Color("#bf616a")
)

// Shared styles
var (
    styleTitle     = lipgloss.NewStyle().Foreground(colAccentSec).Bold(true)
    styleHeader    = lipgloss.NewStyle().Foreground(colTextHigh).Bold(true)
    styleLabel     = lipgloss.NewStyle().Foreground(colAccentPri).Bold(true)
    styleDim       = lipgloss.NewStyle().Foreground(colTextLow)
    styleError     = lipgloss.NewStyle().Foreground(colStatusErr).Bold(true)
    styleWarn      = lipgloss.NewStyle().Foreground(colStatusWarn).Bold(true)
    styleGood      = lipgloss.NewStyle().Foreground(colStatusGood).Bold(true)

    stylePane      = lipgloss.NewStyle().Border(lipgloss.NormalBorder()).BorderForeground(lipgloss.Color("238")).Padding(0, 0)
    stylePaneFocus = lipgloss.NewStyle().Border(lipgloss.RoundedBorder()).BorderForeground(colAccentPri).Padding(0, 0)
    styleDivider   = lipgloss.NewStyle().Foreground(lipgloss.Color("238"))

    styleListHeader   = lipgloss.NewStyle().Bold(true).Foreground(colTextHigh)
    styleListRow      = lipgloss.NewStyle().Foreground(colTextHigh)
    styleListMeta     = lipgloss.NewStyle().Foreground(colTextLow)
    styleListSel      = lipgloss.NewStyle().Foreground(colAccentPri).Bold(true)
    styleListSelUnf   = lipgloss.NewStyle().Foreground(colAccentSec).Bold(true)

    styleTabsActive   = lipgloss.NewStyle().Foreground(colAccentPri).Bold(true)
    styleTabsInactive = lipgloss.NewStyle().Foreground(colTextLow)
)

// Pane chrome dimensions used to derive inner viewport sizes
const (
    paneBorderW = 1
    paneHPad    = 0
    paneVPad    = 0
    paneGutter  = 1
)

func paneInnerWidth(w int) int {
    chrome := 2*(paneBorderW+paneHPad)
    if w <= chrome { return 0 }
    return w - chrome
}

func paneInnerHeight(h int) int {
    chrome := 2*(paneBorderW+paneVPad)
    if h <= chrome { return 0 }
    return h - chrome
}

// paneBox returns a style adjusted for compact mode (no borders) to save space.
func paneBox(w int, focused bool, compact bool) lipgloss.Style {
    base := stylePane
    if focused { base = stylePaneFocus }
    if compact {
        // No border in compact; keep zero padding to maximize space
        return lipgloss.NewStyle().Padding(paneVPad, paneHPad)
    }
    return base.Padding(paneVPad, paneHPad)
}

// placeBox ensures a string is rendered into a fixed w x h box.
func placeBox(w, h int, content string) string {
    if w <= 0 || h <= 0 {
        return ""
    }
    return lipgloss.Place(w, h, lipgloss.Left, lipgloss.Top, content)
}

func hSpacer(w int) string { return lipgloss.NewStyle().Width(w).Render("") }
func vSpacer(h int) string { return lipgloss.NewStyle().Height(h).Render("") }
