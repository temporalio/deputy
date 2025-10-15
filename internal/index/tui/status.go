package tui

import (
    "fmt"
    "time"
)

type statusBarModel struct {
    total   int
    visible int
    latency time.Duration
    healthy bool
    budgetMax int
    budgetRem int
    liveOn bool
}

func newStatusBar() statusBarModel { return statusBarModel{ healthy: true } }

func (m *statusBarModel) Set(total, visible int, latency time.Duration) { m.total, m.visible, m.latency = total, visible, latency }

func (m *statusBarModel) SetBudget(max, remaining int, liveOn bool) { m.budgetMax, m.budgetRem, m.liveOn = max, remaining, liveOn }

func (m statusBarModel) View() string {
    health := styleGood.Render("●")
    lat := ""
    if m.latency > 0 { lat = fmt.Sprintf("  %s", styleDim.Render(m.latency.Truncate(time.Millisecond).String())) }
    budget := ""
    if m.liveOn && m.budgetMax > 0 { budget = fmt.Sprintf("  %s", styleDim.Render(fmt.Sprintf("Budget %d/%d", m.budgetRem, m.budgetMax))) }
    return styleDim.Render("Total ")+itoa(m.total)+styleDim.Render(" · Visible ")+itoa(m.visible)+lat+budget+"  "+health
}
