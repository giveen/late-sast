package gui

import (
	"fmt"

	"late/internal/session"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// ShowSessionBrowser opens a dialog listing saved sessions and calls onLoad
// with the chosen session's history path.
func (a *App) ShowSessionBrowser(onLoad func(histPath string)) {
	metas, err := session.ListSessions()
	if err != nil || len(metas) == 0 {
		dialog.ShowInformation("Sessions", "No saved sessions found.", a.window)
		return
	}

	// Build display labels.
	labels := make([]string, len(metas))
	for i, m := range metas {
		labels[i] = fmt.Sprintf("%s — %s (%d messages)",
			m.ID, m.Title, m.MessageCount)
	}

	list := widget.NewList(
		func() int { return len(labels) },
		func() fyne.CanvasObject {
			return widget.NewLabel("")
		},
		func(id widget.ListItemID, item fyne.CanvasObject) {
			item.(*widget.Label).SetText(labels[id])
		},
	)

	var d dialog.Dialog
	list.OnSelected = func(id widget.ListItemID) {
		d.Hide()
		onLoad(metas[id].HistoryPath)
	}

	d = dialog.NewCustomWithoutButtons("Open Session", list, a.window)
	d.Resize(fyne.NewSize(600, 400))
	d.Show()
}
