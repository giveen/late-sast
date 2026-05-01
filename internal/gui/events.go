package gui

import (
	"late/internal/common"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// startEventLoop drains the orchestrator event channel in a goroutine and
// dispatches events to the relevant ChatPanel and tab.
//
//   - panel       — the ChatPanel belonging to this orchestrator's tab
//   - tabItem     — nil for the root/main tab (never closed)
//   - agentLabel  — human-readable phase label (empty for root)
func (a *App) startEventLoop(
	o common.Orchestrator,
	panel *ChatPanel,
	tabItem *container.TabItem,
	agentLabel string,
) {
	go func() {
		var acc string
		streaming := false

		for event := range o.Events() {
			switch e := event.(type) {

			case common.ContentEvent:
				if !streaming {
					// First chunk: add an empty assistant bubble to fill.
					streaming = true
					acc = ""
					fyne.Do(func() {
						panel.AppendMessage("assistant", "")
					})
				}
				acc = e.Content
				fyne.Do(func() {
					panel.UpdateLastMessage(acc)
				})

			case common.StatusEvent:
				switch e.Status {
				case "thinking":
					streaming = false
					acc = ""

				case "idle":
					if streaming {
						streaming = false
						fyne.Do(func() {
							panel.FinalizeLastMessage()
						})
					}
					if a.inputForOrchestrator(o) != nil {
						fyne.Do(func() {
							a.inputForOrchestrator(o).SetEnabled(true)
						})
					}

				case "closed":
					if streaming {
						fyne.Do(func() {
							panel.FinalizeLastMessage()
						})
					}
					if tabItem != nil {
						label := agentLabel
						fyne.Do(func() {
							a.closeSubagentTab(tabItem, o, label)
						})
					}
					return

				case "error":
					// Keep tab open so the user can read the error.
					if e.Error != nil {
						msg := e.Error.Error()
						fyne.Do(func() {
							panel.AppendMessage("error", "⚠ "+msg)
						})
						if tabItem != nil {
							fyne.Do(func() {
								a.sendNotification("Error in "+agentLabel, msg)
							})
						}
					}
				}

			case common.ChildAddedEvent:
				// Wire up a new subagent tab.
				child := e.Child
				agentType := e.AgentType
				fyne.Do(func() {
					a.openSubagentTab(child, agentType)
				})
			}
		}
	}()
}

// inputForOrchestrator returns the InputPanel associated with the given orchestrator
// (only the root orchestrator has one).
func (a *App) inputForOrchestrator(o common.Orchestrator) *InputPanel {
	a.mu.Lock()
	defer a.mu.Unlock()
	if o.ID() == "main" {
		return a.mainInput
	}
	return nil
}

// makeTabContent builds the content widget for a subagent tab:
// a chat panel + a "Stop" toolbar at the top.
func makeTabContent(panel *ChatPanel, stopFn func()) fyne.CanvasObject {
	stopBtn := widget.NewButton("■ Stop", stopFn)
	header := container.NewHBox(stopBtn)
	return container.NewBorder(header, nil, nil, nil, panel)
}
