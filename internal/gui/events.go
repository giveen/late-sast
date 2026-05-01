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
//   - onUsage     — optional callback to receive (usedTokens, maxTokens); nil to skip
func (a *App) startEventLoop(
	o common.Orchestrator,
	panel *ChatPanel,
	tabItem *container.TabItem,
	agentLabel string,
	onUsage func(used, max int),
) {
	go func() {
		var acc string
		streaming := false
		thinkingStreaming := false

		for event := range o.Events() {
			switch e := event.(type) {

			case common.ContentEvent:
				// onEndTurn emits a ContentEvent with empty content/reasoning but
				// carries final usage accounting. Update the usage bar and skip
				// the message update to avoid clearing the last bubble.
				if e.Content == "" && e.ReasoningContent == "" {
					if e.Usage.PromptTokens > 0 && onUsage != nil {
						used, max := e.Usage.PromptTokens, o.MaxTokens()
						fyne.Do(func() { onUsage(used, max) })
					}
					continue
				}

				// Reasoning / thinking content — streams before the response.
				if e.ReasoningContent != "" {
					if !thinkingStreaming {
						thinkingStreaming = true
						fyne.Do(func() { panel.StartThinking() })
					}
					rc := e.ReasoningContent
					fyne.Do(func() { panel.UpdateThinking(rc) })
				}

				// Response content — collapse thinking box when it first arrives.
				if e.Content != "" {
					if thinkingStreaming {
						thinkingStreaming = false
						fyne.Do(func() { panel.FinalizeThinking() })
					}
					if !streaming {
						streaming = true
						acc = ""
						fyne.Do(func() {
							panel.AppendMessage("assistant", "")
						})
					}
					acc = e.Content
					content := acc // local copy — fyne.Do is async; avoid closure data-race
					fyne.Do(func() {
						panel.UpdateLastMessage(content)
					})
					if e.Usage.PromptTokens > 0 && onUsage != nil {
						used, max := e.Usage.PromptTokens, o.MaxTokens()
						fyne.Do(func() { onUsage(used, max) })
					}
				}

			case common.StatusEvent:
				switch e.Status {
				case "thinking":
					// Collapse the thinking box between tool calls;
					// StartThinking will reopen/reuse the same accordion on next chunk.
					if thinkingStreaming {
						thinkingStreaming = false
						fyne.Do(func() { panel.FinalizeThinking() })
					}
					streaming = false
					acc = ""

				case "idle":
					if thinkingStreaming {
						thinkingStreaming = false
						fyne.Do(func() { panel.FinalizeThinking() })
					}
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
					if thinkingStreaming {
						fyne.Do(func() { panel.FinalizeThinking() })
					}
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
// a chat panel, a "Stop" button on the left, and a context-usage label on the right.
func makeTabContent(panel *ChatPanel, stopFn func(), usageLabel *widget.Label) fyne.CanvasObject {
	stopBtn := widget.NewButton("■ Stop", stopFn)
	header := container.NewBorder(nil, nil, stopBtn, usageLabel, nil)
	return container.NewBorder(header, nil, nil, nil, panel)
}
