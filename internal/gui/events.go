package gui

import (
	"fmt"
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
	currentPhase := "STOP"

	// setTabStatus updates the tab label with an emoji prefix and optional turn
	// counter. Root tabs (tabItem == nil) are left unchanged.
	setTabStatus := func(prefix string, turn, maxTurns int) {
		if tabItem == nil {
			return
		}
		text := agentLabel
		if currentPhase != "" {
			text = fmt.Sprintf("%s · %s", text, currentPhase)
		}
		if turn > 0 {
			if maxTurns > 0 {
				text = fmt.Sprintf("%s (%d/%d)", agentLabel, turn, maxTurns)
			} else {
				text = fmt.Sprintf("%s (%d)", agentLabel, turn)
			}
			if currentPhase != "" {
				text = fmt.Sprintf("%s · %s", text, currentPhase)
			}
		}
		if prefix != "" {
			text = prefix + text
		}
		fyne.Do(func() {
			tabItem.Text = text
			a.tabs.Refresh()
		})
	}
	if tabItem != nil {
		setTabStatus("", 0, 0)
	}

	go func() {
		var acc string
		streaming := false
		thinkingStreaming := false
		cachedHistoryLen := -1
		cachedHistoryTokens := 0
		currentTurn := 0
		currentMaxTurns := 0

		updateUsage := func(e common.ContentEvent) {
			if onUsage == nil {
				return
			}

			used := 0
			if e.Usage.TotalTokens > 0 {
				used = e.Usage.TotalTokens
			} else if e.Usage.PromptTokens > 0 {
				used = e.Usage.PromptTokens
			} else {
				history := o.History()
				if len(history) != cachedHistoryLen {
					cachedHistoryTokens = common.CalculateHistoryTokens(history, o.SystemPrompt(), o.ToolDefinitions())
					cachedHistoryLen = len(history)
				}
				used = cachedHistoryTokens + common.EstimateEventTokens(e)
			}

			max := o.MaxTokens()
			fyne.Do(func() { onUsage(used, max) })
		}

		for event := range o.Events() {
			switch e := event.(type) {

			case common.ContentEvent:
				// onEndTurn emits a ContentEvent with empty content/reasoning but
				// carries final usage accounting. Update the usage bar and skip
				// the message update to avoid clearing the last bubble.
				if e.Content == "" && e.ReasoningContent == "" {
					updateUsage(e)
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
					updateUsage(e)
				} else {
					// Even without content deltas, keep usage indicator current.
					updateUsage(e)
				}

			case common.StatusEvent:
				if e.Turn > 0 {
					currentTurn = e.Turn
				}
				if e.MaxTurns > 0 {
					currentMaxTurns = e.MaxTurns
				}
				switch e.Status {
				case "queued":
					// Agent is waiting for the GPU lock.
					setTabStatus("⏳ ", currentTurn, currentMaxTurns)

				case "thinking":
					// Agent is streaming from the LLM (holds GPU lock).
					setTabStatus("🧠 ", currentTurn, currentMaxTurns)
					// Collapse the thinking box between tool calls;
					// StartThinking will reopen/reuse the same accordion on next chunk.
					if thinkingStreaming {
						thinkingStreaming = false
						fyne.Do(func() { panel.FinalizeThinking() })
					}
					streaming = false
					acc = ""

				case "working":
					// Agent released the GPU and is executing tool calls.
					setTabStatus("⚙ ", currentTurn, currentMaxTurns)

				case "idle":
					setTabStatus("", 0, 0)
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
					setTabStatus("", 0, 0)
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
					setTabStatus("", 0, 0)
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
					if in := a.inputForOrchestrator(o); in != nil {
						fyne.Do(func() {
							in.SetEnabled(true)
						})
					}
					// Close the subagent tab — the error is already surfaced in the
					// main tab as the spawn_subagent tool result, so the orphan tab
					// just clutters the UI. Show a notification instead.
					if tabItem != nil {
						var msg string
						if e.Error != nil {
							msg = e.Error.Error()
						}
						label := agentLabel
						fyne.Do(func() {
							if msg != "" {
								a.sendNotification("Error in "+label, msg)
							}
							a.closeSubagentTab(tabItem, o, label)
						})
					}
				}

			case common.ProjectMapLoadedEvent:
				a.SetArchitecture(e.Data)

			case common.PhaseEvent:
				if a.currentPhaseLabel != nil && o.ID() == "main" {
					phaseText := "Current Phase: " + e.To
					fyne.Do(func() {
						a.currentPhaseLabel.SetText(phaseText)
					})
				}
				if tabItem != nil {
					currentPhase = e.To
					setTabStatus("", currentTurn, currentMaxTurns)
				}

			case common.MissionSnapshotEvent:
				if o.ID() == "main" {
					snapshot := e
					fyne.Do(func() {
						a.updateMissionSnapshot(snapshot)
					})
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
