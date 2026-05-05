package gui

import (
	"context"
	"fmt"
	"sync"

	"late/internal/client"
	"late/internal/common"
	"late/internal/session"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

func formatContextUsage(used, max int) string {
	if max > 0 {
		pct := float64(used) / float64(max) * 100
		return fmt.Sprintf("Context: %d\u202f/\u202f%d  (%.0f%%)", used, max, pct)
	}
	return fmt.Sprintf("Context: %d tokens", used)
}

func formatSubagentContextUsage(used, max int) string {
	if max > 0 {
		pct := float64(used) / float64(max) * 100
		return fmt.Sprintf("Context: %d\u202f/\u202f%d (%.0f%%)", used, max, pct)
	}
	return fmt.Sprintf("Context: %d tokens", used)
}

// phaseLabels maps agentType → human-readable tab label.
var phaseLabels = map[string]string{
	"setup":          "Making Docker",
	"coder":          "Making Docker",
	"scanner":        "Testing Codebase",
	"binary-scanner": "Live Exploit",
	"auditor":        "Making Report",
	"strategist":     "Plan Hypothesis",
	"explorer":       "Explore Graph",
	"executor":       "Run PoC",
}

// App is the top-level GUI state container.
type App struct {
	fyneApp fyne.App
	window  fyne.Window
	tabs    *container.AppTabs
	mainTab *container.TabItem

	mainChat          *ChatPanel
	mainInput         *InputPanel
	statusLabel       *widget.Label // shows current run status / live tool timer
	usageLabel        *widget.Label // shows "Context: N / M (X%)"
	currentPhaseLabel *widget.Label // shows current orchestrator phase
	configDir         string        // config directory backing the Settings dialog

	mu            sync.Mutex
	phaseCounter  map[string]int // label → open count
	tabsByOrcID   map[string]*container.TabItem
	panelsByOrcID map[string]*ChatPanel

	onQuit func() // optional: called before Fyne quits (e.g. docker cleanup)

	rootAgent common.Orchestrator // stored so NotifyReportWritten can submit
	rescanBtn *widget.Button      // shown after report is written
}

// NewApp constructs the App struct (does not start Fyne yet).
func NewApp() *App {
	return &App{
		phaseCounter:  make(map[string]int),
		tabsByOrcID:   make(map[string]*container.TabItem),
		panelsByOrcID: make(map[string]*ChatPanel),
	}
}

// SetOnQuit registers a callback to be invoked (in a background goroutine)
// before the Fyne app exits. Use it for cleanup tasks like stopping containers.
func (a *App) SetOnQuit(fn func()) { a.onQuit = fn }

// SetConfigDir sets the config directory used by the Settings dialog.
// If empty, the dialog falls back to the default late config directory.
func (a *App) SetConfigDir(dir string) { a.configDir = dir }

// ConfirmMiddleware returns a ToolMiddleware that uses Fyne dialogs for
// tool-call confirmation. Safe to call before Run() — the window field
// is resolved lazily when a tool call executes.
func (a *App) ConfirmMiddleware(reg *common.ToolRegistry, unsupervised bool) common.ToolMiddleware {
	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			mw := GUIConfirmMiddleware(a.window, reg, unsupervised)
			return mw(next)(ctx, tc)
		}
	}
}

// buildMainLayout constructs the chat/input/tab widgets for rootAgent and
// starts the event loop. It does NOT call Show or Run — the caller does that.
// Must be called from the Fyne main goroutine (or before ShowAndRun).
func (a *App) buildMainLayout(rootAgent common.Orchestrator, hist []client.ChatMessage) {
	a.rootAgent = rootAgent
	a.mainChat = NewChatPanel()
	for _, msg := range hist {
		a.mainChat.AppendMessage(msg.Role, messageText(msg))
	}

	a.mainInput = NewInputPanel(func(text string) {
		a.mainChat.AppendMessage("user", text)
		a.mainInput.SetEnabled(false)
		if err := rootAgent.Submit(text); err != nil {
			a.mainInput.SetEnabled(true)
		}
	})

	statusLabel := widget.NewLabel("● Ready")
	a.statusLabel = statusLabel
	a.usageLabel = widget.NewLabel("Context: –")
	a.currentPhaseLabel = widget.NewLabel("Current Phase: STOP")

	// handleQuit cancels the agent, runs cleanup, then closes the window.
	// sync.Once ensures at most one execution even if button + OS close race.
	var quitOnce sync.Once
	var quitBtn *widget.Button
	handleQuit := func() {
		quitOnce.Do(func() {
			fyne.Do(func() {
				if quitBtn != nil {
					quitBtn.SetText("Stopping…")
					quitBtn.Disable()
				}
			})
			rootAgent.Cancel()

			// Run cleanup synchronously on background goroutine, then close window.
			// This ensures docker cleanup completes before the app exits.
			go func() {
				if a.onQuit != nil {
					a.onQuit() // Block until cleanup finishes
				}
				// Closing the window via fyne.Do ensures we're on the Fyne main
				// goroutine. By this point cleanup is complete and rootAgent.Cancel()
				// has stopped the run loop.
				fyne.Do(func() { a.window.Close() })
			}()
		})
	}

	// Intercept the OS close button so the same cleanup path is used.
	a.window.SetCloseIntercept(handleQuit)

	quitBtn = widget.NewButton("⏹ Stop & Quit", handleQuit)
	settingsBtn := widget.NewButton("Settings", func() {
		a.showSettingsDialog()
	})
	a.rescanBtn = widget.NewButton("🔄 Rescan", nil)
	a.rescanBtn.Hide()
	// Single top bar: controls on the sides, live status in the centre.
	topBar := container.NewBorder(
		nil, nil,
		container.NewHBox(quitBtn, a.rescanBtn),
		container.NewHBox(a.usageLabel, settingsBtn),
		container.NewHBox(statusLabel, widget.NewSeparator(), a.currentPhaseLabel),
	)

	mainContent := container.NewBorder(
		topBar,
		a.mainInput,
		nil, nil,
		a.mainChat,
	)
	a.mainTab = container.NewTabItem("Main", mainContent)
	a.tabs = container.NewAppTabs(a.mainTab)
	a.tabs.SetTabLocation(container.TabLocationTop)

	a.startEventLoop(rootAgent, a.mainChat, nil, "", func(used, max int) {
		a.usageLabel.SetText(formatContextUsage(used, max))
	})

	// Show an immediate baseline instead of the placeholder while waiting for
	// the first stream usage payload.
	initialUsed := common.CalculateHistoryTokens(rootAgent.History(), rootAgent.SystemPrompt(), rootAgent.ToolDefinitions())
	a.usageLabel.SetText(formatContextUsage(initialUsed, rootAgent.MaxTokens()))

	provider := newGUIInputProvider(a.window)
	ctx := rootAgent.Context()
	if ctx == nil {
		ctx = newContextWithProvider(provider)
	} else {
		ctx = withProvider(ctx, provider)
	}
	type contextSetter interface{ SetContext(context.Context) }
	if cs, ok := rootAgent.(contextSetter); ok {
		cs.SetContext(ctx)
	}
}

// Run wires up Fyne, renders the main window, and starts the event loop.
// This call blocks until the window is closed.
func (a *App) Run(
	rootAgent common.Orchestrator,
	hist []client.ChatMessage,
	sess *session.Session,
	unsupervised bool,
) {
	a.fyneApp = app.NewWithID("io.late")
	a.fyneApp.Settings().SetTheme(&lateTheme{})
	a.window = a.fyneApp.NewWindow("Late")
	a.window.SetIcon(appIcon)
	a.window.Resize(fyne.NewSize(1150, 750))

	a.buildMainLayout(rootAgent, hist)
	a.window.SetContent(a.tabs)
	a.window.ShowAndRun()
}

// openSubagentTab creates a new tab for a child orchestrator.
// Must be called from the Fyne main goroutine (via fyne.Do).
func (a *App) openSubagentTab(child common.Orchestrator, agentType string) {
	label := a.phaseLabel(agentType)

	panel := NewChatPanel()
	subUsage := widget.NewLabel("Context: –")

	stopFn := func() {
		child.Cancel()
	}
	content := makeTabContent(panel, stopFn, subUsage)

	tabItem := container.NewTabItem(label, content)

	a.mu.Lock()
	a.tabsByOrcID[child.ID()] = tabItem
	a.panelsByOrcID[child.ID()] = panel
	a.mu.Unlock()

	a.tabs.Append(tabItem)
	a.tabs.Select(tabItem) // auto-select so user sees the new work
	a.tabs.Refresh()

	// Start event loop for the child.
	a.startEventLoop(child, panel, tabItem, label, func(used, max int) {
		subUsage.SetText(formatSubagentContextUsage(used, max))
	})

	initialUsed := common.CalculateHistoryTokens(child.History(), child.SystemPrompt(), child.ToolDefinitions())
	subUsage.SetText(formatSubagentContextUsage(initialUsed, child.MaxTokens()))
}

// closeSubagentTab removes a subagent tab after showing a toast.
// Must be called from the Fyne main goroutine.
func (a *App) closeSubagentTab(tabItem *container.TabItem, o common.Orchestrator, label string) {
	a.sendNotification(label+" finished", "The subagent has completed its task.")

	a.mu.Lock()
	delete(a.tabsByOrcID, o.ID())
	delete(a.panelsByOrcID, o.ID())
	a.phaseCounter[label]--
	if a.phaseCounter[label] <= 0 {
		delete(a.phaseCounter, label)
	}
	a.mu.Unlock()

	a.tabs.Remove(tabItem)
	a.tabs.Select(a.mainTab)
	a.tabs.Refresh()
}

// phaseLabel returns a human-readable tab label with a counter suffix when
// more than one tab with the same base label is open simultaneously.
func (a *App) phaseLabel(agentType string) string {
	base, ok := phaseLabels[agentType]
	if !ok {
		base = agentType
	}
	a.mu.Lock()
	a.phaseCounter[base]++
	count := a.phaseCounter[base]
	a.mu.Unlock()
	if count == 1 {
		return base
	}
	return fmt.Sprintf("%s #%d", base, count)
}

// sendNotification fires an OS desktop notification.
func (a *App) sendNotification(title, body string) {
	a.fyneApp.SendNotification(&fyne.Notification{
		Title:   title,
		Content: body,
	})
}

// messageText extracts the string content from a ChatMessage.
func messageText(msg client.ChatMessage) string {
	return msg.Content
}

// NotifyReportWritten is called (from any goroutine) after write_sast_report
// successfully writes a report.
func (a *App) NotifyReportWritten(reportPath string) {
	fyne.Do(func() {
		if a.mainChat != nil {
			a.mainChat.AppendMessage("system", fmt.Sprintf("✓ Report written: %s", reportPath))
		}
		if a.rescanBtn != nil {
			a.rescanBtn.OnTapped = func() {
				a.rescanBtn.Disable()
				go func() {
					msg := fmt.Sprintf(
						"Rescan requested. Search your conversation history for the SETUP_COMPLETE block "+
							"and extract all fields (Container, Network, RepoPath, IndexPath, etc.). "+
							"Then spawn_subagent with agent_type=\"scanner\" using those fields as the goal — "+
							"do NOT re-run bootstrap_scan_toolchain or re-clone the repository. "+
							"The existing report is at: %s — load it, re-verify every finding, "+
							"scan for additional vulnerabilities, then write the merged report to the same path.",
						reportPath,
					)
					if a.rootAgent != nil {
						if err := a.rootAgent.Submit(msg); err != nil {
							fyne.Do(func() {
								a.rescanBtn.Enable()
								if a.mainChat != nil {
									a.mainChat.AppendMessage("system", fmt.Sprintf("✗ Rescan failed: %v", err))
								}
							})
						}
					}
				}()
			}
			a.rescanBtn.Show()
		}
	})
}
