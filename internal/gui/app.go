package gui

import (
	"context"
	"fmt"
	"strings"
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
	usageLabel        *widget.Label // shows "Context: N / M (X%)"
	currentPhaseLabel *widget.Label // shows current orchestrator phase
	missionHypLabel   *widget.Label // blackboard: current hypothesis
	missionExecLabel  *widget.Label // blackboard: latest executor outcome
	missionConsLabel  *widget.Label // blackboard: active constraints
	configDir         string        // config directory backing the Settings dialog

	// Project Map tab — populated once get_architecture completes.
	projectMap    *ProjectMapPanel
	projectMapTab *container.TabItem

	mu            sync.Mutex
	phaseCounter  map[string]int // label → open count
	tabsByOrcID   map[string]*container.TabItem
	panelsByOrcID map[string]*ChatPanel

	onQuit func() // optional: called before Fyne quits (e.g. docker cleanup)
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
	a.usageLabel = widget.NewLabel("Context: –")
	a.currentPhaseLabel = widget.NewLabel("Current Phase: STOP")
	a.missionHypLabel = widget.NewLabel("Hypothesis: –")
	a.missionExecLabel = widget.NewLabel("Last Executor: –")
	a.missionConsLabel = widget.NewLabel("Constraints: –")
	a.missionHypLabel.Wrapping = fyne.TextWrapWord
	a.missionExecLabel.Wrapping = fyne.TextWrapWord
	a.missionConsLabel.Wrapping = fyne.TextWrapWord
	missionCard := widget.NewCard("Mission Snapshot", "Strategist loop state", container.NewVBox(
		a.missionHypLabel,
		a.missionExecLabel,
		a.missionConsLabel,
	))

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
			go func() {
				if a.onQuit != nil {
					a.onQuit()
				}
				// Closing the window via fyne.Do ensures we're on the Fyne main
				// goroutine. By this point rootAgent.Cancel() has stopped the
				// run loop so event-loop goroutines are idle — they won't call
				// fyne.Do after drained=true, which eliminates the thread warning.
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
	topBar := container.NewBorder(nil, nil, quitBtn, settingsBtn, nil)

	bottomBar := container.NewVBox(
		a.mainInput,
		missionCard,
		container.NewBorder(nil, nil, statusLabel, a.usageLabel, a.currentPhaseLabel),
	)
	mainContent := container.NewBorder(
		topBar,
		bottomBar,
		nil, nil,
		a.mainChat,
	)
	a.mainTab = container.NewTabItem("Main", mainContent)

	// Project Map tab — initially shows "waiting" placeholder; populated once
	// get_architecture completes and ProjectMapLoadedEvent is received.
	a.projectMap = NewProjectMapPanel()
	a.projectMapTab = container.NewTabItem("Project Map", container.NewPadded(a.projectMap))

	a.tabs = container.NewAppTabs(a.mainTab, a.projectMapTab)
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

// SetArchitecture loads architecture data into the Project Map tab.
// Safe to call from any goroutine — marshals onto the Fyne main goroutine.
func (a *App) SetArchitecture(data common.ArchitectureData) {
	if a.projectMap == nil {
		return
	}
	a.projectMap.Load(data)
}

// HighlightNode signals the Project Map to highlight the cluster that owns
// filePath. Safe to call from any goroutine.
func (a *App) HighlightNode(filePath string, isHotspot bool) {
	if a.projectMap == nil {
		return
	}
	a.projectMap.HighlightFile(filePath, isHotspot)
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

func (a *App) updateMissionSnapshot(e common.MissionSnapshotEvent) {
	if a.missionHypLabel == nil || a.missionExecLabel == nil || a.missionConsLabel == nil {
		return
	}

	h := strings.TrimSpace(e.CurrentHypothesis)
	if h == "" {
		h = "-"
	}
	a.missionHypLabel.SetText("Hypothesis: " + h)

	outcome := strings.TrimSpace(e.LastExecutorOutcome)
	if outcome == "" {
		outcome = "-"
	}
	reason := strings.TrimSpace(e.LastExecutorReason)
	if reason != "" {
		a.missionExecLabel.SetText("Last Executor: " + outcome + " (" + reason + ")")
	} else {
		a.missionExecLabel.SetText("Last Executor: " + outcome)
	}

	if len(e.ActiveConstraints) == 0 {
		a.missionConsLabel.SetText("Constraints: -")
		return
	}
	a.missionConsLabel.SetText("Constraints: " + strings.Join(e.ActiveConstraints, " | "))
}
