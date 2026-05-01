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

// phaseLabels maps agentType → human-readable tab label.
var phaseLabels = map[string]string{
	"setup":          "Making Docker",
	"coder":          "Making Docker",
	"scanner":        "Testing Codebase",
	"binary-scanner": "Live Exploit",
	"auditor":        "Making Report",
}

// App is the top-level GUI state container.
type App struct {
	fyneApp fyne.App
	window  fyne.Window
	tabs    *container.AppTabs
	mainTab *container.TabItem

	mainChat   *ChatPanel
	mainInput  *InputPanel
	usageLabel *widget.Label // shows "Context: N / M (X%)"

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

// ConfirmMiddleware returns a ToolMiddleware that uses Fyne dialogs for
// tool-call confirmation. Safe to call before Run() — the window field
// is always populated by the time tool calls occur.
func (a *App) ConfirmMiddleware(reg *common.ToolRegistry, unsupervised bool) common.ToolMiddleware {
	return GUIConfirmMiddleware(a.window, reg, unsupervised)
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
		a.mainInput.SetEnabled(false)
		if err := rootAgent.Submit(text); err != nil {
			a.mainInput.SetEnabled(true)
		}
	})

	statusLabel := widget.NewLabel("● Ready")
	a.usageLabel = widget.NewLabel("Context: –")

	// handleQuit cancels the agent, runs cleanup, then closes the window.
	// sync.Once ensures at most one execution even if button + OS close race.
	var quitOnce sync.Once
	var quitBtn *widget.Button
	handleQuit := func() {
		quitOnce.Do(func() {
			fyne.Do(func() {
				quitBtn.SetText("Stopping…")
				quitBtn.Disable()
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

	bottomBar := container.NewVBox(
		a.mainInput,
		container.NewBorder(nil, nil, statusLabel, a.usageLabel, nil),
	)
	mainContent := container.NewBorder(
		container.NewHBox(quitBtn),
		bottomBar,
		nil, nil,
		a.mainChat,
	)
	a.mainTab = container.NewTabItem("Main", mainContent)
	a.tabs = container.NewAppTabs(a.mainTab)
	a.tabs.SetTabLocation(container.TabLocationTop)

	a.startEventLoop(rootAgent, a.mainChat, nil, "", func(used, max int) {
		var text string
		if max > 0 {
			pct := float64(used) / float64(max) * 100
			text = fmt.Sprintf("Context: %d\u202f/\u202f%d  (%.0f%%)", used, max, pct)
		} else {
			text = fmt.Sprintf("Context: %d tokens", used)
		}
		a.usageLabel.SetText(text)
	})

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
	subUsage := widget.NewLabel("–")

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
		if max > 0 {
			subUsage.SetText(fmt.Sprintf("%d\u202f/\u202f%d", used, max))
		} else {
			subUsage.SetText(fmt.Sprintf("%d tok", used))
		}
	})
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
