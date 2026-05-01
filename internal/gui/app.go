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

	mainChat  *ChatPanel
	mainInput *InputPanel

	mu            sync.Mutex
	phaseCounter  map[string]int // label → open count
	tabsByOrcID   map[string]*container.TabItem
	panelsByOrcID map[string]*ChatPanel
}

// NewApp constructs the App struct (does not start Fyne yet).
func NewApp() *App {
	return &App{
		phaseCounter:  make(map[string]int),
		tabsByOrcID:   make(map[string]*container.TabItem),
		panelsByOrcID: make(map[string]*ChatPanel),
	}
}

// ConfirmMiddleware returns a ToolMiddleware that uses Fyne dialogs for
// tool-call confirmation. Safe to call before Run() — the window field
// is always populated by the time tool calls occur.
func (a *App) ConfirmMiddleware(reg *common.ToolRegistry, unsupervised bool) common.ToolMiddleware {
	return GUIConfirmMiddleware(a.window, reg, unsupervised)
}

// Run wires up Fyne, renders the main window, and starts the event loop.
// This call blocks until the window is closed.
func (a *App) Run(
	rootAgent common.Orchestrator,
	hist []client.ChatMessage,
	sess *session.Session,
	unsupervised bool,
) {
	a.fyneApp = app.New()
	a.fyneApp.Settings().SetTheme(&lateTheme{})

	a.window = a.fyneApp.NewWindow("Late")
	a.window.Resize(fyne.NewSize(1150, 750))

	// --- Main chat panel ---
	a.mainChat = NewChatPanel()

	// Replay existing history.
	for _, msg := range hist {
		a.mainChat.AppendMessage(msg.Role, messageText(msg))
	}

	// --- Input panel ---
	a.mainInput = NewInputPanel(func(text string) {
		a.mainInput.SetEnabled(false)
		if err := rootAgent.Submit(text); err != nil {
			a.mainInput.SetEnabled(true)
		}
	})

	// --- Status label ---
	statusLabel := widget.NewLabel("● Ready")

	// --- Main tab ---
	mainContent := container.NewBorder(
		nil,
		container.NewVBox(a.mainInput, statusLabel),
		nil, nil,
		a.mainChat,
	)
	a.mainTab = container.NewTabItem("Main", mainContent)
	a.tabs = container.NewAppTabs(a.mainTab)
	a.tabs.SetTabLocation(container.TabLocationTop)

	// --- Root event loop ---
	a.startEventLoop(rootAgent, a.mainChat, nil, "")

	// Wire InputProvider into root agent's context.
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

	a.window.SetContent(a.tabs)
	a.window.ShowAndRun()
}

// openSubagentTab creates a new tab for a child orchestrator.
// Must be called from the Fyne main goroutine (via fyne.Do).
func (a *App) openSubagentTab(child common.Orchestrator, agentType string) {
	label := a.phaseLabel(agentType)

	panel := NewChatPanel()

	stopFn := func() {
		child.Cancel()
	}
	content := makeTabContent(panel, stopFn)

	tabItem := container.NewTabItem(label, content)

	a.mu.Lock()
	a.tabsByOrcID[child.ID()] = tabItem
	a.panelsByOrcID[child.ID()] = panel
	a.mu.Unlock()

	a.tabs.Append(tabItem)
	a.tabs.Select(tabItem) // auto-select so user sees the new work
	a.tabs.Refresh()

	// Start event loop for the child.
	a.startEventLoop(child, panel, tabItem, label)
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
