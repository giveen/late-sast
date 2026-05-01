═══════════════════════════════════════════════════════════════════════════════
 PORTING PLAN: Add a Fyne v2 GUI with per-subagent tabs to a Go TUI agent app
 (Updated with all implementation changes from the late-sast codebase)
═══════════════════════════════════════════════════════════════════════════════

ASSUMPTIONS ABOUT THE SOURCE PROJECT
──────────────────────────────────────
- Go module with a root orchestrator type (BaseOrchestrator) that emits events
  on a channel: ContentEvent, StatusEvent, ChildAddedEvent
- ContentEvent carries Content, ReasoningContent, and Usage fields
- A common.Orchestrator interface shared between orchestrator and agent packages
- A TUI (Bubble Tea) already exists and must be preserved as a --tui fallback
- Subagents are spawned via agent.NewSubagentOrchestrator(...)
- Tool confirmation is handled by middleware (common.ToolMiddleware)
- The agent package imports the tui package → circular import risk

═══════════════════════════════════════════════════════════════════════════════
PHASE 1: DEPENDENCY SETUP
═══════════════════════════════════════════════════════════════════════════════

Step 1.1 — Create a feature branch
────────────────────────────────────
  git checkout -b gui-feature

Step 1.2 — Add Fyne v2 and goldmark
────────────────────────────────────
  go get fyne.io/fyne/v2@latest
  go get github.com/yuin/goldmark@latest
  go mod tidy

  # On Linux, Fyne needs CGO + X11/OpenGL dev libraries:
  sudo apt-get install -y \
    libgl1-mesa-dev \
    libx11-dev \
    libxrandr-dev \
    libxinerama-dev \
    libxcursor-dev \
    libxi-dev \
    libxxf86vm-dev   # <-- commonly missing, causes linker error

  go build ./... 2>&1

Step 1.3 — Fix LANG locale before Fyne initialises (cmd/main.go)
──────────────────────────────────────────────────────────────────
  // Add at the TOP of main(), before any flag.Parse or Fyne calls:
  if lc := os.Getenv("LANG"); lc == "" || lc == "C" || lc == "POSIX" {
      os.Setenv("LANG", "en_US.UTF-8")
  }

  WHY: Fyne's locale parser calls golang.org/x/text/language.Parse on $LANG.
  "C" and "POSIX" are not valid BCP-47 tags and cause a logged Fyne error on
  every startup:  "Fyne error: Error parsing user locale C"

═══════════════════════════════════════════════════════════════════════════════
PHASE 2: BREAK THE CIRCULAR IMPORT
═══════════════════════════════════════════════════════════════════════════════

PROBLEM: agent.NewSubagentOrchestrator accepted a tui.Messenger parameter,
so internal/agent imported internal/tui. Adding internal/gui importing
internal/agent would create a fragile dep graph.

SOLUTION: Replace the concrete tui.Messenger parameter with a generic factory
function type defined in the agent package itself.

Step 2.1 — Add MiddlewareFactory type to internal/agent/agent.go
──────────────────────────────────────────────────────────────────
  type MiddlewareFactory func(registry *common.ToolRegistry) []common.ToolMiddleware

Step 2.2 — Change NewSubagentOrchestrator signature
─────────────────────────────────────────────────────
  // OLD:
  func NewSubagentOrchestrator(..., parent common.Orchestrator, messenger tui.Messenger) (...)

  // NEW:
  func NewSubagentOrchestrator(..., parent common.Orchestrator, middlewareFactory MiddlewareFactory) (...)

Step 2.3 — Update the body to use the factory
───────────────────────────────────────────────
  if middlewareFactory != nil {
      mws = middlewareFactory(sess.Registry)
  }

Step 2.4 — Remove the tui import from agent.go
────────────────────────────────────────────────
  // Delete: "late/internal/tui" from the import block

Step 2.5 — Update ALL callers (TUI path):
──────────────────────────────────────────
  child, err := agent.NewSubagentOrchestrator(
      client, goal, ctxFiles, agentType,
      enabledTools, injectCWD, gemmaThinking, maxTurns,
      rootAgent,
      func(reg *common.ToolRegistry) []common.ToolMiddleware {
          return []common.ToolMiddleware{tui.TUIConfirmMiddleware(p, reg)}
      },
  )

═══════════════════════════════════════════════════════════════════════════════
PHASE 3: EXTEND THE SHARED INTERFACES
═══════════════════════════════════════════════════════════════════════════════

Step 3.1 — Add AgentType to ChildAddedEvent (internal/common/interfaces.go)
─────────────────────────────────────────────────────────────────────────────
  type ChildAddedEvent struct {
      ParentID  string
      Child     Orchestrator
      AgentType string   // e.g. "scanner", "auditor", "coder"
  }

Step 3.2 — Add Usage to ContentEvent (internal/common/interfaces.go)
──────────────────────────────────────────────────────────────────────
  type ContentEvent struct {
      ID               string
      Content          string
      ReasoningContent string     // model's chain-of-thought / thinking text
      ToolCalls        []client.ToolCall
      Usage            client.Usage   // PromptTokens, CompletionTokens, TotalTokens
  }

  WHY: The GUI needs to display a context window usage bar. The orchestrator's
  onEndTurn hook emits a ContentEvent with empty Content/ReasoningContent but
  populated Usage. Handle this as a usage-only event in the event loop.

Step 3.3 — Update AddChild in internal/orchestrator/base.go
─────────────────────────────────────────────────────────────
  func (o *BaseOrchestrator) AddChild(child common.Orchestrator, agentType string) {
      o.eventCh <- common.ChildAddedEvent{
          ParentID:  o.id,
          Child:     child,
          AgentType: agentType,
      }
  }

Step 3.4 — Update the call in agent.go
────────────────────────────────────────
  p.AddChild(child, agentType)   // agentType is the string passed to NewSubagentOrchestrator

═══════════════════════════════════════════════════════════════════════════════
PHASE 4: BUILD THE GUI PACKAGE (internal/gui/)
═══════════════════════════════════════════════════════════════════════════════

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/theme.go
─────────────────────────────────────────────────────────────────────────────
  type lateTheme struct{}

  // Implement fyne.Theme interface:
  func (t *lateTheme) Color(name fyne.ThemeColorName, v fyne.ThemeVariant) color.Color
  func (t *lateTheme) Font(style fyne.TextStyle) fyne.Resource   // → theme.DefaultTheme().Font(...)
  func (t *lateTheme) Icon(name fyne.ThemeIconName) fyne.Resource // → theme.DefaultTheme().Icon(...)
  func (t *lateTheme) Size(name fyne.ThemeSizeName) float32       // → theme.DefaultTheme().Size(...)

  var (
      colorBg       = color.NRGBA{R: 0x19, G: 0x19, B: 0x19, A: 0xFF}  // #191919
      colorSurface  = color.NRGBA{R: 0x24, G: 0x24, B: 0x24, A: 0xFF}  // #242424
      colorAmethyst = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0xFF}  // #9B59B6
      colorText     = color.NRGBA{R: 0xEC, G: 0xF0, B: 0xF1, A: 0xFF}  // #ECF0F1
      colorSubtext  = color.NRGBA{R: 0xBD, G: 0xC3, B: 0xC7, A: 0xFF}  // #BDC3C7
      colorGreen    = color.NRGBA{R: 0x2E, G: 0xCC, B: 0x71, A: 0xFF}  // #2ECC71
      colorOrange   = color.NRGBA{R: 0xE6, G: 0x7E, B: 0x22, A: 0xFF}  // #E67E22
      colorUserBg   = color.NRGBA{R: 0x2C, G: 0x1A, B: 0x3E, A: 0xFF}  // user bubble
      colorHover    = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0x40}
      colorFocus    = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0x80}
  )

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/markdown.go
─────────────────────────────────────────────────────────────────────────────
  func parseMarkdown(src string) []widget.RichTextSegment

  AST NODE MAPPING:
    *ast.Text         → widget.TextSegment with current style
    *ast.Heading      → amethyst+bold TextSegment; newline on exit
    *ast.Emphasis     → Level==1: italic; Level==2: bold
                        NOTE: goldmark has NO ast.Strong — bold is Emphasis.Level==2
    *ast.CodeSpan     → mono=true (green colour)
    *ast.FencedCodeBlock / *ast.CodeBlock → widget.RichTextStyleCodeBlock segment
    *ast.List         → track listDepth; toggle listOrdered
    *ast.ListItem     → prepend "• " or "N. "
    *ast.Paragraph    → append newline on exit
    *ast.ThematicBreak → widget.SeparatorSegment{}
    *ast.Link         → render as plain text (fyne.URI ≠ *url.URL)
    *ast.Blockquote   → toggle italic

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/chat.go  (UPDATED — includes thinking bubble)
─────────────────────────────────────────────────────────────────────────────
  KEY TYPES:

  type messageBubble struct {
      role    string  // "user" | "assistant" | "error"
      content string
      rich    *widget.RichText
  }

  // thinkBubble is a collapsible accordion that streams reasoning content.
  // Only ONE is created per ChatPanel; StartThinking reuses it on subsequent turns.
  type thinkBubble struct {
      accordion *widget.Accordion
      item      *widget.AccordionItem
      rich      *widget.RichText
  }

  type ChatPanel struct {
      widget.BaseWidget
      scroll    *container.Scroll
      vbox      *fyne.Container
      messages  []*messageBubble
      lastThink *thinkBubble  // currently active (or most recent) thinking bubble
  }

  METHODS:
  func NewChatPanel() *ChatPanel
  func (p) CreateRenderer() fyne.WidgetRenderer          // NewSimpleRenderer(p.scroll)
  func (p) AppendMessage(role, content string)           // add bubble, scroll to bottom
  func (p) UpdateLastMessage(content string)             // replace last bubble (plain, streaming)
  func (p) FinalizeLastMessage()                         // re-render with Markdown on idle

  // Thinking accordion — call from Fyne main goroutine:
  func (p) StartThinking()
      // First call: creates accordion, adds to vbox, opens it (expanded).
      // Subsequent calls: reopens and clears the SAME accordion. Never creates a second one.
      // Title: "Thinking…"
      // Visual: dim purple (#6C3D80) 3px left accent stripe.

  func (p) UpdateThinking(content string)
      // Streams new accumulated reasoning text into the open accordion.
      // Uses plain TextSegment (no Markdown) to avoid parse artefacts mid-stream.

  func (p) FinalizeThinking()
      // Collapses the accordion and renames it "Thoughts".
      // User can still click to expand and read the full reasoning.

  BUBBLE LAYOUT:
  - User: right-aligned container, colorUserBg background rectangle, 80px left spacer
  - Assistant: left-aligned with 3px colorAmethyst accent line

  THREAD SAFETY: ALL methods must be called from the Fyne main goroutine.
  Use fyne.Do(func(){ panel.AppendMessage(...) }) from goroutines.

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/input.go
─────────────────────────────────────────────────────────────────────────────
  type InputPanel struct { widget.BaseWidget; ... }
  func NewInputPanel(onSend func(string)) *InputPanel
  func (p) SetEnabled(bool)

  entry.OnSubmitted = func(s string) { send(s) }
  btn.OnTapped      = func()         { send(entry.Text) }

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/provider.go
─────────────────────────────────────────────────────────────────────────────
  type GUIInputProvider struct { win fyne.Window }

  func (p *GUIInputProvider) GetInput(ctx context.Context, prompt string, schema json.RawMessage) (json.RawMessage, error) {
      resultCh := make(chan json.RawMessage, 1)
      fyne.Do(func() {
          // Build form dialog from JSON schema; on OK marshal → resultCh
          // On Cancel: close(resultCh)
      })
      select {
      case res := <-resultCh:
          if res == nil { return nil, context.Canceled }
          return res, nil
      case <-ctx.Done():
          return nil, ctx.Err()
      }
  }

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/confirm.go
─────────────────────────────────────────────────────────────────────────────
  func GUIConfirmMiddleware(win fyne.Window, reg *common.ToolRegistry, unsupervised bool) common.ToolMiddleware

  LOGIC: mirrors TUI confirm exactly.
  Uses a channel + fyne.Do to bridge goroutine → Fyne main goroutine:
    resultCh := make(chan string, 1)
    fyne.Do(func() { /* show dialog; each button: resultCh <- "y"/"s"/"p"/"g"/"n" */ })
    choice := <-resultCh

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/events.go  (UPDATED)
─────────────────────────────────────────────────────────────────────────────
  // Signature — note the 5th onUsage parameter:
  func (a *App) startEventLoop(
      o          common.Orchestrator,
      panel      *ChatPanel,
      tabItem    *container.TabItem,      // nil for root/main tab
      agentLabel string,
      onUsage    func(used, max int),     // nil to skip; called with token counts
  )

  GOROUTINE LOCAL STATE:
    var acc string
    streaming         := false
    thinkingStreaming  := false

  EVENT HANDLING — ContentEvent:

    // Usage-only event (onEndTurn): Content=="" && ReasoningContent==""
    if e.Content == "" && e.ReasoningContent == "" {
        if e.Usage.PromptTokens > 0 && onUsage != nil {
            used, max := e.Usage.PromptTokens, o.MaxTokens()
            fyne.Do(func() { onUsage(used, max) })
        }
        continue   // <-- MUST continue; do not add an empty bubble
    }

    // Reasoning/thinking chunk:
    if e.ReasoningContent != "" {
        if !thinkingStreaming {
            thinkingStreaming = true
            fyne.Do(func() { panel.StartThinking() })
        }
        rc := e.ReasoningContent   // local copy — fyne.Do is ASYNC
        fyne.Do(func() { panel.UpdateThinking(rc) })
    }

    // Response chunk — collapse thinking when first content arrives:
    if e.Content != "" {
        if thinkingStreaming {
            thinkingStreaming = false
            fyne.Do(func() { panel.FinalizeThinking() })
        }
        if !streaming {
            streaming = true
            acc = ""
            fyne.Do(func() { panel.AppendMessage("assistant", "") })
        }
        acc = e.Content
        content := acc   // ← LOCAL COPY — fyne.Do is async; acc may change before callback runs
        fyne.Do(func() { panel.UpdateLastMessage(content) })
        if e.Usage.PromptTokens > 0 && onUsage != nil {
            used, max := e.Usage.PromptTokens, o.MaxTokens()
            fyne.Do(func() { onUsage(used, max) })
        }
    }

  EVENT HANDLING — StatusEvent:

    "thinking":
        // Collapse thinking box between tool calls; StartThinking will reopen
        // the SAME accordion (not create a new one) when reasoning resumes.
        if thinkingStreaming {
            thinkingStreaming = false
            fyne.Do(func() { panel.FinalizeThinking() })
        }
        streaming = false
        acc = ""

    "idle":
        if thinkingStreaming { thinkingStreaming=false; fyne.Do(panel.FinalizeThinking) }
        if streaming         { streaming=false;         fyne.Do(panel.FinalizeLastMessage) }
        // re-enable input panel

    "closed":
        if thinkingStreaming { fyne.Do(panel.FinalizeThinking) }
        if streaming         { fyne.Do(panel.FinalizeLastMessage) }
        if tabItem != nil    { fyne.Do(a.closeSubagentTab(tabItem, o, agentLabel)) }
        return   // exit goroutine

    "error":
        fyne.Do(panel.AppendMessage("error", "⚠ "+msg))

  EVENT HANDLING — ChildAddedEvent:
    child := e.Child; agentType := e.AgentType
    fyne.Do(func() { a.openSubagentTab(child, agentType) })

  SUBAGENT TAB CONTENT:
  func makeTabContent(panel *ChatPanel, stopFn func(), usageLabel *widget.Label) fyne.CanvasObject {
      stopBtn := widget.NewButton("■ Stop", stopFn)
      header  := container.NewBorder(nil, nil, stopBtn, usageLabel, nil)
      return container.NewBorder(header, nil, nil, nil, panel)
  }
  // usageLabel shows "N / M" token counts for the subagent tab header.

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/app.go  (UPDATED)
─────────────────────────────────────────────────────────────────────────────
  type App struct {
      fyneApp fyne.App
      window  fyne.Window
      tabs    *container.AppTabs
      mainTab *container.TabItem

      mainChat   *ChatPanel
      mainInput  *InputPanel
      usageLabel *widget.Label   // "Context: N / M (X%)" in the bottom status bar

      mu            sync.Mutex
      phaseCounter  map[string]int
      tabsByOrcID   map[string]*container.TabItem
      panelsByOrcID map[string]*ChatPanel

      onQuit func()  // called in a background goroutine before Fyne quits
  }

  func (a *App) SetOnQuit(fn func()) { a.onQuit = fn }

  // buildMainLayout — EXTRACTED from Run() so sast_picker.go can call it
  // after the picker screen transitions to the scan screen.
  // Must be called from the Fyne main goroutine (or via fyne.Do).
  func (a *App) buildMainLayout(rootAgent common.Orchestrator, hist []client.ChatMessage) {
      a.mainChat = NewChatPanel()
      // replay history...

      a.mainInput = NewInputPanel(func(text string) {
          a.mainInput.SetEnabled(false)
          rootAgent.Submit(text)
      })

      statusLabel := widget.NewLabel("● Ready")
      a.usageLabel  = widget.NewLabel("Context: –")

      // ── Stop & Quit button ───────────────────────────────────────────────
      // Declared as var first so handleQuit closure can reference it.
      var quitBtn *widget.Button
      var quitOnce sync.Once

      handleQuit := func() {
          quitOnce.Do(func() {
              // Immediate visual feedback — button changes text and disables
              // so the user knows it's working even if cleanup takes time.
              fyne.Do(func() {
                  quitBtn.SetText("Stopping…")
                  quitBtn.Disable()
              })
              rootAgent.Cancel()
              go func() {
                  if a.onQuit != nil { a.onQuit() }
                  // fyne.Do here is safe because rootAgent.Cancel() above has
                  // already stopped event-loop goroutines. By the time the
                  // window closes (drained=true), no goroutine is calling fyne.Do.
                  fyne.Do(func() { a.window.Close() })
              }()
          })
      }

      // Intercept OS window-close button — same path as the UI button.
      a.window.SetCloseIntercept(handleQuit)

      quitBtn = widget.NewButton("⏹ Stop & Quit", handleQuit)
      // quitBtn position: top-right of the main tab content area.

      bottomBar := container.NewVBox(
          a.mainInput,
          container.NewBorder(nil, nil, statusLabel, a.usageLabel, nil),
      )
      mainContent := container.NewBorder(
          container.NewBorder(nil, nil, nil, quitBtn, nil),  // quit button top-right
          bottomBar,
          nil, nil,
          a.mainChat,
      )

      a.mainTab = container.NewTabItem("Main", mainContent)
      a.tabs    = container.NewAppTabs(a.mainTab)
      a.tabs.SetTabLocation(container.TabLocationTop)

      // Start event loop with usage callback for the bottom bar:
      a.startEventLoop(rootAgent, a.mainChat, nil, "", func(used, max int) {
          var text string
          if max > 0 {
              pct  := float64(used) / float64(max) * 100
              text  = fmt.Sprintf("Context: %d\u202f/\u202f%d  (%.0f%%)", used, max, pct)
          } else {
              text = fmt.Sprintf("Context: %d tokens", used)
          }
          a.usageLabel.SetText(text)
      })

      // Wire InputProvider:
      provider := newGUIInputProvider(a.window)
      ctx := rootAgent.Context()
      if ctx == nil { ctx = newContextWithProvider(provider) } else { ctx = withProvider(ctx, provider) }
      type contextSetter interface{ SetContext(context.Context) }
      if cs, ok := rootAgent.(contextSetter); ok { cs.SetContext(ctx) }
  }

  func (a *App) Run(rootAgent, hist, sess, unsupervised) {
      a.fyneApp = app.NewWithID("io.late")   // ← NewWithID, not New()
      a.fyneApp.Settings().SetTheme(&lateTheme{})
      a.window = a.fyneApp.NewWindow("Late")
      a.window.Resize(fyne.NewSize(1150, 750))
      a.buildMainLayout(rootAgent, hist)
      a.window.SetContent(a.tabs)
      a.window.ShowAndRun()
  }

  // openSubagentTab — creates tab with Stop button + usage label in header:
  func (a *App) openSubagentTab(child common.Orchestrator, agentType string) {
      label    := a.phaseLabel(agentType)
      panel    := NewChatPanel()
      subUsage := widget.NewLabel("–")
      stopFn   := func() { child.Cancel() }
      content  := makeTabContent(panel, stopFn, subUsage)
      tabItem  := container.NewTabItem(label, content)

      a.mu.Lock()
      a.tabsByOrcID[child.ID()]   = tabItem
      a.panelsByOrcID[child.ID()] = panel
      a.mu.Unlock()

      a.tabs.Append(tabItem)
      a.tabs.Select(tabItem)
      a.tabs.Refresh()

      a.startEventLoop(child, panel, tabItem, label, func(used, max int) {
          if max > 0 {
              subUsage.SetText(fmt.Sprintf("%d\u202f/\u202f%d", used, max))
          } else {
              subUsage.SetText(fmt.Sprintf("%d tok", used))
          }
      })
  }

  var phaseLabels = map[string]string{
      "setup":          "Making Docker",
      "coder":          "Making Docker",
      "scanner":        "Testing Codebase",
      "binary-scanner": "Live Exploit",
      "auditor":        "Making Report",
  }

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/sast_picker.go  (NEW — SAST-specific only)
─────────────────────────────────────────────────────────────────────────────
  // Only needed for binaries that present a target-selection screen before
  // building the orchestrator (e.g., a dedicated SAST scanner binary).
  // General-purpose agents that always know their target can skip this file.

  type SASTPickerResult struct {
      URL       string   // GitHub URL  (empty when LocalPath is set)
      LocalPath string   // local dir   (empty when URL is set)
      OutputDir string   // report output directory; empty = cwd
  }

  // RunSAST shows either the picker screen or a "Starting…" screen,
  // then calls setupFn in a background goroutine to build the orchestrator.
  // setupFn returns (orchestrator, initialMessage).
  //
  // If knownTarget or knownLocalPath is non-empty, the picker is skipped.
  func (a *App) RunSAST(
      knownTarget, knownLocalPath, knownOutputDir string,
      setupFn func(SASTPickerResult) (common.Orchestrator, string),
  ) {
      a.fyneApp = fyneapp.NewWithID("io.late.sast")   // unique ID required
      a.fyneApp.Settings().SetTheme(&lateTheme{})
      a.window = a.fyneApp.NewWindow("Late SAST")

      transition := func(res SASTPickerResult) {
          rootAgent, initialMsg := setupFn(res)   // blocking; runs in goroutine
          fyne.Do(func() {
              a.window.Resize(fyne.NewSize(1150, 750))
              a.buildMainLayout(rootAgent, nil)
              a.window.SetContent(a.tabs)
          })
          if initialMsg != "" {
              go func() {
                  time.Sleep(300 * time.Millisecond)
                  rootAgent.Submit(initialMsg)
              }()
          }
      }

      if knownTarget != "" || knownLocalPath != "" {
          // CLI flags supplied — skip picker
          a.window.Resize(fyne.NewSize(1150, 750))
          a.window.SetContent(container.NewCenter(widget.NewLabel("Starting scan…")))
          go transition(SASTPickerResult{URL: knownTarget, LocalPath: knownLocalPath, OutputDir: knownOutputDir})
      } else {
          // No flags — show interactive picker
          a.window.Resize(fyne.NewSize(700, 460))
          a.window.SetContent(a.buildPickerContent(
              func(res SASTPickerResult) {
                  fyne.Do(func() {
                      a.window.SetContent(container.NewCenter(widget.NewLabel("Setting up scan…")))
                  })
                  go transition(res)
              },
              knownOutputDir,
          ))
      }
      a.window.ShowAndRun()
  }

  // buildPickerContent returns a form with:
  //   - GitHub URL entry field
  //   - Local path entry + Browse… folder dialog button
  //   - Output directory entry + Browse… folder dialog button
  //   - Error label (hidden until validation fails)
  //   - "Start Scan" button (HighImportance styling)
  func (a *App) buildPickerContent(onStart func(SASTPickerResult), defaultOutputDir string) fyne.CanvasObject

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/context.go
─────────────────────────────────────────────────────────────────────────────
  func newContextWithProvider(p InputProvider) context.Context
  func withProvider(ctx context.Context, p InputProvider) context.Context

─────────────────────────────────────────────────────────────────────────────
File: internal/gui/sessions.go
─────────────────────────────────────────────────────────────────────────────
  func (a *App) ShowSessionBrowser(onLoad func(histPath string))

═══════════════════════════════════════════════════════════════════════════════
PHASE 5: UPDATE THE ENTRY POINT (cmd/<sast-binary>/main.go)
═══════════════════════════════════════════════════════════════════════════════

Step 5.1 — Normalize LANG (top of main(), before everything)
──────────────────────────────────────────────────────────────
  if lc := os.Getenv("LANG"); lc == "" || lc == "C" || lc == "POSIX" {
      os.Setenv("LANG", "en_US.UTF-8")
  }

Step 5.2 — Add --tui flag
──────────────────────────
  useTUIReq := flag.Bool("tui", false, "Use terminal UI instead of graphical")

Step 5.3 — Extract buildScan closure
──────────────────────────────────────
  // buildScan captures all session/tool setup that is identical between
  // TUI and GUI paths, and is also called from the GUI setupFn.
  //
  // Return a concrete struct (not common.Orchestrator interface) so that
  // SetContext / SetMiddlewares are accessible without type assertions.
  type sessionResult struct {
      sess       *session.Session
      rootAgent  *orchestrator.BaseOrchestrator   // concrete type, NOT interface
      initialMsg string
  }

  buildScan := func(target, localPath, outputDir string) sessionResult {
      // ... all existing setup: docker, session, tool registration, etc.
      rootAgent := orchestrator.NewBaseOrchestrator("main", sess, nil, 0)
      return sessionResult{sess: sess, rootAgent: rootAgent, initialMsg: initialMessage}
  }

  // WHY concrete type: rootAgent.SetContext() and rootAgent.SetMiddlewares()
  // are methods on *BaseOrchestrator, not on the common.Orchestrator interface.
  // Returning the interface loses access to them without fragile type assertions.

Step 5.4 — Branch on --tui
───────────────────────────
  if *useTUIReq {
      sr := buildScan(target, localPath, outputDir)
      sess, rootAgent, initialMessage := sr.sess, sr.rootAgent, sr.initialMsg

      // ... existing TUI setup unchanged ...
      // Pass TUI middleware factory to subagent spawner:
      sess.Registry.Register(tool.SpawnSubagentTool{
          Runner: func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
              child, err := agent.NewSubagentOrchestrator(
                  ..., rootAgent,
                  func(reg *common.ToolRegistry) []common.ToolMiddleware {
                      return []common.ToolMiddleware{tui.TUIConfirmMiddleware(p, reg)}
                  },
              )
              ...
          },
      })
      p.Run()
  } else {
      guiApp := gui.NewApp()
      guiApp.SetOnQuit(cleanupContainer)   // cleanup hook (docker, etc.)

      setupFn := func(res gui.SASTPickerResult) (common.Orchestrator, string) {
          sr := buildScan(res.URL, res.LocalPath, res.OutputDir)
          sess, rootAgent := sr.sess, sr.rootAgent

          baseCtx := context.WithValue(context.Background(), common.SkipConfirmationKey, true)
          baseCtx  = context.WithValue(baseCtx, common.ToolApprovalKey, true)
          rootAgent.SetContext(baseCtx)
          rootAgent.SetMiddlewares([]common.ToolMiddleware{
              guiApp.ConfirmMiddleware(sess.Registry, true),
          })

          sess.Registry.Register(tool.SpawnSubagentTool{
              Runner: func(ctx context.Context, goal string, ctxFiles []string, agentType string) (string, error) {
                  child, err := agent.NewSubagentOrchestrator(
                      ..., rootAgent,
                      func(reg *common.ToolRegistry) []common.ToolMiddleware {
                          return []common.ToolMiddleware{guiApp.ConfirmMiddleware(reg, true)}
                      },
                  )
                  ...
                  return fmt.Sprintf("Subagent completed. Result:\n\n%s", res), nil
              },
          })

          return rootAgent, sr.initialMsg
      }

      guiApp.RunSAST(target, localPath, outputDir, setupFn)
  }

═══════════════════════════════════════════════════════════════════════════════
PHASE 6: MAKEFILE
═══════════════════════════════════════════════════════════════════════════════

  BINARY_NAME=late-sast
  VERSION?=v1.x.y.z

  # fetch-cbm: skip download if binary already exists (avoids hanging on make install)
  fetch-cbm:
      @if [ -f "$(CBM_EMBED_PATH)" ]; then \
          echo "Fetched: $(CBM_EMBED_PATH) (cached)"; \
      else \
          # ... curl/tar download ... \
      fi

  # Two separate output names — NEVER share bin/${BINARY_NAME} between targets
  # that build different source packages, or install-X will clobber the other binary.
  build: fetch-cbm                     # → bin/late-sast  (./cmd/late-sast, -tags cbm_embedded)
  build-late:                          # → bin/late        (./cmd/late, no cbm tag)

  install: build build-late            # installs BOTH:
      cp bin/${BINARY_NAME} ~/.local/bin/${BINARY_NAME}
      cp bin/late ~/.local/bin/late

  # Atomic replace when the binary is already running ("text file busy"):
  # cp bin/late-sast ~/.local/bin/late-sast.new && mv ~/.local/bin/late-sast.new ~/.local/bin/late-sast

═══════════════════════════════════════════════════════════════════════════════
PHASE 7: COMMON GOTCHAS & FIXES
═══════════════════════════════════════════════════════════════════════════════

GOTCHA 1 — fyne.Do() is ASYNC, not SYNC
──────────────────────────────────────────
  fyne.Do(fn) queues fn on the Fyne event loop and returns immediately.
  By the time fn runs, local variables in the calling goroutine may have changed.

  WRONG (data race on acc):
    fyne.Do(func() { panel.UpdateLastMessage(acc) })

  CORRECT (capture a local copy before the call):
    content := acc
    fyne.Do(func() { panel.UpdateLastMessage(content) })

  Use fyne.DoAndWait(fn) if you need to block until fn completes.

GOTCHA 2 — Fyne thread warnings after window close
────────────────────────────────────────────────────
  Symptom: "Error in Fyne call thread" logged repeatedly at shutdown.

  Root cause: When the Fyne event loop shuts down it sets an internal
  `drained=true` flag. After that, fyne.Do(fn) runs fn DIRECTLY in the
  calling goroutine instead of queuing it. If event-loop goroutines
  (e.g., your startEventLoop goroutine) are still running and call
  fyne.Do, they execute widget methods off the main goroutine — Fyne
  detects this and logs the warning.

  FIX: Use window.SetCloseIntercept to call rootAgent.Cancel() BEFORE
  Fyne begins shutting down. This stops event-loop goroutines first.
  By the time drained=true, no goroutine is calling fyne.Do.

  a.window.SetCloseIntercept(handleQuit)   // handleQuit calls rootAgent.Cancel()
  // handleQuit then closes the window via: go func() { ...; fyne.Do(a.window.Close) }()

GOTCHA 3 — Preferences API requires a unique ID
──────────────────────────────────────────────────
  Symptom: "Fyne error: Preferences API requires a unique ID"

  FIX: Replace app.New() with app.NewWithID("com.example.yourapp").
  Each distinct binary/window needs its own unique ID string.

    a.fyneApp = app.NewWithID("io.late")           // general assistant
    a.fyneApp = fyneapp.NewWithID("io.late.sast")  // SAST scanner

GOTCHA 4 — LANG=C locale error
─────────────────────────────────
  Symptom: "Fyne error: Error parsing user locale C"

  FIX: Normalise $LANG at the top of main() before Fyne touches it:
    if lc := os.Getenv("LANG"); lc == "" || lc == "C" || lc == "POSIX" {
        os.Setenv("LANG", "en_US.UTF-8")
    }

GOTCHA 5 — One thinking accordion per chat, not per turn
──────────────────────────────────────────────────────────
  Symptom: Multiple "Thoughts" accordions appear — one per tool call or turn.

  Root cause: The "thinking" StatusEvent fires between tool calls, resetting
  thinkingStreaming=false. The next ReasoningContent chunk calls StartThinking()
  again, creating a new accordion each time.

  FIX: StartThinking() checks if lastThink != nil and reuses it:
    if p.lastThink != nil {
        p.lastThink.item.Title = "Thinking…"
        p.lastThink.rich.Segments = []widget.RichTextSegment{ /* empty */ }
        p.lastThink.accordion.Open(0)
        p.lastThink.accordion.Refresh()
        return
    }
    // else: create new accordion, set p.lastThink

  And "thinking" StatusEvent should call FinalizeThinking() (collapse current
  box) but NOT create a new one — that happens lazily when the next
  ReasoningContent chunk arrives.

GOTCHA 6 — Empty ContentEvent clears the last bubble
──────────────────────────────────────────────────────
  The orchestrator's onEndTurn hook emits a ContentEvent{Content:"", Usage:{...}}
  for final token accounting. If your event loop calls AppendMessage("assistant","")
  for this event it creates a blank bubble, and the previous message disappears
  because streaming=false was already set.

  FIX: At the top of the ContentEvent handler, detect and skip this case:
    if e.Content == "" && e.ReasoningContent == "" {
        // usage-only event — update counter, do not touch chat
        if e.Usage.PromptTokens > 0 && onUsage != nil { ... }
        continue
    }

GOTCHA 7 — Stop & Quit button needs visual feedback
──────────────────────────────────────────────────────
  Cleanup (docker stop, etc.) can take several seconds. Without feedback
  users click the button multiple times thinking it didn't work.

  FIX: On first click, immediately change the button text and disable it:
    var quitBtn *widget.Button   // declared before handleQuit closure
    handleQuit := func() {
        quitOnce.Do(func() {
            fyne.Do(func() { quitBtn.SetText("Stopping…"); quitBtn.Disable() })
            rootAgent.Cancel()
            go func() { cleanupFn(); fyne.Do(a.window.Close) }()
        })
    }
    quitBtn = widget.NewButton("⏹ Stop & Quit", handleQuit)

  The sync.Once guards against double-execution when both the button and
  the OS window-close button (SetCloseIntercept) are triggered near-simultaneously.

GOTCHA 8 — SetContext / SetMiddlewares not on the interface
────────────────────────────────────────────────────────────
  These methods exist on *BaseOrchestrator but not on common.Orchestrator.
  Return a concrete *orchestrator.BaseOrchestrator from buildScan(), not
  the interface — then call them directly without type assertions.

GOTCHA 9 — "text file busy" on install
─────────────────────────────────────────
  If the binary is running, `cp bin/late-sast ~/.local/bin/late-sast` fails.

  FIX: Atomic replace via a temp file + mv:
    cp bin/late-sast ~/.local/bin/late-sast.new
    mv ~/.local/bin/late-sast.new ~/.local/bin/late-sast

GOTCHA 10 — ast.Strong does not exist in goldmark
────────────────────────────────────────────────────
  Bold is *ast.Emphasis with Level==2, not ast.Strong.

GOTCHA 11 — fyne.ParseURI does not exist
──────────────────────────────────────────
  Use storage.ParseURI(str) — but it returns fyne.URI, not *url.URL.
  widget.HyperlinkSegment.URL is *url.URL — you cannot directly assign fyne.URI.
  Workaround: use net/url.Parse(str) or render links as plain text.

GOTCHA 12 — Missing libxxf86vm-dev on Linux
────────────────────────────────────────────
  Linker error: "cannot find -lXxf86vm"
  Fix: sudo apt-get install -y libxxf86vm-dev

═══════════════════════════════════════════════════════════════════════════════
PHASE 8: VERIFICATION
═══════════════════════════════════════════════════════════════════════════════

  go build ./...       # must be clean
  go test ./...        # all existing tests must still pass
  go vet ./...

  # TUI fallback:
  ./late-sast --tui https://github.com/owner/repo

  # GUI with picker (no flags):
  ./late-sast
  # → 700×460 picker window with URL/path/output fields

  # GUI skipping picker (CLI flag):
  ./late-sast --path /my/repo
  # → 1150×750 "Starting scan…" then main chat layout

═══════════════════════════════════════════════════════════════════════════════
FILE CHECKLIST
═══════════════════════════════════════════════════════════════════════════════

  NEW FILES:
  □ internal/gui/theme.go        (custom fyne.Theme)
  □ internal/gui/markdown.go     (goldmark → RichTextSegment)
  □ internal/gui/chat.go         (ChatPanel + thinkBubble)
  □ internal/gui/input.go        (InputPanel)
  □ internal/gui/provider.go     (GUIInputProvider)
  □ internal/gui/confirm.go      (GUIConfirmMiddleware)
  □ internal/gui/events.go       (startEventLoop, makeTabContent)
  □ internal/gui/app.go          (App struct, buildMainLayout, Run, tab management)
  □ internal/gui/context.go      (InputProvider context helpers)
  □ internal/gui/sessions.go     (ShowSessionBrowser)
  □ internal/gui/sast_picker.go  (RunSAST, buildPickerContent — SAST-specific only)

  MODIFIED FILES:
  □ internal/common/interfaces.go   (ChildAddedEvent.AgentType; ContentEvent.Usage)
  □ internal/orchestrator/base.go   (AddChild: +agentType param)
  □ internal/agent/agent.go         (MiddlewareFactory type; remove tui import)
  □ cmd/<sast-binary>/main.go       (LANG fix; --tui flag; buildScan closure; GUI branch)
  □ cmd/<main-binary>/main.go       (LANG fix; --tui flag; GUI branch)
  □ Makefile                        (separate bin/late-sast vs bin/late; fetch-cbm cache check)
  □ go.mod / go.sum                 (fyne v2, goldmark)

═══════════════════════════════════════════════════════════════════════════════
KNOWN GAPS (not yet implemented)
═══════════════════════════════════════════════════════════════════════════════

  □ Copy-to-clipboard button on assistant bubbles
  □ Multi-line input (shift+enter for newline)
  □ Drag-and-drop file attachment
  □ Font size / zoom controls
  □ Session browser accessible from within the GUI (fyne.NewMainMenu)
