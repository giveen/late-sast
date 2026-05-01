package gui

import (
	"strings"
	"time"

	"late/internal/common"

	"fyne.io/fyne/v2"
	fyneapp "fyne.io/fyne/v2/app"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// SASTPickerResult holds the user's target selection from the launcher screen.
type SASTPickerResult struct {
	URL       string // GitHub URL (empty when LocalPath is set)
	LocalPath string // local directory path (empty when URL is set)
	OutputDir string // where to write the report; empty means use default (cwd)
}

// RunSAST initialises Fyne, shows a target-picker screen when no target is
// pre-supplied via CLI flags, then calls setupFn with the resolved target.
// setupFn builds the fully wired orchestrator and returns it together with
// the message to auto-submit as the first audit task.
//
// When knownTarget or knownLocalPath is non-empty the picker is skipped and
// the scan starts immediately — backwards-compatible with CLI flag behaviour.
//
// This call blocks until the window is closed.
func (a *App) RunSAST(
	knownTarget, knownLocalPath, knownOutputDir string,
	setupFn func(SASTPickerResult) (common.Orchestrator, string),
) {
	a.fyneApp = fyneapp.NewWithID("io.late.sast")
	a.fyneApp.Settings().SetTheme(&lateTheme{})
	a.window = a.fyneApp.NewWindow("Late SAST")
	a.window.SetIcon(appIcon)

	// transition switches the window from the picker/loading screen to the
	// main chat layout. It runs setupFn in a background goroutine (it may
	// do blocking I/O) and then updates the UI via fyne.Do.
	transition := func(res SASTPickerResult) {
		rootAgent, initialMsg := setupFn(res)
		fyne.Do(func() {
			a.window.Resize(fyne.NewSize(1150, 750))
			a.buildMainLayout(rootAgent, nil)
			a.window.SetContent(a.tabs)
		})
		if initialMsg != "" {
			go func() {
				time.Sleep(300 * time.Millisecond)
				rootAgent.Submit(initialMsg) //nolint:errcheck
			}()
		}
	}

	if knownTarget != "" || knownLocalPath != "" {
		// Target already known via CLI — show a brief loading screen while
		// setup runs in the background.
		a.window.Resize(fyne.NewSize(1150, 750))
		a.window.SetContent(container.NewCenter(
			widget.NewLabel("Starting scan…"),
		))
		go transition(SASTPickerResult{
			URL:       knownTarget,
			LocalPath: knownLocalPath,
			OutputDir: knownOutputDir,
		})
	} else {
		// No target supplied — show the interactive picker.
		a.window.Resize(fyne.NewSize(700, 460))
		a.window.SetContent(a.buildPickerContent(
			func(res SASTPickerResult) {
				fyne.Do(func() {
					a.window.SetContent(container.NewCenter(
						widget.NewLabel("Setting up scan…"),
					))
				})
				go transition(res)
			},
			knownOutputDir,
		))
	}

	a.window.ShowAndRun()
}

// buildPickerContent returns the target-selection form as a Fyne canvas
// object. onStart is called (from the Fyne main goroutine) when the user
// clicks "Start Scan".
func (a *App) buildPickerContent(onStart func(SASTPickerResult), defaultOutputDir string) fyne.CanvasObject {
	title := widget.NewLabelWithStyle(
		"Late SAST — Select Target",
		fyne.TextAlignCenter,
		fyne.TextStyle{Bold: true},
	)

	// ── GitHub URL field ──────────────────────────────────────────────────
	urlLabel := widget.NewLabel("GitHub repository URL")
	urlEntry := widget.NewEntry()
	urlEntry.SetPlaceHolder("https://github.com/owner/repo")

	// ── Local path field + browse button ─────────────────────────────────
	localLabel := widget.NewLabel("— or local directory —")
	localEntry := widget.NewEntry()
	localEntry.SetPlaceHolder("/path/to/project")

	browseBtn := widget.NewButton("Browse…", func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err != nil || lu == nil {
				return
			}
			localEntry.SetText(lu.Path())
			// Clear the URL field so validation passes cleanly.
			urlEntry.SetText("")
		}, a.window)
	})

	// ── Output directory field ────────────────────────────────────────────
	outputLabel := widget.NewLabel("Output directory  (default: current directory)")
	outputEntry := widget.NewEntry()
	outputEntry.SetText(defaultOutputDir)
	outputEntry.SetPlaceHolder("Leave blank for current directory")

	outputBrowse := widget.NewButton("Browse…", func() {
		dialog.ShowFolderOpen(func(lu fyne.ListableURI, err error) {
			if err != nil || lu == nil {
				return
			}
			outputEntry.SetText(lu.Path())
		}, a.window)
	})

	// ── Error label + Start button ────────────────────────────────────────
	errLabel := widget.NewLabel("")
	errLabel.Hide()

	startBtn := widget.NewButton("Start Scan", func() {
		url := strings.TrimSpace(urlEntry.Text)
		localPath := strings.TrimSpace(localEntry.Text)
		outputDir := strings.TrimSpace(outputEntry.Text)

		if url == "" && localPath == "" {
			errLabel.SetText("Enter a GitHub URL or select a local directory.")
			errLabel.Show()
			return
		}
		if url != "" && localPath != "" {
			errLabel.SetText("Use a URL or a local path — not both.")
			errLabel.Show()
			return
		}
		errLabel.Hide()
		onStart(SASTPickerResult{URL: url, LocalPath: localPath, OutputDir: outputDir})
	})
	startBtn.Importance = widget.HighImportance

	return container.NewCenter(
		container.NewVBox(
			title,
			widget.NewSeparator(),
			urlLabel,
			urlEntry,
			localLabel,
			container.NewBorder(nil, nil, nil, browseBtn, localEntry),
			widget.NewSeparator(),
			outputLabel,
			container.NewBorder(nil, nil, nil, outputBrowse, outputEntry),
			widget.NewSeparator(),
			errLabel,
			startBtn,
		),
	)
}
