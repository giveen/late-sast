package gui

import (
	"context"
	"encoding/json"
	"fmt"

	"late/internal/common"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// GUIInputProvider implements common.InputProvider using Fyne dialogs.
type GUIInputProvider struct {
	win fyne.Window
}

func newGUIInputProvider(win fyne.Window) *GUIInputProvider {
	return &GUIInputProvider{win: win}
}

// Prompt shows a modal input dialog and blocks until the user responds.
func (p *GUIInputProvider) Prompt(ctx context.Context, req common.PromptRequest) (json.RawMessage, error) {
	resultCh := make(chan json.RawMessage, 1)
	errCh := make(chan error, 1)

	fyne.Do(func() {
		entry := widget.NewEntry()
		body := container.NewVBox(
			widget.NewLabel(req.Description),
			entry,
		)
		dialog.ShowCustomConfirm(req.Title, "Submit", "Cancel", body,
			func(confirmed bool) {
				if confirmed {
					val, _ := json.Marshal(entry.Text)
					resultCh <- val
				} else {
					errCh <- fmt.Errorf("user cancelled input prompt")
				}
			}, p.win)
	})

	select {
	case res := <-resultCh:
		return res, nil
	case err := <-errCh:
		return nil, err
	case <-ctx.Done():
		return nil, ctx.Err()
	}
}
