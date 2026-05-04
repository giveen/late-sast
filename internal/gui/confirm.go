package gui

import (
	"context"
	"encoding/json"
	"runtime"

	"late/internal/client"
	"late/internal/common"
	"late/internal/tool"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

// GUIConfirmMiddleware returns a ToolMiddleware that shows a Fyne dialog for
// tool-call confirmation.
func GUIConfirmMiddleware(win fyne.Window, reg *common.ToolRegistry, unsupervised bool) common.ToolMiddleware {
	return func(next common.ToolRunner) common.ToolRunner {
		return func(ctx context.Context, tc client.ToolCall) (string, error) {
			// Unsupervised mode — skip confirmation (not on Windows bash).
			if unsupervised {
				if !(runtime.GOOS == "windows" && tc.Function.Name == "bash") {
					approvedCtx := context.WithValue(ctx, common.ToolApprovalKey, true)
					return next(approvedCtx, tc)
				}
			}

			if reg != nil {
				t := reg.Get(tc.Function.Name)
				if t != nil {
					// Check global allow-list.
					if allowed, _ := tool.LoadAllAllowedTools(); allowed[tc.Function.Name] {
						approvedCtx := context.WithValue(ctx, common.ToolApprovalKey, true)
						return next(approvedCtx, tc)
					}
					// Tool's own confirmation logic.
					if !t.RequiresConfirmation(json.RawMessage(tc.Function.Arguments)) {
						return next(ctx, tc)
					}
					// For ShellTool — check if the command is blocked.
					if bashTool, ok := t.(*tool.ShellTool); ok {
						var params struct {
							Command string `json:"command"`
							Cwd     string `json:"cwd"`
						}
						if err := json.Unmarshal([]byte(tc.Function.Arguments), &params); err == nil {
							if blocked, err := bashTool.IsCommandBlocked(params.Command, params.Cwd); blocked {
								return "", bashTool.WrapError(ctx, err)
							}
						}
					}
				}
			}

			// Ask the user via a dialog.
			resultCh := make(chan string, 1)
			fyne.Do(func() {
				showConfirmDialog(win, tc, resultCh)
			})

			select {
			case choice := <-resultCh:
				return applyChoice(ctx, choice, tc, reg, next)
			case <-ctx.Done():
				return "", ctx.Err()
			}
		}
	}
}

// showConfirmDialog builds and displays the tool-confirmation dialog.
// It sends one of "y", "s", "p", "g", "n" to resultCh when the user chooses.
func showConfirmDialog(win fyne.Window, tc client.ToolCall, resultCh chan<- string) {
	label := widget.NewLabel(formatCallString(tc))
	label.Wrapping = fyne.TextWrapWord

	// Pretty-print the tool call arguments.
	var jsonObj map[string]interface{}
	args := tc.Function.Arguments
	if err := json.Unmarshal([]byte(args), &jsonObj); err == nil {
		if pretty, err := json.MarshalIndent(jsonObj, "", "  "); err == nil {
			args = string(pretty)
		}
	}

	code := widget.NewRichTextWithText(tc.Function.Name + "\n" + args)
	code.Wrapping = fyne.TextWrapWord

	var d dialog.Dialog

	send := func(choice string) {
		d.Hide()
		select {
		case resultCh <- choice:
		default:
		}
	}

	buttons := container.NewGridWithColumns(5,
		widget.NewButton("Allow Once", func() { send("y") }),
		widget.NewButton("Session", func() { send("s") }),
		widget.NewButton("Project", func() { send("p") }),
		widget.NewButton("Global", func() { send("g") }),
		widget.NewButton("Deny", func() { send("n") }),
	)

	body := container.NewVBox(label, code, buttons)
	d = dialog.NewCustomWithoutButtons("Confirm Tool Call", body, win)
	d.SetOnClosed(func() {
		// If dismissed without choosing, deny.
		select {
		case resultCh <- "n":
		default:
		}
	})
	d.Show()
}

func formatCallString(tc client.ToolCall) string {
	return "Allow " + tc.Function.Name + " to execute?"
}

// applyChoice processes the user's confirmation choice (mirrors tui logic).
func applyChoice(
	ctx context.Context,
	choice string,
	tc client.ToolCall,
	reg *common.ToolRegistry,
	next common.ToolRunner,
) (string, error) {
	switch choice {
	case "n", "":
		return "Tool execution cancelled by user", nil
	}

	// Persist allow-list entries for s/p/g.
	if reg != nil {
		if t := reg.Get(tc.Function.Name); t != nil {
			if _, ok := t.(*tool.ShellTool); ok {
				var params struct {
					Command string `json:"command"`
				}
				if err := json.Unmarshal([]byte(tc.Function.Arguments), &params); err == nil {
					switch choice {
					case "s", "S":
						tool.SaveSessionAllowedCommand(params.Command)
					case "p", "P":
						_ = tool.SaveAllowedCommand(params.Command, false)
					case "g", "G":
						_ = tool.SaveAllowedCommand(params.Command, true)
					}
				}
			} else {
				switch choice {
				case "s", "S":
					tool.SaveSessionAllowedTool(tc.Function.Name)
				case "p", "P":
					_ = tool.SaveAllowedTool(tc.Function.Name, false)
				case "g", "G":
					_ = tool.SaveAllowedTool(tc.Function.Name, true)
				}
			}
		}
	}

	approvedCtx := context.WithValue(ctx, common.ToolApprovalKey, true)
	return next(approvedCtx, tc)
}
