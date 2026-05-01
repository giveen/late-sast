package gui

import (
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// InputPanel is the compose area at the bottom of a chat tab.
// It contains a text entry, a Send button, and supports file drop.
type InputPanel struct {
	widget.BaseWidget

	entry   *widget.Entry
	sendBtn *widget.Button
	content fyne.CanvasObject
	onSend  func(string)
}

// NewInputPanel builds the input panel and wires the submit callback.
func NewInputPanel(onSend func(string)) *InputPanel {
	p := &InputPanel{onSend: onSend}

	p.entry = widget.NewEntry()
	p.entry.SetPlaceHolder("Ask Late anything… (Enter to send)")
	p.entry.OnSubmitted = func(text string) {
		p.doSend()
	}

	p.sendBtn = widget.NewButtonWithIcon("Send", theme.MailSendIcon(), func() {
		p.doSend()
	})
	p.sendBtn.Importance = widget.HighImportance

	p.content = container.NewBorder(nil, nil, nil, p.sendBtn, p.entry)
	p.ExtendBaseWidget(p)
	return p
}

// CreateRenderer wraps the content layout.
func (p *InputPanel) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(p.content)
}

// SetEnabled toggles the input panel on / off (disabled when agent is thinking).
func (p *InputPanel) SetEnabled(enabled bool) {
	if enabled {
		p.entry.Enable()
		p.sendBtn.Enable()
	} else {
		p.entry.Disable()
		p.sendBtn.Disable()
	}
	p.Refresh()
}

func (p *InputPanel) doSend() {
	text := strings.TrimSpace(p.entry.Text)
	if text == "" {
		return
	}
	p.entry.SetText("")
	if p.onSend != nil {
		p.onSend(text)
	}
}
