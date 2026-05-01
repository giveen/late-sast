package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/widget"
)

// messageBubble tracks a single chat message and its live widget.
type messageBubble struct {
	role    string // "user" or "assistant"
	content string
	rich    *widget.RichText
}

// ChatPanel is a scrollable list of conversation bubbles.
type ChatPanel struct {
	widget.BaseWidget

	scroll   *container.Scroll
	vbox     *fyne.Container
	messages []*messageBubble
}

// NewChatPanel constructs an empty ChatPanel.
func NewChatPanel() *ChatPanel {
	p := &ChatPanel{}
	p.vbox = container.NewVBox()
	p.scroll = container.NewVScroll(p.vbox)
	p.ExtendBaseWidget(p)
	return p
}

// CreateRenderer returns a simple renderer that wraps the scroll container.
func (p *ChatPanel) CreateRenderer() fyne.WidgetRenderer {
	return widget.NewSimpleRenderer(p.scroll)
}

// AppendMessage adds a new message bubble to the bottom of the chat.
func (p *ChatPanel) AppendMessage(role, content string) {
	segs := makeSegments(content, false)
	rich := widget.NewRichText(segs...)
	rich.Wrapping = fyne.TextWrapWord

	bubble := makeBubble(role, rich)
	p.messages = append(p.messages, &messageBubble{role: role, content: content, rich: rich})
	p.vbox.Add(bubble)
	p.scroll.ScrollToBottom()
	p.vbox.Refresh()
}

// UpdateLastMessage replaces the content of the most recently added bubble with
// plain text (used during streaming to avoid incomplete-Markdown parse errors).
func (p *ChatPanel) UpdateLastMessage(content string) {
	if len(p.messages) == 0 {
		return
	}
	last := p.messages[len(p.messages)-1]
	last.content = content
	last.rich.Segments = makeSegments(content, true /* plain */)
	last.rich.Refresh()
	p.scroll.ScrollToBottom()
}

// FinalizeLastMessage re-renders the last bubble with full Markdown once
// streaming is complete (called on StatusEvent "idle").
func (p *ChatPanel) FinalizeLastMessage() {
	if len(p.messages) == 0 {
		return
	}
	last := p.messages[len(p.messages)-1]
	last.rich.Segments = makeSegments(last.content, false)
	last.rich.Refresh()
}

// makeSegments converts content to RichText segments.
// When plain=true the content is treated as pre-formatted text (streaming mode).
func makeSegments(content string, plain bool) []widget.RichTextSegment {
	if plain || content == "" {
		return []widget.RichTextSegment{
			&widget.TextSegment{
				Style: widget.RichTextStyleParagraph,
				Text:  content,
			},
		}
	}
	segs := parseMarkdown(content)
	if len(segs) == 0 {
		return []widget.RichTextSegment{
			&widget.TextSegment{
				Style: widget.RichTextStyleParagraph,
				Text:  content,
			},
		}
	}
	return segs
}

// makeBubble wraps a RichText widget in a styled card-like container.
func makeBubble(role string, rich *widget.RichText) fyne.CanvasObject {
	var bg color.Color
	var align fyne.TextAlign

	switch role {
	case "user":
		bg = colorUserBg
		align = fyne.TextAlignTrailing
	default: // "assistant", "tool", etc.
		bg = colorSurface
		align = fyne.TextAlignLeading
	}

	_ = align // RichText alignment is per-segment; overall layout handles alignment

	rect := canvas.NewRectangle(bg)
	rect.CornerRadius = 8

	pad := container.NewPadded(rich)
	bubble := container.NewStack(rect, pad)

	// Give user bubbles right-side spacing via a border container
	if role == "user" {
		spacer := canvas.NewRectangle(color.Transparent)
		spacer.SetMinSize(fyne.NewSize(80, 0))
		return container.NewBorder(nil, nil, spacer, nil, bubble)
	}

	// Assistant bubbles get a subtle left accent line
	accent := canvas.NewRectangle(colorAmethyst)
	accent.SetMinSize(fyne.NewSize(3, 0))
	return container.NewBorder(nil, nil, accent, nil, bubble)
}
