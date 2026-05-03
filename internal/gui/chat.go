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

// thinkBubble is a collapsible accordion that streams reasoning content.
type thinkBubble struct {
	accordion *widget.Accordion
	item      *widget.AccordionItem
	rich      *widget.RichText
}

// ChatPanel is a scrollable list of conversation bubbles.
type ChatPanel struct {
	widget.BaseWidget

	scroll    *container.Scroll
	vbox      *fyne.Container
	messages  []*messageBubble
	lastThink *thinkBubble // currently active (or most recent) thinking bubble
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

// StartThinking adds (or reopens) the single "Thinking…" accordion.
// Subsequent calls reuse the existing accordion rather than creating a new one.
// Call from the Fyne main goroutine.
func (p *ChatPanel) StartThinking() {
	if p.lastThink != nil {
		// Reuse: clear content ready for the next reasoning chunk.
		// Do NOT reopen — let the user decide whether to expand it.
		p.lastThink.item.Title = "Thinking…"
		p.lastThink.rich.Segments = []widget.RichTextSegment{
			&widget.TextSegment{Style: widget.RichTextStyleParagraph, Text: ""},
		}
		p.lastThink.accordion.Refresh()
		return
	}

	rich := widget.NewRichText(&widget.TextSegment{
		Style: widget.RichTextStyleParagraph,
		Text:  "",
	})
	rich.Wrapping = fyne.TextWrapWord

	item := widget.NewAccordionItem("Thinking…", rich)
	acc := widget.NewAccordion(item)
	// Collapsed by default — user can expand to read reasoning.

	// Dim purple left accent to visually separate from response bubbles.
	accent := canvas.NewRectangle(color.NRGBA{R: 0x6C, G: 0x3D, B: 0x80, A: 0xFF})
	accent.SetMinSize(fyne.NewSize(3, 0))
	wrapped := container.NewBorder(nil, nil, accent, nil, acc)

	p.lastThink = &thinkBubble{accordion: acc, item: item, rich: rich}
	p.vbox.Add(wrapped)
	p.scroll.ScrollToBottom()
	p.vbox.Refresh()
}

// UpdateThinking streams new accumulated reasoning into the open thinking bubble.
// Call from the Fyne main goroutine.
func (p *ChatPanel) UpdateThinking(content string) {
	if p.lastThink == nil {
		return
	}
	p.lastThink.rich.Segments = []widget.RichTextSegment{
		&widget.TextSegment{
			Style: widget.RichTextStyleParagraph,
			Text:  content,
		},
	}
	p.lastThink.rich.Refresh()
	// Only auto-scroll if the accordion is collapsed. When the user has opened it
	// to read the reasoning, leave the scroll position alone so they can read
	// without being dragged to the bottom on every streaming chunk.
	if !p.lastThink.item.Open {
		p.scroll.ScrollToBottom()
	}
}

// FinalizeThinking collapses the thinking accordion when reasoning is complete.
// Call from the Fyne main goroutine.
func (p *ChatPanel) FinalizeThinking() {
	if p.lastThink == nil {
		return
	}
	p.lastThink.item.Title = "Thoughts"
	p.lastThink.accordion.Close(0)
	p.lastThink.accordion.Refresh()
	// Keep lastThink reference — user can still expand to read it.
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
