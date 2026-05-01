package gui

import (
	"bytes"
	"fmt"
	"strings"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/storage"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
	"github.com/yuin/goldmark"
	"github.com/yuin/goldmark/ast"
	"github.com/yuin/goldmark/extension"
	extast "github.com/yuin/goldmark/extension/ast"
	"github.com/yuin/goldmark/text"
)

// parseMarkdown converts a Markdown string into Fyne RichTextSegment slices.
// During streaming (incomplete input), callers should pass plain text and skip
// this function — use a plain TextSegment instead to avoid parse errors.
func parseMarkdown(src string) []widget.RichTextSegment {
	if strings.TrimSpace(src) == "" {
		return nil
	}

	source := []byte(src)
	reader := text.NewReader(source)
	md := goldmark.New(goldmark.WithExtensions(extension.Table))
	doc := md.Parser().Parse(reader)

	w := &mdWalker{source: source}
	ast.Walk(doc, w.walk) //nolint:errcheck
	return w.segments
}

// mdWalker walks a goldmark AST and produces Fyne RichTextSegment slices.
type mdWalker struct {
	source       []byte
	segments     []widget.RichTextSegment
	bold         bool
	italic       bool
	mono         bool
	headingLevel int
	listDepth    int
	listOrdered  bool
	itemCounter  int
}

func (w *mdWalker) currentStyle() widget.RichTextStyle {
	s := widget.RichTextStyleParagraph
	s.TextStyle = fyne.TextStyle{
		Bold:      w.bold,
		Italic:    w.italic,
		Monospace: w.mono,
	}
	if w.headingLevel >= 1 {
		s.TextStyle.Bold = true
		s.ColorName = theme.ColorNamePrimary
		switch w.headingLevel {
		case 1:
			s.SizeName = theme.SizeNameHeadingText
		case 2:
			s.SizeName = theme.SizeNameSubHeadingText
		}
	}
	if w.mono {
		s.ColorName = theme.ColorNameSuccess // green for inline code
	}
	if w.bold && !w.italic && w.headingLevel == 0 {
		s.ColorName = theme.ColorNameWarning // orange for strong
	}
	return s
}

func (w *mdWalker) addText(text string) {
	if text == "" {
		return
	}
	w.segments = append(w.segments, &widget.TextSegment{
		Style: w.currentStyle(),
		Text:  text,
	})
}

func (w *mdWalker) walk(n ast.Node, entering bool) (ast.WalkStatus, error) {
	switch node := n.(type) {

	case *ast.Text:
		if entering {
			w.addText(string(node.Segment.Value(w.source)))
			if node.SoftLineBreak() {
				w.addText(" ")
			}
			if node.HardLineBreak() {
				w.addText("\n")
			}
		}

	case *ast.Heading:
		if entering {
			w.headingLevel = node.Level
		} else {
			w.headingLevel = 0
			w.segments = append(w.segments, &widget.TextSegment{
				Style: widget.RichTextStyleParagraph,
				Text:  "\n",
			})
		}

	case *ast.Emphasis:
		if node.Level == 1 {
			w.italic = entering
		} else {
			w.bold = entering
		}

	case *ast.CodeSpan:
		w.mono = entering

	case *ast.FencedCodeBlock, *ast.CodeBlock:
		if entering {
			var buf bytes.Buffer
			switch nb := node.(type) {
			case *ast.FencedCodeBlock:
				for i := 0; i < nb.Lines().Len(); i++ {
					line := nb.Lines().At(i)
					buf.Write(line.Value(w.source))
				}
			case *ast.CodeBlock:
				for i := 0; i < nb.Lines().Len(); i++ {
					line := nb.Lines().At(i)
					buf.Write(line.Value(w.source))
				}
			}
			w.segments = append(w.segments, &widget.TextSegment{
				Style: widget.RichTextStyleCodeBlock,
				Text:  buf.String(),
			})
		}
		return ast.WalkSkipChildren, nil

	case *ast.Blockquote:
		// Wrap children in subdued colour by toggling italic
		w.italic = entering

	case *ast.List:
		if entering {
			w.listDepth++
			w.listOrdered = node.IsOrdered()
			w.itemCounter = 0
		} else {
			w.listDepth--
		}

	case *ast.ListItem:
		if entering {
			w.itemCounter++
			indent := strings.Repeat("  ", w.listDepth-1)
			if w.listOrdered {
				w.addText(fmt.Sprintf("%s%d. ", indent, w.itemCounter))
			} else {
				w.addText(indent + "• ")
			}
		}

	case *extast.Table:
		if entering {
			w.addText("\n")
			w.addText(renderTable(node, w.source))
			w.addText("\n")
		}
		return ast.WalkSkipChildren, nil

	case *ast.Paragraph:
		if !entering {
			w.segments = append(w.segments, &widget.TextSegment{
				Style: widget.RichTextStyleParagraph,
				Text:  "\n",
			})
		}

	case *ast.ThematicBreak:
		if entering {
			w.segments = append(w.segments, &widget.SeparatorSegment{})
		}

	case *ast.Link:
		if entering {
			uri, _ := storage.ParseURI(string(node.Destination))
			if uri != nil {
				// Collect link text from child Text nodes.
				var linkText strings.Builder
				for c := node.FirstChild(); c != nil; c = c.NextSibling() {
					if t, ok := c.(*ast.Text); ok {
						linkText.Write(t.Segment.Value(w.source))
					}
				}
				w.addText(linkText.String()) // render as plain text; HyperlinkSegment requires *url.URL
				return ast.WalkSkipChildren, nil
			}
		}

	case *ast.RawHTML:
		// Ignore raw HTML in Markdown
		return ast.WalkSkipChildren, nil
	}

	return ast.WalkContinue, nil
}

func renderTable(tbl *extast.Table, source []byte) string {
	rows := make([][]string, 0)
	headerSeen := false

	for c := tbl.FirstChild(); c != nil; c = c.NextSibling() {
		switch n := c.(type) {
		case *extast.TableHeader:
			headerSeen = true
			for r := n.FirstChild(); r != nil; r = r.NextSibling() {
				if row, ok := r.(*extast.TableRow); ok {
					rows = append(rows, extractTableRowCells(row, source))
				}
			}
		case *extast.TableRow:
			rows = append(rows, extractTableRowCells(n, source))
		}
	}

	if len(rows) == 0 {
		return ""
	}

	maxCols := 0
	for _, r := range rows {
		if len(r) > maxCols {
			maxCols = len(r)
		}
	}
	if maxCols == 0 {
		return ""
	}

	for i := range rows {
		for len(rows[i]) < maxCols {
			rows[i] = append(rows[i], "")
		}
	}

	var out strings.Builder
	writeRow := func(cells []string) {
		out.WriteString("| ")
		for i, cell := range cells {
			if i > 0 {
				out.WriteString(" | ")
			}
			out.WriteString(strings.TrimSpace(cell))
		}
		out.WriteString(" |\n")
	}

	writeRow(rows[0])
	if headerSeen {
		out.WriteString("| ")
		for i := 0; i < maxCols; i++ {
			if i > 0 {
				out.WriteString(" | ")
			}
			out.WriteString("---")
		}
		out.WriteString(" |\n")
	}

	start := 0
	if headerSeen {
		start = 1
	}
	for i := start; i < len(rows); i++ {
		writeRow(rows[i])
	}

	return strings.TrimRight(out.String(), "\n")
}

func extractTableRowCells(row *extast.TableRow, source []byte) []string {
	cells := make([]string, 0)
	for c := row.FirstChild(); c != nil; c = c.NextSibling() {
		if cell, ok := c.(*extast.TableCell); ok {
			cells = append(cells, nodePlainText(cell, source))
		}
	}
	return cells
}

func nodePlainText(n ast.Node, source []byte) string {
	var b strings.Builder
	var walkFn func(ast.Node)
	walkFn = func(cur ast.Node) {
		switch t := cur.(type) {
		case *ast.Text:
			b.Write(t.Segment.Value(source))
			if t.HardLineBreak() || t.SoftLineBreak() {
				b.WriteString(" ")
			}
		case *ast.CodeSpan:
			for c := t.FirstChild(); c != nil; c = c.NextSibling() {
				walkFn(c)
			}
		default:
			for c := cur.FirstChild(); c != nil; c = c.NextSibling() {
				walkFn(c)
			}
		}
	}
	walkFn(n)
	return strings.TrimSpace(b.String())
}
