package gui

import (
	"fmt"
	"image/color"
	"sync"
	"time"

	"late/internal/common"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/canvas"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/theme"
	"fyne.io/fyne/v2/widget"
)

// clusterCard is the visual representation of one architecture cluster.
type clusterCard struct {
	label     string
	files     []string
	isHotspot bool

	// Fyne widgets
	bg       *canvas.Rectangle
	title    *canvas.Text
	subtitle *canvas.Text
	box      *fyne.Container
}

func newClusterCard(c common.ArchitectureCluster) *clusterCard {
	cc := &clusterCard{
		label:     c.Label,
		files:     c.Files,
		isHotspot: c.IsHotspot,
	}

	cc.bg = canvas.NewRectangle(clusterBgColor(c.IsHotspot))
	cc.bg.CornerRadius = 6
	cc.bg.StrokeWidth = 1
	cc.bg.StrokeColor = theme.Color(theme.ColorNameSeparator)

	cc.title = canvas.NewText(c.Label, theme.Color(theme.ColorNameForeground))
	cc.title.TextStyle = fyne.TextStyle{Bold: true}
	cc.title.TextSize = 12

	subtitle := fmt.Sprintf("%d files", len(c.Files))
	if c.IsHotspot {
		subtitle = "⚠ HOTSPOT · " + subtitle
	}
	cc.subtitle = canvas.NewText(subtitle, theme.Color(theme.ColorNamePlaceHolder))
	cc.subtitle.TextSize = 10

	inner := container.NewVBox(
		container.NewPadded(cc.title),
		container.NewPadded(cc.subtitle),
	)
	cc.box = container.NewStack(cc.bg, inner)
	return cc
}

// highlight briefly changes the card background to indicate agent activity.
func (cc *clusterCard) highlight() {
	fyne.Do(func() {
		highlightCol := theme.Color(theme.ColorNamePrimary)
		restoreCol := clusterBgColor(cc.isHotspot)
		cc.bg.FillColor = highlightCol
		cc.bg.Refresh()
		anim := canvas.NewColorRGBAAnimation(highlightCol, restoreCol, 1500*time.Millisecond, func(c color.Color) {
			cc.bg.FillColor = c
			cc.bg.Refresh()
		})
		anim.Curve = fyne.AnimationLinear
		anim.Start()
	})
}

// markHotspot permanently marks this card as a high-risk hotspot.
func (cc *clusterCard) markHotspot() {
	fyne.Do(func() {
		cc.isHotspot = true
		cc.bg.FillColor = hotspotColor()
		cc.bg.Refresh()
		cc.subtitle.Text = "🔴 HOTSPOT · " + fmt.Sprintf("%d files", len(cc.files))
		cc.subtitle.Refresh()
	})
}

func clusterBgColor(isHotspot bool) color.Color {
	if isHotspot {
		return hotspotColor()
	}
	return theme.Color(theme.ColorNameButton)
}

func hotspotColor() color.Color {
	return color.RGBA{R: 180, G: 40, B: 40, A: 220}
}

// ─── ProjectMapPanel ──────────────────────────────────────────────────────────

// ProjectMapPanel is a Fyne widget that renders the codebase architecture as a
// grid of cluster cards. It updates in real time as agents access files.
type ProjectMapPanel struct {
	widget.BaseWidget

	mu      sync.RWMutex
	cards   []*clusterCard
	fileMap map[string]*clusterCard // file path → owning card
	data    common.ArchitectureData
	loaded  bool

	scroll *container.Scroll
	grid   *fyne.Container
	empty  *widget.Label
	stack  *fyne.Container
}

// NewProjectMapPanel creates an empty Project Map panel.
func NewProjectMapPanel() *ProjectMapPanel {
	p := &ProjectMapPanel{
		fileMap: make(map[string]*clusterCard),
	}
	p.ExtendBaseWidget(p)
	return p
}

// CreateRenderer implements fyne.Widget.
func (p *ProjectMapPanel) CreateRenderer() fyne.WidgetRenderer {
	p.empty = widget.NewLabel("Waiting for codebase analysis…\nThe Project Map will populate once get_architecture completes.")
	p.empty.Alignment = fyne.TextAlignCenter
	p.empty.Wrapping = fyne.TextWrapWord

	p.grid = container.NewAdaptiveGrid(3)
	p.scroll = container.NewScroll(p.grid)

	p.stack = container.NewStack(p.empty)

	return widget.NewSimpleRenderer(p.stack)
}

// Load populates the panel from ArchitectureData.
// Must be called from the Fyne main goroutine (or via fyne.Do).
func (p *ProjectMapPanel) Load(data common.ArchitectureData) {
	p.mu.Lock()
	p.data = data
	p.loaded = true
	p.cards = p.cards[:0]
	p.fileMap = make(map[string]*clusterCard)

	for _, c := range data.Clusters {
		card := newClusterCard(c)
		p.cards = append(p.cards, card)
		for _, f := range c.Files {
			p.fileMap[f] = card
		}
	}
	cards := p.cards
	p.mu.Unlock()

	// Rebuild the grid on the Fyne thread.
	fyne.Do(func() {
		p.grid.RemoveAll()
		for _, cc := range cards {
			p.grid.Add(cc.box)
		}
		p.stack.RemoveAll()
		header := p.buildHeader(data)
		p.stack.Add(container.NewBorder(header, nil, nil, nil, p.scroll))
		p.stack.Refresh()
	})
}

// HighlightFile briefly highlights the cluster card that owns filePath.
// Safe to call from any goroutine.
func (p *ProjectMapPanel) HighlightFile(filePath string, isHotspot bool) {
	p.mu.RLock()
	card, ok := p.fileMap[filePath]
	p.mu.RUnlock()
	if !ok {
		return
	}
	if isHotspot {
		card.markHotspot()
	} else {
		card.highlight()
	}
}

func (p *ProjectMapPanel) buildHeader(data common.ArchitectureData) fyne.CanvasObject {
	lang := data.Language
	if lang == "" {
		lang = "unknown"
	}
	info := fmt.Sprintf(
		"Language: %s   Files: %d   Nodes: %d   Clusters: %d   Hotspots: %d",
		lang, data.FileCount, data.NodeCount, len(data.Clusters), len(data.Hotspots),
	)
	lbl := widget.NewLabel(info)
	lbl.TextStyle = fyne.TextStyle{Monospace: true}
	return container.NewPadded(lbl)
}
