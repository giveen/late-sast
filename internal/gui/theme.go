package gui

import (
	"image/color"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/theme"
)

// Palette colours — ported from tui/theme.go (obsidian + amethyst).
var (
	colorBg       = color.NRGBA{R: 0x19, G: 0x19, B: 0x19, A: 0xFF} // #191919
	colorSurface  = color.NRGBA{R: 0x24, G: 0x24, B: 0x24, A: 0xFF} // #242424
	colorAmethyst = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0xFF} // #9B59B6
	colorText     = color.NRGBA{R: 0xEC, G: 0xF0, B: 0xF1, A: 0xFF} // #ECF0F1
	colorSubtext  = color.NRGBA{R: 0xBD, G: 0xC3, B: 0xC7, A: 0xFF} // #BDC3C7
	colorGreen    = color.NRGBA{R: 0x2E, G: 0xCC, B: 0x71, A: 0xFF} // #2ECC71
	colorOrange   = color.NRGBA{R: 0xE6, G: 0x7E, B: 0x22, A: 0xFF} // #E67E22
	colorUserBg   = color.NRGBA{R: 0x2C, G: 0x1A, B: 0x3E, A: 0xFF} // user bubble
	colorHover    = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0x40}
	colorFocus    = color.NRGBA{R: 0x9B, G: 0x59, B: 0xB6, A: 0x80}
)

type lateTheme struct{}

func (t *lateTheme) Color(name fyne.ThemeColorName, _ fyne.ThemeVariant) color.Color {
	switch name {
	case theme.ColorNameBackground:
		return colorBg
	case theme.ColorNameButton:
		return colorAmethyst
	case theme.ColorNameDisabledButton:
		return colorSurface
	case theme.ColorNameForeground:
		return colorText
	case theme.ColorNameDisabled:
		return colorSubtext
	case theme.ColorNamePlaceHolder:
		return colorSubtext
	case theme.ColorNameScrollBar:
		return colorAmethyst
	case theme.ColorNameShadow:
		return color.NRGBA{A: 0x88}
	case theme.ColorNameInputBackground:
		return colorSurface
	case theme.ColorNameOverlayBackground:
		return colorSurface
	case theme.ColorNameHeaderBackground:
		return colorBg
	case theme.ColorNameSelection:
		return colorHover
	case theme.ColorNamePrimary:
		return colorAmethyst
	case theme.ColorNameHover:
		return colorHover
	case theme.ColorNameFocus:
		return colorFocus
	case theme.ColorNameSuccess:
		return colorGreen
	case theme.ColorNameWarning:
		return colorOrange
	}
	return theme.DefaultTheme().Color(name, theme.VariantDark)
}

func (t *lateTheme) Font(style fyne.TextStyle) fyne.Resource {
	return theme.DefaultTheme().Font(style)
}

func (t *lateTheme) Icon(name fyne.ThemeIconName) fyne.Resource {
	return theme.DefaultTheme().Icon(name)
}

func (t *lateTheme) Size(name fyne.ThemeSizeName) float32 {
	switch name {
	case theme.SizeNamePadding:
		return 8
	case theme.SizeNameInlineIcon:
		return 20
	case theme.SizeNameScrollBar:
		return 10
	case theme.SizeNameText:
		return 13
	case theme.SizeNameHeadingText:
		return 22
	case theme.SizeNameSubHeadingText:
		return 17
	}
	return theme.DefaultTheme().Size(name)
}
