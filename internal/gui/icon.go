package gui

import (
	_ "embed"

	"fyne.io/fyne/v2"
)

//go:embed late-sast.svg
var appIconBytes []byte

// appIcon is the Fyne resource used for window and taskbar icons.
var appIcon = fyne.NewStaticResource("late-sast.svg", appIconBytes)
