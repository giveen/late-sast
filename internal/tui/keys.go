package tui

import "charm.land/bubbles/v2/key"

// KeyMap holds all key bindings for the TUI.
type KeyMap struct {
	Submit       key.Binding
	Stop         key.Binding
	Tab          key.Binding
	Back         key.Binding
	AllowOnce    key.Binding
	AllowSession key.Binding
	AllowProject key.Binding
	AllowGlobal  key.Binding
	Deny         key.Binding
	Help         key.Binding
	Quit         key.Binding
}

// ShortHelp returns the bindings shown in the status-bar short hint.
func (k KeyMap) ShortHelp() []key.Binding {
	return []key.Binding{k.Help, k.Quit}
}

// FullHelp returns all bindings for the full help overlay (? key).
func (k KeyMap) FullHelp() [][]key.Binding {
	return [][]key.Binding{
		{k.Submit, k.Stop, k.Tab, k.Back, k.Quit},
		{k.AllowOnce, k.AllowSession, k.AllowProject, k.AllowGlobal, k.Deny},
	}
}

// DefaultKeyMap is the default key map for the TUI.
var DefaultKeyMap = KeyMap{
	Submit:       key.NewBinding(key.WithKeys("enter"), key.WithHelp("enter", "send message")),
	Stop:         key.NewBinding(key.WithKeys("ctrl+g"), key.WithHelp("ctrl+g", "stop agent")),
	Tab:          key.NewBinding(key.WithKeys("tab"), key.WithHelp("tab", "switch agent")),
	Back:         key.NewBinding(key.WithKeys("esc"), key.WithHelp("esc", "back / quit")),
	AllowOnce:    key.NewBinding(key.WithKeys("y"), key.WithHelp("y", "allow once")),
	AllowSession: key.NewBinding(key.WithKeys("s"), key.WithHelp("s", "allow session")),
	AllowProject: key.NewBinding(key.WithKeys("p"), key.WithHelp("p", "allow project")),
	AllowGlobal:  key.NewBinding(key.WithKeys("g"), key.WithHelp("g", "allow globally")),
	Deny:         key.NewBinding(key.WithKeys("n"), key.WithHelp("n", "deny")),
	Help:         key.NewBinding(key.WithKeys("?"), key.WithHelp("?", "toggle help")),
	Quit:         key.NewBinding(key.WithKeys("ctrl+c"), key.WithHelp("ctrl+c", "quit")),
}
