package gui

import (
	"path/filepath"
	"strings"

	"late/internal/config"
	"late/internal/pathutil"

	"fyne.io/fyne/v2"
	"fyne.io/fyne/v2/container"
	"fyne.io/fyne/v2/dialog"
	"fyne.io/fyne/v2/widget"
)

func (a *App) settingsConfigDir() (string, error) {
	if a.configDir != "" {
		return a.configDir, nil
	}
	return pathutil.LateConfigDir()
}

func (a *App) showSettingsDialog() {
	cfgDir, err := a.settingsConfigDir()
	if err != nil {
		dialog.ShowError(err, a.window)
		return
	}

	cfg, loadErr := config.LoadConfigFromDir(cfgDir)
	if cfg == nil {
		fallback := config.Config{}
		cfg = &fallback
	}

	openAIBaseURLEntry := widget.NewEntry()
	openAIBaseURLEntry.SetText(cfg.OpenAIBaseURL)
	openAIAPIKeyEntry := widget.NewPasswordEntry()
	openAIAPIKeyEntry.SetText(cfg.OpenAIAPIKey)
	openAIModelEntry := widget.NewEntry()
	openAIModelEntry.SetText(cfg.OpenAIModel)

	subagentBaseURLEntry := widget.NewEntry()
	subagentBaseURLEntry.SetText(cfg.SubagentBaseURL)
	subagentAPIKeyEntry := widget.NewPasswordEntry()
	subagentAPIKeyEntry.SetText(cfg.SubagentAPIKey)
	subagentModelEntry := widget.NewEntry()
	subagentModelEntry.SetText(cfg.SubagentModel)

	auditorBaseURLEntry := widget.NewEntry()
	auditorBaseURLEntry.SetText(cfg.AuditorBaseURL)
	auditorAPIKeyEntry := widget.NewPasswordEntry()
	auditorAPIKeyEntry.SetText(cfg.AuditorAPIKey)
	auditorModelEntry := widget.NewEntry()
	auditorModelEntry.SetText(cfg.AuditorModel)

	skillsDirEntry := widget.NewEntry()
	skillsDirEntry.SetText(cfg.SkillsDir)

	form := widget.NewForm(
		widget.NewFormItem("OpenAI Base URL", openAIBaseURLEntry),
		widget.NewFormItem("OpenAI API Key", openAIAPIKeyEntry),
		widget.NewFormItem("OpenAI Model", openAIModelEntry),
		widget.NewFormItem("Subagent Base URL", subagentBaseURLEntry),
		widget.NewFormItem("Subagent API Key", subagentAPIKeyEntry),
		widget.NewFormItem("Subagent Model", subagentModelEntry),
		widget.NewFormItem("Auditor Base URL", auditorBaseURLEntry),
		widget.NewFormItem("Auditor API Key", auditorAPIKeyEntry),
		widget.NewFormItem("Auditor Model", auditorModelEntry),
		widget.NewFormItem("Skills Directory", skillsDirEntry),
	)

	pathLabel := widget.NewLabel("Config file: " + filepath.Join(cfgDir, "config.json"))
	pathLabel.Wrapping = fyne.TextWrapWord

	content := container.NewVBox(pathLabel)
	if loadErr != nil {
		warn := widget.NewLabel("Warning: existing config had issues; defaults were loaded. Saving will rewrite the file.")
		warn.Wrapping = fyne.TextWrapWord
		content.Add(warn)
	}
	content.Add(form)

	scroll := container.NewVScroll(content)
	scroll.SetMinSize(fyne.NewSize(760, 520))

	dialog.ShowCustomConfirm("Settings", "Save", "Cancel", scroll, func(ok bool) {
		if !ok {
			return
		}

		updated := *cfg
		updated.OpenAIBaseURL = strings.TrimSpace(openAIBaseURLEntry.Text)
		updated.OpenAIAPIKey = strings.TrimSpace(openAIAPIKeyEntry.Text)
		updated.OpenAIModel = strings.TrimSpace(openAIModelEntry.Text)
		updated.SubagentBaseURL = strings.TrimSpace(subagentBaseURLEntry.Text)
		updated.SubagentAPIKey = strings.TrimSpace(subagentAPIKeyEntry.Text)
		updated.SubagentModel = strings.TrimSpace(subagentModelEntry.Text)
		updated.AuditorBaseURL = strings.TrimSpace(auditorBaseURLEntry.Text)
		updated.AuditorAPIKey = strings.TrimSpace(auditorAPIKeyEntry.Text)
		updated.AuditorModel = strings.TrimSpace(auditorModelEntry.Text)
		updated.SkillsDir = strings.TrimSpace(skillsDirEntry.Text)

		if err := config.SaveConfigFromDir(cfgDir, &updated); err != nil {
			dialog.ShowError(err, a.window)
			return
		}
		dialog.ShowInformation("Settings", "Configuration saved to config.json", a.window)
	}, a.window)
}
