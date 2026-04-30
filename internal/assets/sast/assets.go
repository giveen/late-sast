package sast

import (
	"embed"
)

//go:embed SKILL.md references/*.md
var SASTSkillFS embed.FS
