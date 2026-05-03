package orchestrator

import (
	"testing"
	"time"
)

func TestCalculateTurns(t *testing.T) {
	meta := ComplexityMeta{RouteCount: 10, HotspotCount: 4}
	got := CalculateTurns(meta, 500)
	want := 50 + (5 * 10) + (10 * 4)
	if got != want {
		t.Fatalf("CalculateTurns() = %d, want %d", got, want)
	}
}

func TestCalculateTurns_Capped(t *testing.T) {
	meta := ComplexityMeta{RouteCount: 200, HotspotCount: 100}
	got := CalculateTurns(meta, 500)
	if got != 500 {
		t.Fatalf("CalculateTurns() = %d, want cap 500", got)
	}
}

func TestCalculateTurns_LanguageMultiplierCpp(t *testing.T) {
	// C++ multiplier 1.5x: base 100 → 150
	meta := ComplexityMeta{RouteCount: 10, HotspotCount: 4, PrimaryLanguage: "c++"}
	base := 50 + (5 * 10) + (10 * 4) // 140
	want := int(float64(base) * 1.5)  // 210
	got := CalculateTurns(meta, 500)
	if got != want {
		t.Fatalf("CalculateTurns(c++) = %d, want %d", got, want)
	}
}

func TestCalculateTurns_LanguageMultiplierPython(t *testing.T) {
	// Python multiplier 0.8x
	meta := ComplexityMeta{RouteCount: 10, HotspotCount: 4, PrimaryLanguage: "python"}
	base := 50 + (5 * 10) + (10 * 4) // 140
	want := int(float64(base) * 0.8)  // 112
	got := CalculateTurns(meta, 500)
	if got != want {
		t.Fatalf("CalculateTurns(python) = %d, want %d", got, want)
	}
}

func TestCalculateTurns_UnknownLanguage(t *testing.T) {
	// Unknown language defaults to 1.0x multiplier
	meta := ComplexityMeta{RouteCount: 10, HotspotCount: 4, PrimaryLanguage: "cobol"}
	want := 50 + (5 * 10) + (10 * 4)
	got := CalculateTurns(meta, 500)
	if got != want {
		t.Fatalf("CalculateTurns(cobol) = %d, want %d", got, want)
	}
}

func TestLanguageMultiplier(t *testing.T) {
	tests := []struct {
		lang string
		want float64
	}{
		{"c", 1.5}, {"cpp", 1.5}, {"c++", 1.5}, {"C++", 1.5},
		{"rust", 1.3},
		{"go", 1.0}, {"java", 1.0}, {"Go", 1.0},
		{"python", 0.8}, {"javascript", 0.8}, {"php", 0.8},
		{"unknown", 1.0},
	}
	for _, tt := range tests {
		got := LanguageMultiplier(tt.lang)
		if got != tt.want {
			t.Errorf("LanguageMultiplier(%q) = %v, want %v", tt.lang, got, tt.want)
		}
	}
}

func TestCalculateTimeout(t *testing.T) {
	meta := ComplexityMeta{FileCount: 120, HotspotCount: 7}
	got := CalculateTimeout(meta, 60*time.Minute)
	want := 5*time.Minute + (120 * 2 * time.Second) + (7 * 5 * time.Second)
	if got != want {
		t.Fatalf("CalculateTimeout() = %s, want %s", got, want)
	}
}

func TestCalculateTimeout_Capped(t *testing.T) {
	meta := ComplexityMeta{FileCount: 50000, HotspotCount: 5000}
	got := CalculateTimeout(meta, 60*time.Minute)
	if got != 60*time.Minute {
		t.Fatalf("CalculateTimeout() = %s, want cap %s", got, 60*time.Minute)
	}
}

