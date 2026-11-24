package config

import "testing"

func TestLoadFromEnvMaxTurnsDefaultAndOverride(t *testing.T) {
	t.Setenv("COLLISION_MAX_TURNS_PER_RUN", "")
	cfg := LoadFromEnv()
	if cfg.MaxTurnsPerRun != 100 {
		t.Fatalf("expected default MaxTurnsPerRun=100, got %d", cfg.MaxTurnsPerRun)
	}

	t.Setenv("COLLISION_MAX_TURNS_PER_RUN", "42")
	cfg = LoadFromEnv()
	if cfg.MaxTurnsPerRun != 42 {
		t.Fatalf("expected override MaxTurnsPerRun=42, got %d", cfg.MaxTurnsPerRun)
	}

	t.Setenv("COLLISION_MAX_TURNS_PER_RUN", "invalid")
	cfg = LoadFromEnv()
	if cfg.MaxTurnsPerRun != 100 {
		t.Fatalf("expected invalid value to fall back to 100, got %d", cfg.MaxTurnsPerRun)
	}
}
