package config

import (
	"os"
	"strconv"
	"strings"
	"time"
)

type Config struct {
	ListenAddr string

	// Upstream provider keys
	OpenAIAPIKey     string
	AnthropicAPIKey  string
	OpenRouterAPIKey string

	// Upstream base URLs (overridable for tests / self-hosted proxies)
	OpenAIBaseURL     string
	AnthropicBaseURL  string
	OpenRouterBaseURL string

	// Auth & signing
	TokenSigningSecret string
	AdminAPIKey        string
	DefaultTokenTTL    time.Duration

	// Anti-spam & budgets
	MaxTurnsPerRun         int
	MaxRequestsPerMinIP    int
	MaxRequestsPerMinUser  int
	MaxConcurrentPerUser   int
	AllowedModels          map[string]bool
	AllowedPromptHashes    map[string]bool
	BlockedEmailDomains    map[string]bool
	RequirePromptHashMatch bool
}

var defaultDisposableDomains = []string{
	"mailinator.com",
	"guerrillamail.com",
	"10minutemail.com",
	"tempmail.com",
	"yopmail.com",
	"sharklasers.com",
	"throwawaymail.com",
	"trashmail.com",
}

func LoadFromEnv() Config {
	cfg := Config{
		ListenAddr:             envOr("COLLISION_LISTEN_ADDR", ":8787"),
		OpenAIAPIKey:           os.Getenv("OPENAI_API_KEY"),
		AnthropicAPIKey:        os.Getenv("ANTHROPIC_API_KEY"),
		OpenRouterAPIKey:       os.Getenv("OPENROUTER_API_KEY"),
		OpenAIBaseURL:          envOr("OPENAI_BASE_URL", "https://api.openai.com"),
		AnthropicBaseURL:       envOr("ANTHROPIC_BASE_URL", "https://api.anthropic.com"),
		OpenRouterBaseURL:      envOr("OPENROUTER_BASE_URL", "https://openrouter.ai/api"),
		TokenSigningSecret:     envOr("COLLISION_TOKEN_SECRET", "dev-insecure-change-me"),
		AdminAPIKey:            os.Getenv("COLLISION_ADMIN_KEY"),
		DefaultTokenTTL:        time.Duration(envInt("COLLISION_TOKEN_TTL_SECONDS", 900)) * time.Second,
		MaxTurnsPerRun:         envInt("COLLISION_MAX_TURNS_PER_RUN", 40),
		MaxRequestsPerMinIP:    envInt("COLLISION_RATE_LIMIT_IP_RPM", 60),
		MaxRequestsPerMinUser:  envInt("COLLISION_RATE_LIMIT_USER_RPM", 30),
		MaxConcurrentPerUser:   envInt("COLLISION_MAX_CONCURRENT_USER", 2),
		AllowedModels:          parseSet(os.Getenv("COLLISION_ALLOWED_MODELS")),
		AllowedPromptHashes:    parseSet(os.Getenv("COLLISION_ALLOWED_PROMPT_HASHES")),
		BlockedEmailDomains:    parseSet(os.Getenv("COLLISION_BLOCKED_EMAIL_DOMAINS")),
		RequirePromptHashMatch: os.Getenv("COLLISION_REQUIRE_PROMPT_HASH") == "true",
	}

	for _, d := range defaultDisposableDomains {
		cfg.BlockedEmailDomains[d] = true
	}
	return cfg
}

func envOr(key, fallback string) string {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		return v
	}
	return fallback
}

func envInt(key string, fallback int) int {
	if v := strings.TrimSpace(os.Getenv(key)); v != "" {
		if n, err := strconv.Atoi(v); err == nil && n > 0 {
			return n
		}
	}
	return fallback
}

func parseSet(csv string) map[string]bool {
	out := make(map[string]bool)
	for _, item := range strings.Split(csv, ",") {
		trimmed := strings.TrimSpace(item)
		if trimmed != "" {
			out[trimmed] = true
		}
	}
	return out
}
