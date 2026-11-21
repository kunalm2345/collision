package proxy

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"net"
	"net/http"
	"strings"
	"time"

	"github.com/kunalm2345/collision/gateway/internal/antispam"
	"github.com/kunalm2345/collision/gateway/internal/auth"
	"github.com/kunalm2345/collision/gateway/internal/config"
)

type Server struct {
	cfg    config.Config
	guard  *antispam.Guard
	client *http.Client
	mux    *http.ServeMux
}

func NewServer(cfg config.Config) *Server {
	guard := antispam.NewGuard(antispam.Options{
		IPRPM:                  cfg.MaxRequestsPerMinIP,
		UserRPM:                cfg.MaxRequestsPerMinUser,
		DefaultMaxTurns:        cfg.MaxTurnsPerRun,
		MaxConcurrentPerUser:   cfg.MaxConcurrentPerUser,
		BlockedEmailDomains:    cfg.BlockedEmailDomains,
		AllowedPromptHashes:    cfg.AllowedPromptHashes,
		AllowedModels:          cfg.AllowedModels,
		RequirePromptHashMatch: cfg.RequirePromptHashMatch,
	})

	s := &Server{
		cfg:    cfg,
		guard:  guard,
		client: &http.Client{Timeout: 5 * time.Minute},
		mux:    http.NewServeMux(),
	}

	s.mux.HandleFunc("GET /healthz", s.handleHealth)
	s.mux.HandleFunc("POST /v1/tokens", s.handleMintToken)
	s.mux.HandleFunc("POST /v1/messages", s.handleProxy("anthropic"))
	s.mux.HandleFunc("POST /v1/responses", s.handleProxy("openai"))
	s.mux.HandleFunc("POST /v1/chat/completions", s.handleProxy("auto"))

	return s
}

func (s *Server) ServeHTTP(w http.ResponseWriter, r *http.Request) {
	s.mux.ServeHTTP(w, r)
}

func (s *Server) handleHealth(w http.ResponseWriter, _ *http.Request) {
	writeJSON(w, http.StatusOK, map[string]any{
		"ok": true,
		"providers": map[string]bool{
			"openai":     s.cfg.OpenAIAPIKey != "",
			"anthropic":  s.cfg.AnthropicAPIKey != "",
			"openrouter": s.cfg.OpenRouterAPIKey != "",
		},
	})
}

type mintTokenRequest struct {
	RunID    string `json:"run_id"`
	UserID   string `json:"user_id"`
	Email    string `json:"email"`
	VendorID string `json:"vendor_id"`
	MaxTurns int    `json:"max_turns"`
}

func (s *Server) handleMintToken(w http.ResponseWriter, r *http.Request) {
	if s.cfg.AdminAPIKey != "" {
		if bearerToken(r) != s.cfg.AdminAPIKey {
			writeError(w, http.StatusUnauthorized, "invalid admin key")
			return
		}
	}

	var req mintTokenRequest
	if err := json.NewDecoder(io.LimitReader(r.Body, 16*1024)).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "invalid json body")
		return
	}

	if err := s.guard.CheckEmail(req.Email); err != nil {
		writeError(w, http.StatusForbidden, err.Error())
		return
	}

	if req.MaxTurns <= 0 || req.MaxTurns > s.cfg.MaxTurnsPerRun {
		req.MaxTurns = s.cfg.MaxTurnsPerRun
	}

	exp := time.Now().Add(s.cfg.DefaultTokenTTL).Unix()
	tok, err := auth.MintToken(auth.RunClaims{
		RunID:    req.RunID,
		UserID:   req.UserID,
		VendorID: req.VendorID,
		MaxTurns: req.MaxTurns,
		Exp:      exp,
	}, s.cfg.TokenSigningSecret)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"token":      tok,
		"expires_at": exp,
		"max_turns":  req.MaxTurns,
	})
}

func (s *Server) handleProxy(defaultProvider string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tok := bearerToken(r)
		if tok == "" {
			tok = r.Header.Get("x-api-key")
		}
		claims, err := auth.VerifyToken(tok, s.cfg.TokenSigningSecret)
		if err != nil {
			writeError(w, http.StatusUnauthorized, err.Error())
			return
		}

		if err := s.guard.CheckPromptHash(r.Header.Get("X-Collision-Prompt-Hash")); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		bodyBytes, err := io.ReadAll(io.LimitReader(r.Body, 4*1024*1024))
		if err != nil {
			writeError(w, http.StatusBadRequest, "failed to read request body")
			return
		}

		var peek struct {
			Model string `json:"model"`
		}
		_ = json.Unmarshal(bodyBytes, &peek)

		if err := s.guard.CheckModel(peek.Model); err != nil {
			writeError(w, http.StatusForbidden, err.Error())
			return
		}

		release, err := s.guard.Acquire(clientIP(r), claims.UserID, claims.RunID, claims.MaxTurns)
		if err != nil {
			status := http.StatusTooManyRequests
			if errors.Is(err, antispam.ErrTurnBudget) {
				status = http.StatusPaymentRequired
			}
			writeError(w, status, err.Error())
			return
		}
		defer release()

		provider := resolveProvider(defaultProvider, r.Header.Get("X-Collision-Provider"), peek.Model, s.cfg)
		upstreamReq, err := s.buildUpstreamRequest(r, provider, bodyBytes)
		if err != nil {
			writeError(w, http.StatusBadGateway, err.Error())
			return
		}

		resp, err := s.client.Do(upstreamReq)
		if err != nil {
			writeError(w, http.StatusBadGateway, "upstream request failed")
			return
		}
		defer resp.Body.Close()

		for k, vals := range resp.Header {
			for _, v := range vals {
				w.Header().Add(k, v)
			}
		}
		w.WriteHeader(resp.StatusCode)

		flusher, canFlush := w.(http.Flusher)
		buf := make([]byte, 32*1024)
		for {
			n, readErr := resp.Body.Read(buf)
			if n > 0 {
				_, _ = w.Write(buf[:n])
				if canFlush {
					flusher.Flush()
				}
			}
			if readErr != nil {
				break
			}
		}
	}
}

func resolveProvider(defaultProvider, headerProvider, model string, cfg config.Config) string {
	if headerProvider != "" {
		return strings.ToLower(headerProvider)
	}
	if defaultProvider != "auto" {
		return defaultProvider
	}
	if strings.HasPrefix(model, "openrouter/") || (cfg.OpenRouterAPIKey != "" && cfg.OpenAIAPIKey == "") {
		return "openrouter"
	}
	return "openai"
}

func (s *Server) buildUpstreamRequest(r *http.Request, provider string, body []byte) (*http.Request, error) {
	var targetURL string
	switch provider {
	case "anthropic":
		if s.cfg.AnthropicAPIKey == "" {
			return nil, errors.New("ANTHROPIC_API_KEY not configured on gateway")
		}
		targetURL = strings.TrimRight(s.cfg.AnthropicBaseURL, "/") + "/v1/messages"
	case "openrouter":
		if s.cfg.OpenRouterAPIKey == "" {
			return nil, errors.New("OPENROUTER_API_KEY not configured on gateway")
		}
		targetURL = strings.TrimRight(s.cfg.OpenRouterBaseURL, "/") + "/v1/chat/completions"
	default:
		if s.cfg.OpenAIAPIKey == "" {
			return nil, errors.New("OPENAI_API_KEY not configured on gateway")
		}
		targetURL = strings.TrimRight(s.cfg.OpenAIBaseURL, "/") + r.URL.Path
	}

	req, err := http.NewRequestWithContext(r.Context(), http.MethodPost, targetURL, bytes.NewReader(body))
	if err != nil {
		return nil, err
	}
	req.Header.Set("Content-Type", "application/json")
	if accept := r.Header.Get("Accept"); accept != "" {
		req.Header.Set("Accept", accept)
	}

	switch provider {
	case "anthropic":
		req.Header.Set("x-api-key", s.cfg.AnthropicAPIKey)
		version := r.Header.Get("anthropic-version")
		if version == "" {
			version = "2023-06-01"
		}
		req.Header.Set("anthropic-version", version)
	case "openrouter":
		req.Header.Set("Authorization", "Bearer "+s.cfg.OpenRouterAPIKey)
		req.Header.Set("X-Title", "Collision Gateway")
	default:
		req.Header.Set("Authorization", "Bearer "+s.cfg.OpenAIAPIKey)
	}

	return req, nil
}

func bearerToken(r *http.Request) string {
	authHeader := r.Header.Get("Authorization")
	if strings.HasPrefix(strings.ToLower(authHeader), "bearer ") {
		return strings.TrimSpace(authHeader[7:])
	}
	return ""
}

func clientIP(r *http.Request) string {
	if xff := r.Header.Get("X-Forwarded-For"); xff != "" {
		return strings.TrimSpace(strings.Split(xff, ",")[0])
	}
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err != nil {
		return r.RemoteAddr
	}
	return host
}

func writeJSON(w http.ResponseWriter, status int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, status int, msg string) {
	writeJSON(w, status, map[string]any{"error": msg})
}
