package proxy_test

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
	"time"

	"github.com/kunalm2345/collision/gateway/internal/config"
	"github.com/kunalm2345/collision/gateway/internal/proxy"
)

func TestGatewayMintAndProxyWithAntiSpam(t *testing.T) {
	upstream := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("x-api-key") != "upstream-anth-key" {
			t.Errorf("expected upstream anthropic key, got %q", r.Header.Get("x-api-key"))
		}
		w.Header().Set("Content-Type", "text/event-stream")
		_, _ = w.Write([]byte("data: {\"ok\":true}\n\n"))
	}))
	defer upstream.Close()

	cfg := config.Config{
		AnthropicAPIKey:        "upstream-anth-key",
		AnthropicBaseURL:       upstream.URL,
		TokenSigningSecret:     "test-secret",
		AdminAPIKey:            "admin-secret",
		DefaultTokenTTL:        5 * time.Minute,
		MaxTurnsPerRun:         2,
		MaxRequestsPerMinIP:    10,
		MaxRequestsPerMinUser:  10,
		MaxConcurrentPerUser:   2,
		AllowedModels:          map[string]bool{"claude-sonnet-4-5": true},
		AllowedPromptHashes:    map[string]bool{"hash-ok": true},
		BlockedEmailDomains:    map[string]bool{"mailinator.com": true},
		RequirePromptHashMatch: true,
	}

	gw := proxy.NewServer(cfg)

	// 1. Disposable email is rejected
	badMint := httptest.NewRequest(http.MethodPost, "/v1/tokens", bytes.NewBufferString(`{"run_id":"r1","user_id":"u1","email":"spam@mailinator.com"}`))
	badMint.Header.Set("Authorization", "Bearer admin-secret")
	rec := httptest.NewRecorder()
	gw.ServeHTTP(rec, badMint)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for disposable email, got %d", rec.Code)
	}

	// 2. Valid mint succeeds
	goodMint := httptest.NewRequest(http.MethodPost, "/v1/tokens", bytes.NewBufferString(`{"run_id":"r1","user_id":"u1","email":"dev@company.com","vendor_id":"acme"}`))
	goodMint.Header.Set("Authorization", "Bearer admin-secret")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, goodMint)
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200 on token mint, got %d: %s", rec.Code, rec.Body.String())
	}
	var mintResp struct {
		Token string `json:"token"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &mintResp); err != nil || mintResp.Token == "" {
		t.Fatalf("expected token in response, got %s", rec.Body.String())
	}

	// 3. Wrong prompt hash is rejected
	badHashReq := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewBufferString(`{"model":"claude-sonnet-4-5"}`))
	badHashReq.Header.Set("Authorization", "Bearer "+mintResp.Token)
	badHashReq.Header.Set("X-Collision-Prompt-Hash", "tampered")
	rec = httptest.NewRecorder()
	gw.ServeHTTP(rec, badHashReq)
	if rec.Code != http.StatusForbidden {
		t.Fatalf("expected 403 for unapproved prompt hash, got %d", rec.Code)
	}

	// 4. Two valid requests succeed, 3rd hits per-run turn budget (MaxTurnsPerRun=2)
	for i := 1; i <= 3; i++ {
		req := httptest.NewRequest(http.MethodPost, "/v1/messages", bytes.NewBufferString(`{"model":"claude-sonnet-4-5"}`))
		req.Header.Set("Authorization", "Bearer "+mintResp.Token)
		req.Header.Set("X-Collision-Prompt-Hash", "hash-ok")
		rec = httptest.NewRecorder()
		gw.ServeHTTP(rec, req)
		if i <= 2 && rec.Code != http.StatusOK {
			t.Fatalf("turn %d expected 200, got %d: %s", i, rec.Code, rec.Body.String())
		}
		if i == 3 && rec.Code != http.StatusPaymentRequired {
			t.Fatalf("turn 3 expected 402 turn budget exceeded, got %d", rec.Code)
		}
	}
}
