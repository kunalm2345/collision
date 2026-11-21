package antispam

import (
	"errors"
	"net/mail"
	"strings"
	"sync"
	"time"
)

var (
	ErrRateLimited       = errors.New("rate limit exceeded")
	ErrTurnBudget        = errors.New("per-run turn budget exceeded")
	ErrConcurrency       = errors.New("too many concurrent requests for user")
	ErrDisposableEmail   = errors.New("disposable email domain is blocked")
	ErrPromptNotAdmitted = errors.New("system prompt hash is not in gateway allowlist")
	ErrModelNotAllowed   = errors.New("requested model is not allowed")
)

type bucket struct {
	tokens     float64
	lastRefill time.Time
}

type Guard struct {
	mu                     sync.Mutex
	ipBuckets              map[string]*bucket
	userBuckets            map[string]*bucket
	runTurns               map[string]int
	userActive             map[string]int
	ipRPM                  int
	userRPM                int
	defaultMaxTurns        int
	maxConcurrentPerUser   int
	blockedEmailDomains    map[string]bool
	allowedPromptHashes    map[string]bool
	allowedModels          map[string]bool
	requirePromptHashMatch bool
}

type Options struct {
	IPRPM                  int
	UserRPM                int
	DefaultMaxTurns        int
	MaxConcurrentPerUser   int
	BlockedEmailDomains    map[string]bool
	AllowedPromptHashes    map[string]bool
	AllowedModels          map[string]bool
	RequirePromptHashMatch bool
}

func NewGuard(opts Options) *Guard {
	if opts.IPRPM <= 0 {
		opts.IPRPM = 60
	}
	if opts.UserRPM <= 0 {
		opts.UserRPM = 30
	}
	if opts.DefaultMaxTurns <= 0 {
		opts.DefaultMaxTurns = 40
	}
	if opts.MaxConcurrentPerUser <= 0 {
		opts.MaxConcurrentPerUser = 2
	}
	return &Guard{
		ipBuckets:              make(map[string]*bucket),
		userBuckets:            make(map[string]*bucket),
		runTurns:               make(map[string]int),
		userActive:             make(map[string]int),
		ipRPM:                  opts.IPRPM,
		userRPM:                opts.UserRPM,
		defaultMaxTurns:        opts.DefaultMaxTurns,
		maxConcurrentPerUser:   opts.MaxConcurrentPerUser,
		blockedEmailDomains:    opts.BlockedEmailDomains,
		allowedPromptHashes:    opts.AllowedPromptHashes,
		allowedModels:          opts.AllowedModels,
		requirePromptHashMatch: opts.RequirePromptHashMatch,
	}
}

func (g *Guard) CheckEmail(email string) error {
	if strings.TrimSpace(email) == "" {
		return nil
	}
	addr, err := mail.ParseAddress(email)
	if err != nil {
		return ErrDisposableEmail
	}
	parts := strings.Split(strings.ToLower(addr.Address), "@")
	if len(parts) != 2 {
		return ErrDisposableEmail
	}
	if g.blockedEmailDomains[parts[1]] {
		return ErrDisposableEmail
	}
	return nil
}

func (g *Guard) CheckModel(model string) error {
	if len(g.allowedModels) == 0 || model == "" {
		return nil
	}
	if !g.allowedModels[model] {
		return ErrModelNotAllowed
	}
	return nil
}

func (g *Guard) CheckPromptHash(hash string) error {
	if !g.requirePromptHashMatch && len(g.allowedPromptHashes) == 0 {
		return nil
	}
	if hash == "" || !g.allowedPromptHashes[hash] {
		return ErrPromptNotAdmitted
	}
	return nil
}

// Acquire checks IP & user rate limits, concurrency, and per-run turn budget.
// Caller must invoke the returned release function when the upstream request finishes.
func (g *Guard) Acquire(ip, userID, runID string, maxTurns int) (func(), error) {
	g.mu.Lock()
	defer g.mu.Unlock()

	now := time.Now()
	if !consumeToken(g.ipBuckets, ip, g.ipRPM, now) {
		return nil, ErrRateLimited
	}
	if !consumeToken(g.userBuckets, userID, g.userRPM, now) {
		return nil, ErrRateLimited
	}
	if g.userActive[userID] >= g.maxConcurrentPerUser {
		return nil, ErrConcurrency
	}

	limit := maxTurns
	if limit <= 0 {
		limit = g.defaultMaxTurns
	}
	if g.runTurns[runID] >= limit {
		return nil, ErrTurnBudget
	}

	g.runTurns[runID]++
	g.userActive[userID]++

	released := false
	return func() {
		g.mu.Lock()
		defer g.mu.Unlock()
		if released {
			return
		}
		released = true
		if g.userActive[userID] > 0 {
			g.userActive[userID]--
		}
	}, nil
}

func consumeToken(store map[string]*bucket, key string, rpm int, now time.Time) bool {
	b, ok := store[key]
	if !ok {
		store[key] = &bucket{tokens: float64(rpm - 1), lastRefill: now}
		return true
	}
	elapsed := now.Sub(b.lastRefill).Seconds()
	refill := elapsed * (float64(rpm) / 60.0)
	b.tokens = minFloat(float64(rpm), b.tokens+refill)
	b.lastRefill = now
	if b.tokens < 1.0 {
		return false
	}
	b.tokens -= 1.0
	return true
}

func minFloat(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
