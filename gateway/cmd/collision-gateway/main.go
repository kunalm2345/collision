package main

import (
	"log"
	"net/http"
	"time"

	"github.com/kunalm2345/collision/gateway/internal/config"
	"github.com/kunalm2345/collision/gateway/internal/proxy"
)

func main() {
	cfg := config.LoadFromEnv()
	srv := &http.Server{
		Addr:              cfg.ListenAddr,
		Handler:           proxy.NewServer(cfg),
		ReadHeaderTimeout: 15 * time.Second,
	}

	log.Printf("collision-gateway listening on %s", cfg.ListenAddr)
	if err := srv.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("gateway error: %v", err)
	}
}
