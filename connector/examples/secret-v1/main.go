// Reference Secret Provider connector. Implements connector/provider/secret/v1
// with an in-memory, mutex-guarded map keyed by secret name. Demonstrates
// wiring with connector/shared.
//
// Run:
//
//	go run ./connector/examples/secret-v1
//
// Configure with environment variables:
//
//	ADDR=":8080"      listen address
//	LOG_LEVEL=info    debug | info | warn | error
//	STRICT_DECODE=1   reject unknown JSON fields
//
// The connector exposes /v2/health, /v2/health/{readiness,liveness},
// /v2/info, /v1/metrics, and the secret v1 routes under /v1/secretProvider.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"syscall"

	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	connectorID      = "example-secret-v1"
	connectorName    = "Example In-Memory Secret Provider"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	logger := newLogger(envOr("LOG_LEVEL", "info"))

	store := NewStore()
	handler, err := secret.NewHandler(store,
		secret.WithStrictDecode(env("STRICT_DECODE") != ""),
		secret.WithVaultProfileAttributes(&Attrs{}),
	)
	if err != nil {
		logger.Error("build secret handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(envOr("ADDR", ":8080")),
		shared.WithInfo(shared.Info{
			ID:          connectorID,
			Name:        connectorName,
			Version:     connectorVersion,
			Description: "Reference connector backed by an in-memory map. Not for production.",
		}),
		shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{
			Version: connectorVersion,
			Commit:  commitSHA,
			Runtime: runtime.Version(),
		})),
		shared.Register(handler),
	)
	if err != nil {
		logger.Error("build connector", "err", err)
		os.Exit(1)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()

	if err := c.Run(ctx); err != nil {
		logger.Error("connector run", "err", err)
		os.Exit(1)
	}
}

func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch level {
	case "debug":
		lvl = slog.LevelDebug
	case "warn":
		lvl = slog.LevelWarn
	case "error":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}

func env(key string) string { return os.Getenv(key) }

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}
