// Reference Cryptography Provider v2 connector. Implements
// connector/provider/cryptography/v2 with an in-memory, mutex-guarded key
// store whose signatures and ciphertext are deterministic placeholders (see
// store.go); scope is wiring verification, not security.
//
// Run:
//
//	go run ./connector/examples/cryptography-v2
//
// Configure with environment variables:
//
//	APP_ADDR            listen address          default ":8080"
//	APP_LOG_LEVEL       log level               default INFO   (DEBUG|INFO|WARN|ERROR)
//	APP_ASYNC_DELAY     async operation delay   default 500ms  (time.ParseDuration syntax)
//
// The connector exposes /v2/health, /v2/health/{readiness,liveness}, /v2/info,
// /v1/metrics, and all 24 Cryptography Provider v2 routes under
// /v2/cryptographyProvider. It registers AsyncKeyProvider and
// AsyncSignProvider and advertises the "asynchronous" feature flag, which
// Core requires before routing asynchronous operations here.
//
// Unknown JSON properties always answer 400: every Cryptography Provider v2
// request DTO disallows them unconditionally.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-cryptography-v2"
	connectorName    = "Example In-Memory Cryptography Provider v2"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	logger := newLogger(envOr("APP_LOG_LEVEL", "INFO"))

	store := NewStore(envDuration("APP_ASYNC_DELAY", defaultAsyncOperationDelay))

	handler, err := cryptography.NewHandler(store,
		cryptography.WithAsyncKeys(store),
		cryptography.WithAsyncSign(store),
		cryptography.WithTokenAttributes(store),
		cryptography.WithTokenProfileAttributes(store),
		cryptography.WithCreateKeyAttributes(store),
		cryptography.WithEncryptAttributes(store),
		cryptography.WithDecryptAttributes(store),
		cryptography.WithSignAttributes(store),
		cryptography.WithVerifyAttributes(store),
		cryptography.WithRandomDataAttributes(store),
		cryptography.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_ASYNCHRONOUS))),
	)
	if err != nil {
		logger.Error("build cryptography handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(envOr("APP_ADDR", ":8080")),
		shared.WithInfo(shared.Info{
			ID:          connectorID,
			Name:        connectorName,
			Version:     connectorVersion,
			Description: "Reference v2 cryptography connector backed by an in-memory key store. Not for production; performs no real cryptography.",
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

// newLogger builds a connector.log v1 slog logger at the supplied level.
// Matching is case-insensitive; unknown values yield INFO.
func newLogger(level string) *slog.Logger {
	var lvl slog.Level
	switch strings.ToUpper(level) {
	case "DEBUG":
		lvl = slog.LevelDebug
	case "WARN":
		lvl = slog.LevelWarn
	case "ERROR":
		lvl = slog.LevelError
	default:
		lvl = slog.LevelInfo
	}
	return slog.New(shared.NewLogHandler(os.Stdout, &shared.LogHandlerOptions{Level: lvl, ServiceName: connectorID, ServiceVersion: connectorVersion}))
}

// envOr returns the environment variable named key, or def if it is unset or empty.
func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

// envDuration returns the environment variable named key parsed with
// time.ParseDuration. Unset, empty or unparsable values yield def.
func envDuration(key string, def time.Duration) time.Duration {
	v, ok := os.LookupEnv(key)
	if !ok || v == "" {
		return def
	}
	d, err := time.ParseDuration(v)
	if err != nil {
		return def
	}
	return d
}
