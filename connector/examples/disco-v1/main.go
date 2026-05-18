// Reference Discovery Provider connector. Implements
// connector/provider/discovery/v1 with an in-memory map keyed by discovery
// uuid; "discovery work" is simulated by a 1–10 second random sleep.
//
// Spec uses /v1 info + /v1/health. The /v1 info response advertises every
// route under the discoveryProvider function group, including the shared
// checkHealth and listSupportedFunctions endpoints (added via
// WithExtraEndpoints with nil Handler so shared still owns the routes but
// they show up in the info listing).
//
// Run:
//
//	go run ./connector/examples/disco-v1
//
// Configure with environment variables:
//
//	ADDR=":8080"        listen address
//	LOG_LEVEL=info      debug | info | warn | error
//	STRICT_DECODE=1     reject unknown JSON fields
//	DISCOVERY_KIND=...  comma-separated discovery kinds (default "localhost-default")
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	connectorID      = "example-disco-v1"
	connectorName    = "Example In-Memory Discovery Provider"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	logger := newLogger(envOr("LOG_LEVEL", "info"))

	kinds := strings.Split(envOr("DISCOVERY_KIND", "localhost-default"), ",")
	for i := range kinds {
		kinds[i] = strings.TrimSpace(kinds[i])
	}

	store := NewStore()
	handler, err := discovery.NewHandler(store,
		discovery.WithStrictDecode(env("STRICT_DECODE") != ""),
		discovery.WithKinds(kinds...),
	)
	if err != nil {
		logger.Error("build discovery handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(envOr("ADDR", ":8080")),
		shared.WithInfoVersion(shared.VersionV1),
		shared.WithHealthVersion(shared.VersionV1),
		shared.WithErrorRenderer(discovery.WriteError),
		shared.WithInfo(shared.Info{
			ID:          connectorID,
			Name:        connectorName,
			Version:     connectorVersion,
			Description: "Reference discovery connector with an in-memory store. Not for production.",
		}),
		shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{
			Version: connectorVersion,
			Commit:  commitSHA,
			Runtime: runtime.Version(),
		})),
		shared.Register(handler),
		// Info-only entries (Handler nil) for endpoints owned by shared so
		// the /v1 info listing matches the canonical convention.
		shared.WithExtraEndpoints(
			shared.ExtraEndpoint{
				FunctionGroupCode: discovery.FunctionGroupCode,
				Method:            http.MethodGet,
				Context:           "/v1/health",
				Name:              "checkHealth",
			},
			shared.ExtraEndpoint{
				FunctionGroupCode: discovery.FunctionGroupCode,
				Method:            http.MethodGet,
				Context:           "/v1",
				Name:              "listSupportedFunctions",
			},
		),
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
