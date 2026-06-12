// Reference Entity Provider connector. Implements connector/provider/entity/v1
// with an in-memory entity store; location operations return placeholder
// payloads. Scope is wiring verification.
//
// Run:
//
//	go run ./connector/examples/entity-v1
//
// Configure with environment variables:
//
//	ADDR=":8080"        listen address
//	LOG_LEVEL=info      debug | info | warn | error
//	STRICT_DECODE=true  reject unknown JSON fields
//	ENTITY_KIND=...     comma-separated kinds (default "default")
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"strings"
	"syscall"

	entity "github.com/OmniTrustILM/go-sdk/connector/provider/entity/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-entity-v1"
	connectorName    = "Example Entity Provider"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	logger := newLogger(envOr("LOG_LEVEL", "info"))

	kinds := strings.Split(envOr("ENTITY_KIND", "default"), ",")
	for i := range kinds {
		kinds[i] = strings.TrimSpace(kinds[i])
	}

	store := NewStore()
	handler, err := entity.NewHandler(store,
		entity.Base(handlerbase.WithStrictDecode(envBool("STRICT_DECODE"))),
		entity.WithKinds(kinds...),
	)
	if err != nil {
		logger.Error("build entity handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(envOr("ADDR", ":8080")),
		shared.WithInfoVersion(shared.VersionV1),
		shared.WithHealthVersion(shared.VersionV1),
		shared.WithErrorRenderer(shared.WriteV1Error),
		shared.WithInfo(shared.Info{
			ID:          connectorID,
			Name:        connectorName,
			Version:     connectorVersion,
			Description: "Reference entity connector with an in-memory store. Not for production.",
		}),
		shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{
			Version: connectorVersion,
			Commit:  commitSHA,
			Runtime: runtime.Version(),
		})),
		shared.Register(handler),
		shared.WithExtraEndpoints(
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1/health", Name: "checkHealth"},
			shared.ExtraEndpoint{FunctionGroupCode: entity.FunctionGroupCode, Method: http.MethodGet, Context: "/v1", Name: "listSupportedFunctions"},
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
	return slog.New(shared.NewLogHandler(os.Stdout, &shared.LogHandlerOptions{Level: lvl, ServiceName: connectorID, ServiceVersion: connectorVersion}))
}

func envOr(key, def string) string {
	if v := os.Getenv(key); v != "" {
		return v
	}
	return def
}

func envBool(key string) bool {
	v := os.Getenv(key)
	if v == "" {
		return false
	}
	b, err := strconv.ParseBool(v)
	if err != nil {
		return false
	}
	return b
}
