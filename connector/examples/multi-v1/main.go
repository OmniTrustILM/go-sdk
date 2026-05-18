// Combined Discovery + Authority v2 connector. Demonstrates that multiple
// v1-family providers can be registered on a single shared.Connector
// without route collisions or info-listing conflicts.
//
// Run:
//
//	go run ./connector/examples/multi-v1
//
// Both function groups appear in /v1 listSupportedFunctions:
//
//	curl -s http://localhost:8080/v1 | jq '.[].functionGroupCode'
//	# "discoveryProvider"
//	# "authorityProvider"
package main

import (
	"context"
	"log/slog"
	"net/http"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v2"
	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-multi-v1"
	connectorName    = "Example Combined Discovery + Authority Connector"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	logger := newLogger(envOr("LOG_LEVEL", "info"))

	discoStore := NewDiscoveryStore()
	authStore := NewAuthorityStore()

	discoHandler, err := discovery.NewHandler(discoStore,
		discovery.Base(handlerbase.WithStrictDecode(envBool("STRICT_DECODE"))),
		discovery.WithKinds("localhost-default"),
	)
	if err != nil {
		logger.Error("build discovery handler", "err", err)
		os.Exit(1)
	}

	authHandler, err := authority.NewHandler(authStore,
		authority.Base(handlerbase.WithStrictDecode(envBool("STRICT_DECODE"))),
		authority.WithKinds("placeholder-ca"),
	)
	if err != nil {
		logger.Error("build authority handler", "err", err)
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
			Description: "Reference connector hosting both Discovery v1 and Authority v2 on the same mux.",
		}),
		shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{
			Version: connectorVersion,
			Commit:  commitSHA,
			Runtime: runtime.Version(),
		})),
		shared.Register(discoHandler),
		shared.Register(authHandler),
		// Info-only entries so /v1 info lists the shared endpoints under
		// each function group, matching the convention from example 1 in
		// the CZERTAINLY docs.
		shared.WithExtraEndpoints(
			shared.ExtraEndpoint{FunctionGroupCode: discovery.FunctionGroupCode, Method: http.MethodGet, Context: "/v1/health", Name: "checkHealth"},
			shared.ExtraEndpoint{FunctionGroupCode: discovery.FunctionGroupCode, Method: http.MethodGet, Context: "/v1", Name: "listSupportedFunctions"},
			shared.ExtraEndpoint{FunctionGroupCode: authority.FunctionGroupCode, Method: http.MethodGet, Context: "/v1/health", Name: "checkHealth"},
			shared.ExtraEndpoint{FunctionGroupCode: authority.FunctionGroupCode, Method: http.MethodGet, Context: "/v1", Name: "listSupportedFunctions"},
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
