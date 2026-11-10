// Reference Discovery Provider v2 connector. Poll status to produce three
// genuine X.509 certificate fixtures; drain results with sequence cursors.
// Run with go run ./connector/examples/disco-v2. ADDR defaults to :8080;
// LOG_LEVEL accepts debug/info/warn/error; STRICT_DECODE accepts Go booleans.
// All state is in memory and lost on restart. Not for production use.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-disco-v2"
	connectorVersion = "0.1.0"
)

func main() {
	var level slog.Level
	if e := level.UnmarshalText([]byte(envOr("LOG_LEVEL", "INFO"))); e != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(shared.NewLogHandler(os.Stdout, &shared.LogHandlerOptions{Level: level, ServiceName: connectorID, ServiceVersion: connectorVersion}))
	store, e := NewStore()
	if e != nil {
		logger.Error("create discovery fixtures", "err", e)
		os.Exit(1)
	}
	strict, _ := strconv.ParseBool(os.Getenv("STRICT_DECODE"))
	handler, e := discovery.NewHandler(store, discovery.Base(handlerbase.WithStrictDecode(strict), handlerbase.WithFeatures("discoveryStopResume")), discovery.WithAttributeDefinitions(store))
	if e != nil {
		logger.Error("build discovery handler", "err", e)
		os.Exit(1)
	}
	c, e := shared.New(shared.WithLogger(logger), shared.WithAddr(envOr("ADDR", ":8080")), shared.WithInfo(shared.Info{ID: connectorID, Name: "Example Discovery Provider v2", Version: connectorVersion, Description: "Three in-memory certificate fixtures. Not for production."}), shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{Version: connectorVersion, Commit: "dev", Runtime: runtime.Version()})), shared.Register(handler))
	if e != nil {
		logger.Error("build connector", "err", e)
		os.Exit(1)
	}
	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if e = c.Run(ctx); e != nil {
		logger.Error("connector run", "err", e)
		os.Exit(1)
	}
}
func envOr(key, fallback string) string {
	if value := os.Getenv(key); value != "" {
		return value
	}
	return fallback
}
