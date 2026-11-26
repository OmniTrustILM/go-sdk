// Reference Content Signing Formatting Provider v1 connector for a demo
// signature family at the signed level: the data to be signed is a prefix
// attribute followed by the document's SHA-256. Run with
// go run ./connector/examples/contentsigning-v1. ADDR defaults to :8080;
// LOG_LEVEL accepts debug/info/warn/error; STRICT_DECODE accepts Go booleans.
// Not for production use.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strconv"
	"syscall"

	contentsigning "github.com/OmniTrustILM/go-sdk/connector/provider/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-contentsigning-v1"
	connectorVersion = "0.1.0"
)

func main() {
	var level slog.Level
	if level.UnmarshalText([]byte(envOr("LOG_LEVEL", "INFO"))) != nil {
		level = slog.LevelInfo
	}
	logger := slog.New(shared.NewLogHandler(os.Stdout, &shared.LogHandlerOptions{Level: level, ServiceName: connectorID, ServiceVersion: connectorVersion}))
	strict, _ := strconv.ParseBool(os.Getenv("STRICT_DECODE"))
	handler, e := contentsigning.NewHandler(formatter{}, contentsigning.Base(handlerbase.WithStrictDecode(strict)))
	if e != nil {
		logger.Error("build content signing handler", "err", e)
		os.Exit(1)
	}
	c, e := shared.New(shared.WithLogger(logger), shared.WithAddr(envOr("ADDR", ":8080")), shared.WithInfo(shared.Info{ID: connectorID, Name: "Example Content Signing Formatting Provider v1", Version: connectorVersion, Description: "Demo signature family at the signed level. Not for production."}), shared.WithMetrics(shared.DefaultPrometheus(shared.BuildInfo{Version: connectorVersion, Commit: "dev", Runtime: runtime.Version()})), shared.Register(handler))
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
