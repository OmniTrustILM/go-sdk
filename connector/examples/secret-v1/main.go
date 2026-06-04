// Reference Secret Provider connector. Implements connector/provider/secret/v1
// with an in-memory, mutex-guarded map keyed by secret name. Demonstrates
// wiring with connector/shared.
//
// Run:
//
//	go run ./connector/examples/secret-v1
//
// Configure with APP_* environment variables (read via envconfig):
//
//	APP_ADDR          listen address           default ":8080"
//	APP_LOG_LEVEL     log level                default INFO   (DEBUG|INFO|WARN|ERROR)
//	APP_STRICT_DECODE reject unknown JSON      default false
//	APP_USERNAME      credentials username     default "admin"
//	APP_PASSWORD      credentials password     default "admin"
//
// The connector exposes /v2/health, /v2/health/{readiness,liveness},
// /v2/info, /v1/metrics, and the secret v1 routes under /v1/secretProvider.
// Every Provider request must carry the username and password attributes
// (matched by UUID — see attrs.go); mismatches return 401 UNAUTHORIZED and
// missing attributes return 422 VALIDATION_FAILED.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-secret-v1"
	connectorName    = "Example In-Memory Secret Provider"
	connectorVersion = "0.1.0"
	commitSHA        = "dev"
)

func main() {
	cfg, err := LoadConfig()
	if err != nil {
		// Logger not built yet; fall back to default.
		slog.Default().Error("load config", "err", err)
		os.Exit(1)
	}
	logger := newLogger(cfg.LogLevel)

	store := NewStore(cfg)
	attrs := &Attrs{}

	handler, err := secret.NewHandler(store,
		secret.Base(handlerbase.WithStrictDecode(cfg.StrictDecode)),
		secret.WithVaultAttributes(attrs),
		secret.WithVaultProfileAttributes(attrs),
	)
	if err != nil {
		logger.Error("build secret handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(cfg.Addr),
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

// newLogger builds a JSON slog logger at the supplied level. Case-insensitive;
// unknown values fall back to INFO.
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
	return slog.New(slog.NewJSONHandler(os.Stdout, &slog.HandlerOptions{Level: lvl}))
}
