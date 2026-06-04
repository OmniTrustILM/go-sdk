// Reference Authority Provider v3 connector. Implements
// connector/provider/authority/v3 against a real in-memory X.509 CA
// (self-signed P-256 root generated at startup) — it signs genuine PKCS#10
// CSRs, tracks revocations, and serves signed CRLs. Demonstrates wiring with
// connector/shared.
//
// Run:
//
//	go run ./connector/examples/authority-v3
//
// Configure with APP_* environment variables (read via envconfig):
//
//	APP_ADDR          listen address              default ":8080"
//	APP_LOG_LEVEL     log level                   default INFO (DEBUG|INFO|WARN|ERROR)
//	APP_STRICT_DECODE reject unknown JSON         default false
//	APP_CA_NAME       provisioned CA name         default "demo-ca"
//	APP_API_KEY       credential for the CA       default "changeme"
//	APP_ASYNC_ISSUE   simulate async issuance     default false
//	APP_ASYNC_DELAY   simulated processing time   default 2s
//
// Mandatory attributes: /v3/authorityProvider/authorities/attributes
// publishes two required authority attributes — ca_name and api_key — that
// every other v3 operation must carry in authorityAttributes (matched by
// UUID, see attrs.go). Wrong api_key returns 401 UNAUTHORIZED; a missing
// attribute or unknown ca_name returns 422 VALIDATION_FAILED. The issue
// schema additionally requires validity_days (1-825), consumed by issue and
// renew.
package main

import (
	"context"
	"log/slog"
	"os"
	"os/signal"
	"runtime"
	"strings"
	"syscall"

	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const (
	connectorID      = "example-authority-v3"
	connectorName    = "Example In-Memory Authority Provider v3"
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

	ca, err := NewCA(cfg.CaName)
	if err != nil {
		logger.Error("create in-memory CA", "err", err)
		os.Exit(1)
	}
	backend := NewBackend(cfg, ca)
	attrs := &Attrs{cfg: cfg}

	handler, err := authority.NewHandler(backend,
		authority.Base(handlerbase.WithStrictDecode(cfg.StrictDecode)),
		authority.WithAuthorityAttributes(attrs),
		authority.WithRAProfileAttributes(attrs),
		authority.WithIssueAttributes(attrs),
		authority.WithRevokeAttributes(attrs),
		authority.WithRegisterAttributes(attrs),
	)
	if err != nil {
		logger.Error("build authority handler", "err", err)
		os.Exit(1)
	}

	c, err := shared.New(
		shared.WithLogger(logger),
		shared.WithAddr(cfg.Addr),
		shared.WithInfo(shared.Info{
			ID:          connectorID,
			Name:        connectorName,
			Version:     connectorVersion,
			Description: "Reference v3 connector backed by an in-memory X.509 CA. Not for production.",
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
