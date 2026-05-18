// Package shared provides the HTTP server, request lifecycle, and cross-cutting
// concerns (logging, error handling, health, request ID) used by every
// CZERTAINLY connector spec. Provider-specific handlers (secret, authority,
// compliance, ...) plug in via Registrable and Mount onto the Connector.
package shared

import (
	"context"
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"sync"
)

// Connector hosts shared HTTP endpoints (health, problem-handling middleware,
// request id, slog logging) and the routes contributed by registered provider
// handlers. Construct with New, start with Run.
type Connector struct {
	cfg     *config
	mux     *http.ServeMux
	handler http.Handler
	server  *http.Server
	closed  sync.Once
}

// Registrable is implemented by provider handler packages. Mount attaches
// HTTP routes onto the supplied Router; Interface contributes one
// ConnectorInterfaceInfo entry to /v2/info.
type Registrable interface {
	Mount(Router)
	Interface() InterfaceInfo
}

// New constructs a Connector. Options are applied left-to-right; the resulting
// configuration is validated before any HTTP routes are mounted.
func New(opts ...Option) (*Connector, error) {
	cfg := defaultConfig()
	for _, opt := range opts {
		if err := opt(cfg); err != nil {
			return nil, fmt.Errorf("shared: apply option: %w", err)
		}
	}
	if err := cfg.validate(); err != nil {
		return nil, fmt.Errorf("shared: invalid config: %w", err)
	}

	mux := http.NewServeMux()
	c := &Connector{cfg: cfg, mux: mux}

	router := newMuxRouter(mux)
	c.mountBuiltins(router)

	for _, r := range cfg.registrables {
		r.Mount(router)
	}

	c.handler = c.buildHandler()
	c.server = &http.Server{
		Addr:              cfg.addr,
		Handler:           c.handler,
		ReadTimeout:       cfg.readTimeout,
		WriteTimeout:      cfg.writeTimeout,
		ReadHeaderTimeout: cfg.readHeaderTimeout,
		IdleTimeout:       cfg.idleTimeout,
		ErrorLog:          slog.NewLogLogger(cfg.logger.Handler(), slog.LevelError),
	}

	return c, nil
}

// Handler returns the fully wired http.Handler. Use with httptest.NewServer
// for integration tests without binding a real port.
func (c *Connector) Handler() http.Handler { return c.handler }

// Logger returns the base logger configured on the Connector. Per-request
// loggers (with req_id, method, path attrs) are available via
// LoggerFromContext inside handlers.
func (c *Connector) Logger() *slog.Logger { return c.cfg.logger }

// Run starts the HTTP server and blocks until ctx is cancelled or the server
// fails to start. Cancellation triggers a graceful shutdown bounded by
// WithShutdownTimeout (default 30s).
func (c *Connector) Run(ctx context.Context) error {
	errCh := make(chan error, 1)
	go func() {
		c.cfg.logger.Info("connector starting",
			"addr", c.cfg.addr,
			"tls", c.cfg.tlsEnabled(),
		)
		var err error
		if c.cfg.tlsEnabled() {
			err = c.server.ListenAndServeTLS(c.cfg.tlsCertFile, c.cfg.tlsKeyFile)
		} else {
			err = c.server.ListenAndServe()
		}
		if err != nil && !errors.Is(err, http.ErrServerClosed) {
			errCh <- err
			return
		}
		errCh <- nil
	}()

	select {
	case err := <-errCh:
		return err
	case <-ctx.Done():
		c.cfg.logger.Info("connector shutdown requested", "reason", ctx.Err())
		return c.Close(context.Background())
	}
}

// Close gracefully shuts the server down once. Safe to call concurrently or
// repeatedly. Bounded by WithShutdownTimeout.
func (c *Connector) Close(ctx context.Context) error {
	var err error
	c.closed.Do(func() {
		shutdownCtx, cancel := context.WithTimeout(ctx, c.cfg.shutdownTimeout)
		defer cancel()
		err = c.server.Shutdown(shutdownCtx)
	})
	return err
}

// MaxRequestBytes returns the configured request-body limit. Provider handlers
// pass this to DecodeJSON so all decoders apply the same cap.
func (c *Connector) MaxRequestBytes() int64 { return c.cfg.maxRequestBytes }

// StrictDecode returns whether JSON decoders should reject unknown fields.
func (c *Connector) StrictDecode() bool { return c.cfg.strictDecode }

// buildHandler composes the middleware chain. Order from outermost (executed
// first on incoming request) to innermost:
//
//  1. context decorator        (caller-supplied ctx mutation)
//  2. request id               (sets X-Request-Id and ctx value)
//  3. slog logger              (creates statusRecorder; attaches request-scoped logger; logs completion)
//  4. metrics                  (records request totals, latency, in-flight; sits outside recover so panics count as 500)
//  5. recover                  (catches panics, renders 500 via WriteProblem)
//  6. user middleware          (WithMiddleware order preserved)
//  7. auth                     (WithAuth)
//  8. mux                      (provider routes + builtins)
func (c *Connector) buildHandler() http.Handler {
	var h http.Handler = c.mux

	if c.cfg.auth != nil {
		h = c.cfg.auth(h)
	}
	for i := len(c.cfg.middleware) - 1; i >= 0; i-- {
		h = c.cfg.middleware[i](h)
	}
	h = withRecover(c.cfg.logger, c.cfg.errorRenderer)(h)
	if c.cfg.metrics != nil {
		h = withMetrics(c.mux, c.cfg.metrics)(h)
	}
	h = withSlogLogger(c.cfg.logger)(h)
	h = withErrorRenderer(c.cfg.errorRenderer)(h)
	h = withRequestID(c.cfg.requestIDHeader)(h)
	if c.cfg.contextDecorator != nil {
		h = withContextDecorator(c.cfg.contextDecorator)(h)
	}
	return h
}

// mountBuiltins attaches endpoints owned by the shared package: health
// (v1 or v2 based on cfg.healthVersion), info (v1 listSupportedFunctions or
// /v2/info based on cfg.infoVersion), /v1/metrics when WithMetrics is
// supplied, and every ExtraEndpoint registered via WithExtraEndpoints.
// Called in New before provider Mount; the underlying http.ServeMux panics
// on duplicate method+pattern registrations, so providers and extras must
// not collide with builtin paths or with each other.
func (c *Connector) mountBuiltins(r Router) {
	mountHealth(r, c.cfg.healthChecker, c.cfg.healthVersion)
	mountInfo(r, c.cfg)
	if c.cfg.metrics != nil {
		r.Handle(http.MethodGet, "/v1/metrics", c.cfg.metrics.Handler().ServeHTTP)
	}
	mountExtras(r, c.cfg.extras)
}
