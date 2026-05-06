package shared

import (
	"context"
	"errors"
	"log/slog"
	"net/http"
	"time"
)

// Option configures a Connector. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields, and append for
// list-shaped fields (middleware, registrables).
type Option func(*config) error

// Middleware is the standard net/http middleware shape.
type Middleware func(http.Handler) http.Handler

type config struct {
	logger *slog.Logger

	addr              string
	tlsCertFile       string
	tlsKeyFile        string
	readTimeout       time.Duration
	writeTimeout      time.Duration
	readHeaderTimeout time.Duration
	idleTimeout       time.Duration
	shutdownTimeout   time.Duration

	middleware       []Middleware
	auth             Middleware
	requestIDHeader  string
	contextDecorator func(context.Context, *http.Request) context.Context

	info          Info
	healthChecker HealthChecker
	metrics       MetricsCollector

	registrables []Registrable

	maxRequestBytes int64
	strictDecode    bool
}

func defaultConfig() *config {
	return &config{
		logger:            slog.Default(),
		addr:              ":8080",
		readTimeout:       30 * time.Second,
		writeTimeout:      30 * time.Second,
		readHeaderTimeout: 10 * time.Second,
		idleTimeout:       60 * time.Second,
		shutdownTimeout:   30 * time.Second,
		requestIDHeader:   "X-Request-Id",
		healthChecker:     defaultHealthChecker{},
		maxRequestBytes:   1 << 20, // 1 MiB
	}
}

func (c *config) validate() error {
	if c.logger == nil {
		return errors.New("logger must not be nil")
	}
	if c.addr == "" {
		return errors.New("addr must not be empty")
	}
	if (c.tlsCertFile == "") != (c.tlsKeyFile == "") {
		return errors.New("tls cert and key must be provided together")
	}
	if c.maxRequestBytes <= 0 {
		return errors.New("maxRequestBytes must be > 0")
	}
	if c.shutdownTimeout <= 0 {
		return errors.New("shutdownTimeout must be > 0")
	}
	return nil
}

func (c *config) tlsEnabled() bool { return c.tlsCertFile != "" && c.tlsKeyFile != "" }

// WithLogger sets the base slog.Logger. Per-request loggers derived from it are
// attached to request context; reach them with LoggerFromContext.
func WithLogger(l *slog.Logger) Option {
	return func(c *config) error {
		if l == nil {
			return errors.New("logger must not be nil")
		}
		c.logger = l
		return nil
	}
}

// WithAddr sets the listen address (default ":8080").
func WithAddr(addr string) Option {
	return func(c *config) error { c.addr = addr; return nil }
}

// WithTLS enables TLS using the given cert/key files. Both or neither.
func WithTLS(certFile, keyFile string) Option {
	return func(c *config) error {
		c.tlsCertFile = certFile
		c.tlsKeyFile = keyFile
		return nil
	}
}

func WithReadTimeout(d time.Duration) Option {
	return func(c *config) error { c.readTimeout = d; return nil }
}

func WithWriteTimeout(d time.Duration) Option {
	return func(c *config) error { c.writeTimeout = d; return nil }
}

func WithReadHeaderTimeout(d time.Duration) Option {
	return func(c *config) error { c.readHeaderTimeout = d; return nil }
}

func WithIdleTimeout(d time.Duration) Option {
	return func(c *config) error { c.idleTimeout = d; return nil }
}

// WithShutdownTimeout bounds graceful shutdown. Default 30s.
func WithShutdownTimeout(d time.Duration) Option {
	return func(c *config) error { c.shutdownTimeout = d; return nil }
}

// WithMiddleware appends user middleware. Earlier entries are outer (executed
// first on the request path).
func WithMiddleware(mw ...Middleware) Option {
	return func(c *config) error { c.middleware = append(c.middleware, mw...); return nil }
}

// WithAuth installs the authentication middleware. Spec defines no auth scheme;
// callers plug mTLS, OAuth, or anything else here.
func WithAuth(mw Middleware) Option {
	return func(c *config) error { c.auth = mw; return nil }
}

// WithRequestIDHeader overrides the request id header. Default "X-Request-Id".
func WithRequestIDHeader(h string) Option {
	return func(c *config) error {
		if h == "" {
			return errors.New("request id header must not be empty")
		}
		c.requestIDHeader = h
		return nil
	}
}

// WithContextDecorator allows callers to mutate request context before any
// shared middleware runs. Useful to inject trace IDs, tenant info, etc.
func WithContextDecorator(fn func(context.Context, *http.Request) context.Context) Option {
	return func(c *config) error { c.contextDecorator = fn; return nil }
}

// WithInfo supplies static connector identity used by /v2/info. Functions are
// auto-populated from registered handlers; callers do not need to fill them.
func WithInfo(i Info) Option {
	return func(c *config) error { c.info = i; return nil }
}

// WithHealthCheck installs the HealthChecker for /v2/health* endpoints. If
// omitted, a checker that always reports UP is used.
func WithHealthCheck(h HealthChecker) Option {
	return func(c *config) error {
		if h == nil {
			return errors.New("health checker must not be nil")
		}
		c.healthChecker = h
		return nil
	}
}

// WithMetrics installs the MetricsCollector backing /v1/metrics. When
// supplied, the metrics middleware is added to the chain and the "metrics"
// interface is reported by /v2/info. Use DefaultPrometheus for the standard
// Prometheus implementation that satisfies the spec's x-metrics-profile.
func WithMetrics(m MetricsCollector) Option {
	return func(c *config) error {
		if m == nil {
			return errors.New("metrics collector must not be nil")
		}
		c.metrics = m
		return nil
	}
}

// WithMaxRequestBytes caps request body size during JSON decode. Default 1 MiB.
func WithMaxRequestBytes(n int64) Option {
	return func(c *config) error { c.maxRequestBytes = n; return nil }
}

// WithStrictDecode rejects request bodies containing unknown JSON fields.
// Default false (lenient).
func WithStrictDecode(b bool) Option {
	return func(c *config) error { c.strictDecode = b; return nil }
}

// Register attaches a provider handler to the Connector. Each handler may be
// registered at most once; the order of registration determines route mount
// order (relevant only when patterns overlap, which they should not).
func Register(r Registrable) Option {
	return func(c *config) error {
		if r == nil {
			return errors.New("registrable must not be nil")
		}
		c.registrables = append(c.registrables, r)
		return nil
	}
}
