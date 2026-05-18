package shared

import (
	"context"
	"errors"
	"fmt"
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

	infoVersion   string
	healthVersion string

	errorRenderer ErrorRenderer

	registrables []Registrable
	extras       []ExtraEndpoint

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
		infoVersion:       VersionV2,
		healthVersion:     VersionV2,
		errorRenderer:     WriteProblem,
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
	if c.infoVersion != VersionV1 && c.infoVersion != VersionV2 {
		return errors.New(`infoVersion must be "v1" or "v2"`)
	}
	if c.healthVersion != VersionV1 && c.healthVersion != VersionV2 {
		return errors.New(`healthVersion must be "v1" or "v2"`)
	}
	for i, e := range c.extras {
		if e.FunctionGroupCode == "" {
			return fmt.Errorf("extras[%d]: functionGroupCode must not be empty", i)
		}
		if e.Method == "" {
			return fmt.Errorf("extras[%d]: method must not be empty", i)
		}
		if e.Context == "" {
			return fmt.Errorf("extras[%d]: context must not be empty", i)
		}
		if e.Name == "" {
			return fmt.Errorf("extras[%d]: name must not be empty", i)
		}
		// Handler may be nil: such entries are info-only and surface in /v1
		// info without registering anything on the mux. Useful for declaring
		// shared endpoints (e.g. /v1/health) that the shared package mounts
		// itself.
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

// WithInfoVersion selects which info endpoint the Connector exposes:
// VersionV1 mounts GET /v1 (listSupportedFunctions), VersionV2 mounts
// GET /v2/info. Default VersionV2.
//
// Trade-off: only one of the two endpoints is exposed per Connector. With
// VersionV2, V1Reporter contributions from registered handlers are not
// reachable — the v1 function-group listing has no endpoint to serve from.
// Conversely, with VersionV1, the InterfaceInfo values returned by
// Registrable.Interface() are not surfaced (the /v2/info response shape is
// not emitted). Pick the version that matches the specs implemented by the
// registered providers; if a connector mixes v1 and v2 spec providers, run
// two Connectors or split deployments.
//
// The choice is also reflected in the /v2/info response interface list
// ("info" version field) when /v2/info is the active endpoint.
func WithInfoVersion(v string) Option {
	return func(c *config) error {
		if v != VersionV1 && v != VersionV2 {
			return errors.New(`infoVersion must be "v1" or "v2"`)
		}
		c.infoVersion = v
		return nil
	}
}

// WithHealthVersion selects which health endpoint(s) the Connector exposes.
// VersionV1 mounts only GET /v1/health. VersionV2 mounts GET /v2/health,
// /v2/health/readiness, /v2/health/liveness. Default VersionV2.
//
// The choice is reflected in the /v2/info response interface list ("health"
// version field) when /v2/info is the active info endpoint.
func WithHealthVersion(v string) Option {
	return func(c *config) error {
		if v != VersionV1 && v != VersionV2 {
			return errors.New(`healthVersion must be "v1" or "v2"`)
		}
		c.healthVersion = v
		return nil
	}
}

// WithErrorRenderer overrides the connector-wide error renderer used by the
// recover middleware and by any code that calls shared.RenderError. Default
// is WriteProblem (RFC 9457 ProblemDetail). v1 spec connectors must set this
// to a renderer that emits their spec's error shape (e.g. discovery.WriteError).
func WithErrorRenderer(r ErrorRenderer) Option {
	return func(c *config) error {
		if r == nil {
			return errors.New("error renderer must not be nil")
		}
		c.errorRenderer = r
		return nil
	}
}

// WithExtraEndpoints registers user-supplied HTTP handlers on the Connector's
// mux and surfaces them under matching function groups in /v1 info. Useful
// for callback URLs and helper endpoints not part of any canonical spec.
//
// Each ExtraEndpoint must specify FunctionGroupCode, Method, Context, and
// Name; UUID and Required are optional. Handler is optional too — when nil,
// the entry is info-only (no route mounted) and is used to advertise paths
// that the shared package already serves itself (/v1, /v1/health). Patterns
// follow stdlib http.ServeMux syntax.
func WithExtraEndpoints(eps ...ExtraEndpoint) Option {
	return func(c *config) error {
		c.extras = append(c.extras, eps...)
		return nil
	}
}
