// Package handlerbase provides the shared configuration and option helpers
// every provider Handler embeds. Every provider sub-package (secret v1,
// discovery v1, authority v1/v2, ...) needs the same knobs — base path,
// request-body size limit, strict-decode flag, logger override — and the
// option boilerplate to set them. Hoisting those into one place keeps each
// provider package focused on its spec-specific surface.
//
// Provider packages embed Config in their Handler and expose a Base option
// that lifts handlerbase.Option into the provider's own Option type:
//
//	type Handler struct {
//	    handlerbase.Config
//	    provider Provider
//	    // provider-specific fields
//	}
//
//	type Option func(*Handler) error
//
//	func Base(opts ...handlerbase.Option) Option {
//	    return func(h *Handler) error {
//	        for _, o := range opts {
//	            if err := o(&h.Config); err != nil { return err }
//	        }
//	        return nil
//	    }
//	}
//
// Caller code then writes:
//
//	discovery.NewHandler(p,
//	    discovery.Base(
//	        handlerbase.WithStrictDecode(true),
//	        handlerbase.WithMaxRequestBytes(2<<20),
//	    ),
//	    discovery.WithKinds("a"),
//	)
package handlerbase

import (
	"errors"
	"log/slog"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// DefaultMaxRequestBytes caps decoded request bodies. Picked to match the
// shared.Connector default; provider Handlers inherit it via NewConfig.
const DefaultMaxRequestBytes int64 = 1 << 20 // 1 MiB

// Config carries the cross-provider configuration that every provider
// Handler embeds. Fields are exported so the embedding struct sees them via
// promotion (h.BasePath, h.MaxBytes, etc.) without forwarding accessors.
//
// LoggerFor is exposed as a method so route handlers do not have to
// duplicate the "override-or-context" lookup.
type Config struct {
	// BasePath is the route prefix the provider mounts its endpoints under.
	BasePath string

	// MaxBytes caps body size for endpoints that decode JSON.
	MaxBytes int64

	// Strict toggles json.Decoder.DisallowUnknownFields.
	Strict bool

	// Logger overrides the per-request slog.Logger when non-nil. Most
	// handlers prefer LoggerFor(r) which falls back to the context logger.
	Logger *slog.Logger
}

// NewConfig returns a Config populated with the SDK defaults. defaultBasePath
// is the provider-specific route prefix (e.g. "/v1/discoveryProvider").
func NewConfig(defaultBasePath string) Config {
	return Config{
		BasePath: defaultBasePath,
		MaxBytes: DefaultMaxRequestBytes,
	}
}

// LoggerFor returns the most specific logger available: an explicit override
// (WithLogger) when set, otherwise the request-scoped logger from the shared
// middleware chain.
func (c *Config) LoggerFor(r *http.Request) *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return shared.LoggerFromContext(r.Context())
}

// Option configures a Config. Provider packages lift these into their own
// Option type via a thin Base(...) wrapper.
type Option func(*Config) error

// WithBasePath overrides the route prefix the provider mounts under. Useful
// when fronting the connector with a prefix-stripping proxy.
func WithBasePath(p string) Option {
	return func(c *Config) error {
		if p == "" {
			return errors.New("base path must not be empty")
		}
		c.BasePath = p
		return nil
	}
}

// WithMaxRequestBytes caps decoded request body size. Default 1 MiB.
func WithMaxRequestBytes(n int64) Option {
	return func(c *Config) error {
		if n <= 0 {
			return errors.New("maxRequestBytes must be > 0")
		}
		c.MaxBytes = n
		return nil
	}
}

// WithStrictDecode rejects request bodies containing unknown JSON fields.
// Default false.
func WithStrictDecode(b bool) Option {
	return func(c *Config) error { c.Strict = b; return nil }
}

// WithLogger overrides the per-handler base logger. When unset, handlers use
// the request-scoped logger from shared.LoggerFromContext.
func WithLogger(l *slog.Logger) Option {
	return func(c *Config) error {
		if l == nil {
			return errors.New("logger must not be nil")
		}
		c.Logger = l
		return nil
	}
}
