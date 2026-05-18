package discovery

import (
	"errors"
	"log/slog"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// WithBasePath overrides the discovery-specific route prefix. Default
// "/v1/discoveryProvider". Useful when fronting the connector with a
// prefix-stripping proxy. The shared /v1, /v1/health, and attribute-endpoint
// patterns are not affected — they retain their canonical paths.
func WithBasePath(p string) Option {
	return func(h *Handler) error {
		if p == "" {
			return errors.New("base path must not be empty")
		}
		h.basePath = p
		return nil
	}
}

// WithKinds declares the discovery kinds this connector supports. Surfaced
// in /v1 listSupportedFunctions under the discoveryProvider function group.
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		h.kinds = append(h.kinds, kinds...)
		return nil
	}
}

// WithMaxRequestBytes caps body size for endpoints that decode JSON. Default
// 1 MiB.
func WithMaxRequestBytes(n int64) Option {
	return func(h *Handler) error {
		if n <= 0 {
			return errors.New("maxRequestBytes must be > 0")
		}
		h.maxBytes = n
		return nil
	}
}

// WithStrictDecode rejects request bodies containing unknown JSON fields.
// Default false.
func WithStrictDecode(b bool) Option {
	return func(h *Handler) error { h.strict = b; return nil }
}

// WithLogger overrides the per-handler base logger. When unset, handlers use
// the request-scoped logger from shared.LoggerFromContext.
func WithLogger(l *slog.Logger) Option {
	return func(h *Handler) error {
		if l == nil {
			return errors.New("logger must not be nil")
		}
		h.logger = l
		return nil
	}
}

// WithAttributes registers the AttributeProvider backing the kind-scoped
// attribute endpoints. When not supplied, list returns an empty array and
// validate is a no-op success.
func WithAttributes(p AttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("attribute provider must not be nil")
		}
		h.attrs = p
		return nil
	}
}
