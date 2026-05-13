package secret

import (
	"errors"
	"log/slog"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// WithBasePath overrides the route prefix. Default "/v1/secretProvider".
// Useful when mounting multiple v1 connectors on the same Connector or when
// fronting the connector with a prefix-stripping proxy.
func WithBasePath(p string) Option {
	return func(h *Handler) error {
		if p == "" {
			return errors.New("base path must not be empty")
		}
		h.basePath = p
		return nil
	}
}

// WithMaxRequestBytes caps body size for endpoints that decode JSON. Default
// 1 MiB. Set independently from the shared.Connector default so providers
// with notably larger payloads (e.g. keystore uploads) can opt up.
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
// Default false (lenient).
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

// WithSecretAttributes registers the GET /secrets/{secretType}/attributes
// handler.
func WithSecretAttributes(p SecretAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("secret attribute provider must not be nil")
		}
		h.secretAttrs = p
		return nil
	}
}

// WithVaultAttributes registers the GET /vaults/attributes handler.
func WithVaultAttributes(p VaultAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("vault attribute provider must not be nil")
		}
		h.vaultAttrs = p
		return nil
	}
}

// WithVaultProfileAttributes registers the POST /vaultProfiles/attributes
// handler.
func WithVaultProfileAttributes(p VaultProfileAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("vault profile attribute provider must not be nil")
		}
		h.vaultProfileAttrs = p
		return nil
	}
}

// WithRotateAttributes registers the GET /secrets/rotate/attributes handler.
func WithRotateAttributes(p RotateAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("rotate attribute provider must not be nil")
		}
		h.rotateAttrs = p
		return nil
	}
}
