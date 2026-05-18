package secret

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// Base lifts shared handlerbase options (base path, max bytes, strict decode,
// logger override) into the secret provider's Option type.
//
//	secret.NewHandler(p,
//	    secret.Base(
//	        handlerbase.WithStrictDecode(true),
//	        handlerbase.WithMaxRequestBytes(2<<20),
//	    ),
//	    secret.WithSecretAttributes(myAttrs),
//	)
func Base(opts ...handlerbase.Option) Option {
	return func(h *Handler) error {
		for _, opt := range opts {
			if err := opt(&h.Config); err != nil {
				return err
			}
		}
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
