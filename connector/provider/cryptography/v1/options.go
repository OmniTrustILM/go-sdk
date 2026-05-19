package cryptography

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper.
type Option func(*Handler) error

// Base lifts shared handlerbase options into the cryptography provider's
// Option type.
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

// WithKinds declares the token-instance kinds this connector supports.
// Required: each kind drives a separate kind-attribute route mount (see
// Mount in handler.go for the conflict reason).
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		h.kinds = append(h.kinds, kinds...)
		return nil
	}
}

// WithKindAttributes registers the generic kind-scoped attribute provider.
func WithKindAttributes(p KindAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("kind attribute provider must not be nil")
		}
		h.kindAttrs = p
		return nil
	}
}

// WithTokenProfileAttributes registers the per-instance token-profile
// attribute provider.
func WithTokenProfileAttributes(p TokenProfileAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("token profile attribute provider must not be nil")
		}
		h.tokenProfileAttrs = p
		return nil
	}
}

// WithTokenActivationAttributes registers the per-instance activation
// attribute provider.
func WithTokenActivationAttributes(p TokenActivationAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("token activation attribute provider must not be nil")
		}
		h.tokenActivationAttrs = p
		return nil
	}
}

// WithCreateSecretKeyAttributes registers the per-instance secret-key
// creation attribute provider.
func WithCreateSecretKeyAttributes(p CreateSecretKeyAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("create secret key attribute provider must not be nil")
		}
		h.createSecretKeyAttrs = p
		return nil
	}
}

// WithCreateKeyPairAttributes registers the per-instance key-pair
// creation attribute provider.
func WithCreateKeyPairAttributes(p CreateKeyPairAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("create key pair attribute provider must not be nil")
		}
		h.createKeyPairAttrs = p
		return nil
	}
}

// WithRandomDataAttributes registers the per-instance random-data
// attribute provider.
func WithRandomDataAttributes(p RandomDataAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("random data attribute provider must not be nil")
		}
		h.randomDataAttrs = p
		return nil
	}
}
