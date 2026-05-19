package entity

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper.
type Option func(*Handler) error

// Base lifts shared handlerbase options into the entity provider's Option type.
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

// WithKinds declares the entity-instance kinds this connector supports.
// Each kind drives a separate kind-attribute route mount.
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

// WithLocationAttributes registers the per-entity location-attribute provider.
func WithLocationAttributes(p LocationAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("location attribute provider must not be nil")
		}
		h.locationAttrs = p
		return nil
	}
}

// WithPushCertificateAttributes registers the per-entity push-certificate
// attribute provider.
func WithPushCertificateAttributes(p PushCertificateAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("push certificate attribute provider must not be nil")
		}
		h.pushAttrs = p
		return nil
	}
}

// WithGenerateCsrAttributes registers the per-entity generate-CSR attribute
// provider.
func WithGenerateCsrAttributes(p GenerateCsrAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("generate csr attribute provider must not be nil")
		}
		h.csrAttrs = p
		return nil
	}
}
