package authority

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// Base lifts shared handlerbase options (base path, max bytes, strict decode,
// logger override) into the authority provider's Option type.
//
//	authority.NewHandler(p,
//	    authority.Base(handlerbase.WithStrictDecode(true)),
//	    authority.WithKinds("hashicorp-vault"),
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

// WithKinds declares the connector kinds this provider supports.
// Surfaced in /v1 listSupportedFunctions and drives the per-literal-kind
// attribute route mounts. Delegates to handlerbase.WithKinds for input
// validation (rejects empty kinds and characters forbidden in a URL
// path segment).
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		return handlerbase.WithKinds(kinds...)(&h.Config)
	}
}

// WithKindAttributes registers the AttributeProvider backing the generic
// kind-scoped attribute endpoints. When not supplied, list returns an empty
// array and validate is a no-op success.
func WithKindAttributes(p KindAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("kind attribute provider must not be nil")
		}
		h.kindAttrs = p
		return nil
	}
}

// WithRAProfileAttributes registers the per-instance RA Profile attribute
// provider.
func WithRAProfileAttributes(p RAProfileAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("ra profile attribute provider must not be nil")
		}
		h.raProfileAttrs = p
		return nil
	}
}

// WithIssueCertificateAttributes registers the per-instance issue-certificate
// attribute provider.
func WithIssueCertificateAttributes(p IssueCertificateAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("issue certificate attribute provider must not be nil")
		}
		h.issueAttrs = p
		return nil
	}
}

// WithRevokeCertificateAttributes registers the per-instance revoke-certificate
// attribute provider.
func WithRevokeCertificateAttributes(p RevokeCertificateAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("revoke certificate attribute provider must not be nil")
		}
		h.revokeAttrs = p
		return nil
	}
}
