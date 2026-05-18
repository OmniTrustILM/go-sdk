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

// WithKinds declares the authority kinds this connector supports. Surfaced
// in /v1 listSupportedFunctions under the authorityProvider function group.
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		h.kinds = append(h.kinds, kinds...)
		return nil
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
