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
//	    authority.WithAuthorityAttributes(attrs),
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

// WithAuthorityAttributes registers the provider backing
// GET /v3/authorityProvider/authorities/attributes.
func WithAuthorityAttributes(p AuthorityAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("authority attribute provider must not be nil")
		}
		h.authorityAttrs = p
		return nil
	}
}

// WithRAProfileAttributes registers the provider backing
// POST /v3/authorityProvider/authorities/raProfile/attributes.
func WithRAProfileAttributes(p RAProfileAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("ra profile attribute provider must not be nil")
		}
		h.raProfileAttrs = p
		return nil
	}
}

// WithIssueAttributes registers the provider backing
// POST /v3/authorityProvider/certificates/issue/attributes.
func WithIssueAttributes(p IssueAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("issue attribute provider must not be nil")
		}
		h.issueAttrs = p
		return nil
	}
}

// WithRevokeAttributes registers the provider backing
// POST /v3/authorityProvider/certificates/revoke/attributes.
func WithRevokeAttributes(p RevokeAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("revoke attribute provider must not be nil")
		}
		h.revokeAttrs = p
		return nil
	}
}

// WithRegisterAttributes registers the provider backing
// POST /v3/authorityProvider/certificates/register/attributes.
func WithRegisterAttributes(p RegisterAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("register attribute provider must not be nil")
		}
		h.registerAttrs = p
		return nil
	}
}

// WithAttributeDefinitions registers the provider backing the connector-level
// Attributes API: GET /v2/attributes, GET /v2/attributes/{uuid}, and
// POST /v2/attributes/callback. When not supplied, list returns an empty
// definition set and get/callback respond 404.
func WithAttributeDefinitions(p AttributeDefinitionsProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("attribute definitions provider must not be nil")
		}
		h.attributeDefs = p
		return nil
	}
}
