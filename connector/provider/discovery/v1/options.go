package discovery

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// Base lifts shared handlerbase options (base path, max bytes, strict decode,
// logger override) into the discovery provider's Option type.
//
//	discovery.NewHandler(p,
//	    discovery.Base(
//	        handlerbase.WithStrictDecode(true),
//	        handlerbase.WithMaxRequestBytes(2<<20),
//	    ),
//	    discovery.WithKinds("a"),
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

// WithKinds declares the discovery kinds this connector supports. Surfaced
// in /v1 listSupportedFunctions under the discoveryProvider function group.
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		h.kinds = append(h.kinds, kinds...)
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
