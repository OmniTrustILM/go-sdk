package notification

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper.
type Option func(*Handler) error

// Base lifts shared handlerbase options into the notification provider's
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

// WithKinds declares the notification-instance kinds this connector supports.
// Each kind drives separate kind-attribute and mapping-attribute route
// mounts.
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

// WithMappingAttributes registers the recipient-mapping attribute provider.
func WithMappingAttributes(p MappingAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("mapping attribute provider must not be nil")
		}
		h.mappingAttrs = p
		return nil
	}
}
