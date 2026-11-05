package discovery

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

type Option func(*Handler) error

// Base lifts the SDK's base path, logger, body limit, decode and feature options.
func Base(opts ...handlerbase.Option) Option {
	return func(h *Handler) error {
		for _, o := range opts {
			if err := o(&h.Config); err != nil {
				return err
			}
		}
		return nil
	}
}
func WithAttributeDefinitions(p AttributeDefinitionsProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("discovery v2: attribute definitions provider must not be nil")
		}
		h.attributeDefs = p
		return nil
	}
}
