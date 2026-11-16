package discovery

import "github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"

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
