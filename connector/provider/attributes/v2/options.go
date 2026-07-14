package attributes

import "github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"

// Option configures a Handler at construction.
type Option func(*Handler) error

// Base applies handlerbase configuration (max request bytes, strict JSON
// decoding, logger) to the handler — the same knobs the functional-interface
// providers expose.
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
