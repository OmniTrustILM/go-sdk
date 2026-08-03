package attributes

import "github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"

// Option configures a Handler at construction.
type Option func(*Handler) error

// Base applies handlerbase configuration (max request bytes, strict JSON
// decoding, logger) to the handler — the same knobs the functional-interface
// providers expose.
//
// handlerbase.WithFeatures is accepted but does nothing here. This handler's
// Interface() returns an empty Code, which tells /v2/info to leave it out of
// the interfaces list (see connector/shared/info.go), and feature flags are
// a field on that list entry. Advertise them instead on the functional interface —
// authority, secret...
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
