package credential

import (
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper.
type Option func(*Handler) error

// Base lifts shared handlerbase options (base path, max bytes, strict decode,
// logger override) into the credential provider's Option type.
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

// WithKinds declares the credential kinds this connector supports. Surfaced
// in /v1 listSupportedFunctions under the credentialProvider function group.
func WithKinds(kinds ...string) Option {
	return func(h *Handler) error {
		h.kinds = append(h.kinds, kinds...)
		return nil
	}
}
