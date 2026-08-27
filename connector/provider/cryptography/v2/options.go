package cryptography

import (
	"errors"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// Option configures a Handler. Returned by every With* helper. Applied in
// order; later options override earlier ones for scalar fields.
type Option func(*Handler) error

// Base lifts shared handlerbase options (base path, max bytes, strict decode,
// logger override, advertised features) into this package's Option type.
//
//	cryptography.NewHandler(p,
//	    cryptography.Base(
//	        handlerbase.WithStrictDecode(true),
//	        handlerbase.WithFeatures(string(mdl.FEATUREFLAG_ASYNCHRONOUS)),
//	    ),
//	    cryptography.WithAsyncKeys(p),
//	)
//
// handlerbase.WithStrictDecode has no effect here: every v2 request DTO's
// generated UnmarshalJSON calls DisallowUnknownFields unconditionally, matching
// the contract's additionalProperties: false, so unknown properties always
// answer 400.
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

// WithAsyncKeys registers the provider backing the four key status/cancel
// routes. When absent those routes answer 404 OPERATION_NOT_SUPPORTED. See
// AsyncKeyProvider for the ENFORCED-feature-flag requirement.
func WithAsyncKeys(p AsyncKeyProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("async key provider must not be nil")
		}
		h.asyncKeys = p
		return nil
	}
}

// WithAsyncSign registers the provider backing the two sign status/cancel
// routes. When absent those routes answer 404 OPERATION_NOT_SUPPORTED. See
// AsyncSignProvider for the ENFORCED-feature-flag requirement.
func WithAsyncSign(p AsyncSignProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("async sign provider must not be nil")
		}
		h.asyncSign = p
		return nil
	}
}

// WithTokenAttributes registers the provider backing
// GET /v2/cryptographyProvider/tokens/attributes.
func WithTokenAttributes(p TokenAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("token attribute provider must not be nil")
		}
		h.tokenAttrs = p
		return nil
	}
}

// WithTokenProfileAttributes registers the provider backing
// POST /v2/cryptographyProvider/tokens/tokenProfile/attributes.
func WithTokenProfileAttributes(p TokenProfileAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("token profile attribute provider must not be nil")
		}
		h.tokenProfileAttrs = p
		return nil
	}
}

// WithCreateKeyAttributes registers the provider backing
// POST /v2/cryptographyProvider/keys/create/attributes.
func WithCreateKeyAttributes(p CreateKeyAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("create key attribute provider must not be nil")
		}
		h.createKeyAttrs = p
		return nil
	}
}

// WithEncryptAttributes registers the provider backing
// POST /v2/cryptographyProvider/operations/encrypt/attributes.
func WithEncryptAttributes(p EncryptAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("encrypt attribute provider must not be nil")
		}
		h.encryptAttrs = p
		return nil
	}
}

// WithDecryptAttributes registers the provider backing
// POST /v2/cryptographyProvider/operations/decrypt/attributes.
func WithDecryptAttributes(p DecryptAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("decrypt attribute provider must not be nil")
		}
		h.decryptAttrs = p
		return nil
	}
}

// WithSignAttributes registers the provider backing
// POST /v2/cryptographyProvider/operations/sign/attributes.
func WithSignAttributes(p SignAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("sign attribute provider must not be nil")
		}
		h.signAttrs = p
		return nil
	}
}

// WithVerifyAttributes registers the provider backing
// POST /v2/cryptographyProvider/operations/verify/attributes.
func WithVerifyAttributes(p VerifyAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("verify attribute provider must not be nil")
		}
		h.verifyAttrs = p
		return nil
	}
}

// WithRandomDataAttributes registers the provider backing
// POST /v2/cryptographyProvider/operations/random/attributes.
func WithRandomDataAttributes(p RandomDataAttributeProvider) Option {
	return func(h *Handler) error {
		if p == nil {
			return errors.New("random data attribute provider must not be nil")
		}
		h.randomAttrs = p
		return nil
	}
}
