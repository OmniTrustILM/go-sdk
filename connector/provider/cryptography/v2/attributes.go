package cryptography

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// Attribute provider interfaces are split per endpoint so a connector can
// implement only the surfaces it actually exposes. Each unregistered attribute
// endpoint responds 200 with an empty array — the SDK-wide convention for
// optional attribute providers.
//
// Definitions returned here must not contain resolved credentials or secret
// values.

// TokenAttributeProvider serves GET /v2/cryptographyProvider/tokens/attributes.
// The only GET in this interface and the only endpoint with no request body.
type TokenAttributeProvider interface {
	TokenAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error)
}

// TokenProfileAttributeProvider serves
// POST /v2/cryptographyProvider/tokens/tokenProfile/attributes.
type TokenProfileAttributeProvider interface {
	TokenProfileAttributes(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// CreateKeyAttributeProvider serves
// POST /v2/cryptographyProvider/keys/create/attributes.
type CreateKeyAttributeProvider interface {
	CreateKeyAttributes(ctx context.Context, req *mdl.CreateKeyAttributesRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// EncryptAttributeProvider serves
// POST /v2/cryptographyProvider/operations/encrypt/attributes.
type EncryptAttributeProvider interface {
	EncryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// DecryptAttributeProvider serves
// POST /v2/cryptographyProvider/operations/decrypt/attributes.
type DecryptAttributeProvider interface {
	DecryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// SignAttributeProvider serves
// POST /v2/cryptographyProvider/operations/sign/attributes.
type SignAttributeProvider interface {
	SignAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// VerifyAttributeProvider serves
// POST /v2/cryptographyProvider/operations/verify/attributes.
type VerifyAttributeProvider interface {
	VerifyAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}

// RandomDataAttributeProvider serves
// POST /v2/cryptographyProvider/operations/random/attributes. Scoped to the
// token profile, not to a key — random data has no key context.
type RandomDataAttributeProvider interface {
	RandomDataAttributes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error)
}
