package cryptography

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
)

// Attribute provider interfaces are split per endpoint family so a connector
// can implement only the surfaces it actually exposes. Each unregistered
// endpoint responds 200 with an empty array (list) or bare 200 (validate)
// — the SDK-wide convention.

// KindAttributeProvider serves the generic kind-scoped attribute endpoints
// driving token-instance creation UIs:
//
//	GET  /v1/cryptographyProvider/{kind}/attributes
//	POST /v1/cryptographyProvider/{kind}/attributes/validate
type KindAttributeProvider interface {
	Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error)
	ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// TokenProfileAttributeProvider serves the per-token-instance token profile
// attribute endpoints:
//
//	GET  /v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes
//	POST /v1/cryptographyProvider/tokens/{uuid}/tokenProfile/attributes/validate
type TokenProfileAttributeProvider interface {
	TokenProfileAttributes(ctx context.Context, tokenUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateTokenProfileAttributes(ctx context.Context, tokenUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// TokenActivationAttributeProvider serves the per-token-instance activation
// attribute endpoints:
//
//	GET  /v1/cryptographyProvider/tokens/{uuid}/activate/attributes
//	POST /v1/cryptographyProvider/tokens/{uuid}/activate/attributes/validate
type TokenActivationAttributeProvider interface {
	TokenActivationAttributes(ctx context.Context, tokenUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateTokenActivationAttributes(ctx context.Context, tokenUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// CreateSecretKeyAttributeProvider serves the per-token-instance secret-key
// creation attribute endpoints:
//
//	GET  /v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes
//	POST /v1/cryptographyProvider/tokens/{uuid}/keys/secret/attributes/validate
type CreateSecretKeyAttributeProvider interface {
	CreateSecretKeyAttributes(ctx context.Context, tokenUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateCreateSecretKeyAttributes(ctx context.Context, tokenUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// CreateKeyPairAttributeProvider serves the per-token-instance key-pair
// creation attribute endpoints:
//
//	GET  /v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes
//	POST /v1/cryptographyProvider/tokens/{uuid}/keys/pair/attributes/validate
type CreateKeyPairAttributeProvider interface {
	CreateKeyPairAttributes(ctx context.Context, tokenUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateCreateKeyPairAttributes(ctx context.Context, tokenUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}

// RandomDataAttributeProvider serves the per-token-instance random-data
// attribute endpoints:
//
//	GET  /v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes
//	POST /v1/cryptographyProvider/tokens/{uuid}/keys/random/attributes/validate
type RandomDataAttributeProvider interface {
	RandomDataAttributes(ctx context.Context, tokenUuid string) ([]mdl.BaseAttributeDto, error)
	ValidateRandomDataAttributes(ctx context.Context, tokenUuid string, attrs []mdl.RequestAttribute) (validationErrors []string, err error)
}
