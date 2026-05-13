package secret

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// Attribute provider interfaces are split per endpoint so a connector can
// implement only the attribute surfaces it actually exposes. Each unregistered
// attribute endpoint responds with 404 ATTR_NOT_REGISTERED; the convention may
// change once the attribute registry lands (see the open question in res-1.md).
//
// One implementation can satisfy several of these interfaces simply by
// embedding or by pointer-receiving multiple methods on the same struct.

// SecretAttributeProvider serves
//   GET /v1/secretProvider/secrets/{secretType}/attributes
//
// The secretType path parameter is validated against the SecretType enum
// before this method is called; implementations can assume t is one of the
// AllowedSecretTypeEnumValues entries.
type SecretAttributeProvider interface {
	SecretAttributes(ctx context.Context, t mdl.SecretType) ([]mdl.BaseAttributeDto, error)
}

// VaultAttributeProvider serves
//   GET /v1/secretProvider/vaults/attributes
type VaultAttributeProvider interface {
	VaultAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error)
}

// VaultProfileAttributeProvider serves
//   POST /v1/secretProvider/vaultProfiles/attributes
//
// The request body carries previously-collected vault attributes that the
// implementation can use to dynamically tailor the returned profile attribute
// definitions (e.g. enumerate vault paths after the user picked a vault).
type VaultProfileAttributeProvider interface {
	VaultProfileAttributes(ctx context.Context, ctxAttrs []mdl.RequestAttribute) ([]mdl.BaseAttributeDto, error)
}

// RotateAttributeProvider serves
//   GET /v1/secretProvider/secrets/rotate/attributes
type RotateAttributeProvider interface {
	RotateAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error)
}
