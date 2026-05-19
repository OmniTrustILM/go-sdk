// Package cryptography provides the HTTP server adapter for the Cryptography
// Provider API. Connector authors implement the Provider interface (and any
// subset of the optional attribute provider sub-interfaces) and register
// the resulting Handler with shared.Connector.
//
// Cryptography is a v1-family info/health spec: it uses /v1
// listSupportedFunctions for info and /v1/health for health checks. Wire
// shared.WithErrorRenderer(shared.WriteV1Error) on the Connector.
package cryptography

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
)

// Provider is the core business contract every Cryptography Provider
// connector must implement. Methods correspond 1:1 to the operations in
// cryptography.json. The interface is large; see the section headers below
// for the logical groupings.
//
// Returned errors should be *shared.Error. Plain errors are rendered as 500
// INTERNAL_ERROR via WriteV1Error.
type Provider interface {
	// --- Token instance management --------------------------------------

	ListTokenInstances(ctx context.Context) ([]mdl.TokenInstanceDto, error)
	CreateTokenInstance(ctx context.Context, req *mdl.TokenInstanceRequestDto) (*mdl.TokenInstanceDto, error)
	GetTokenInstance(ctx context.Context, uuid string) (*mdl.TokenInstanceDto, error)
	UpdateTokenInstance(ctx context.Context, uuid string, req *mdl.TokenInstanceRequestDto) (*mdl.TokenInstanceDto, error)
	RemoveTokenInstance(ctx context.Context, uuid string) error
	GetTokenInstanceStatus(ctx context.Context, uuid string) (*mdl.TokenInstanceStatusDto, error)

	// ActivateTokenInstance carries the activation attribute payload as a
	// flat array (PATCH /tokens/{uuid}/activate).
	ActivateTokenInstance(ctx context.Context, uuid string, attrs []mdl.RequestAttribute) error
	DeactivateTokenInstance(ctx context.Context, uuid string) error

	// --- Key management -------------------------------------------------

	ListKeys(ctx context.Context, tokenUuid string) ([]mdl.KeyDataResponseDto, error)
	GetKey(ctx context.Context, tokenUuid, keyUuid string) (*mdl.KeyDataResponseDto, error)
	DestroyKey(ctx context.Context, tokenUuid, keyUuid string) error

	CreateSecretKey(ctx context.Context, tokenUuid string, req *mdl.CreateKeyRequestDto) (*mdl.KeyDataResponseDto, error)
	CreateKeyPair(ctx context.Context, tokenUuid string, req *mdl.CreateKeyRequestDto) (*mdl.KeyPairDataResponseDto, error)
	RandomData(ctx context.Context, tokenUuid string, req *mdl.RandomDataRequestDto) (*mdl.RandomDataResponseDto, error)

	// --- Cryptographic operations ---------------------------------------

	SignData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.SignDataRequestDto) (*mdl.SignDataResponseDto, error)
	VerifyData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.VerifyDataRequestDto) (*mdl.VerifyDataResponseDto, error)
	EncryptData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.CipherDataRequestDto) (*mdl.EncryptDataResponseDto, error)
	DecryptData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.CipherDataRequestDto) (*mdl.DecryptDataResponseDto, error)
}
