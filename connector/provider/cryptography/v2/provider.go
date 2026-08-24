// Package cryptography implements the Cryptography Provider v2 connector
// interface: token status and attribute schemas, key creation and destruction
// with caller-selected execution modes, batch sign and verify, encrypt and
// decrypt, and random-data generation.
//
// Every operation carries its scope in the request body, so all 24 route
// patterns are literal and this package composes with any other provider
// package on one mux.
package cryptography

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// Provider is the surface every v2 cryptography connector implements. A
// synchronous-only connector — the expected shape for a PKCS#11 token —
// implements exactly these ten methods and always returns accepted == false.
//
// Optional surfaces live in separate interfaces: the eight attribute schemas
// in attributes.go, and the six status/cancel endpoints in AsyncKeyProvider
// and AsyncSignProvider.
//
// The handler rejects empty and duplicate-bearing batch lists with 422 before
// any method here runs, so an implementation may assume every list the
// contract marks minItems: 1 has at least one element.
type Provider interface {
	// TokenStatus reports whether the token described by req.TokenAttributes
	// is reachable and usable.
	TokenStatus(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) (*mdl.TokenStatusResponseV2Dto, error)

	// TokenProfileKeyUsages lists the key usages the token profile supports.
	TokenProfileKeyUsages(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.KeyUsage, error)

	// KeyRequestTypes lists the key request types the token profile supports.
	KeyRequestTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.KeyRequestType, error)

	// CreateKey creates a secret key or key pair. accepted == false renders
	// 200 with the created key; true renders 202 with the operationMeta
	// tracking handle.
	//
	// The handler has already validated req and rejects, as a provider bug, a
	// response whose shape contradicts accepted. Implementers must:
	//   - populate exactly one oneOf arm and set its keyRequestType
	//     discriminator to the value naming that arm ("secret" or "keyPair"),
	//     which is how Core resolves the oneOf
	//   - return the complete payload and no operationMeta on 200, and
	//     operationMeta alone on 202
	//   - honor req.KeyCreationId as an idempotency key: an equivalent retry
	//     returns the original result or handle, and non-equivalent reuse
	//     returns ErrKeyCreationConflict. Equivalence covers KeyRequestType,
	//     ExecutionMode, TokenAttributes, TokenProfileAttributes, KeyUsages
	//     and CreateKeyAttributes.
	//   - validate publicKeySpki's DER encoding and its agreement with the
	//     declared algorithm and length, and MetadataAttribute; these need
	//     crypto knowledge or connector-specific attribute equality.
	//
	// Returning accepted == false for an asynchronous request is a provider
	// bug: Core requires HTTP 202 for that mode. A connector that cannot
	// execute asynchronously must leave FEATUREFLAG_ASYNCHRONOUS unadvertised
	// so Core never selects the mode.
	CreateKey(ctx context.Context, req *mdl.CreateKeyRequestV2Dto) (resp *mdl.KeyCreationResponse, accepted bool, err error)

	// DestroyKey destroys a key, with CreateKey's accepted semantics. After
	// accepting asynchronous destruction the connector must reject new
	// cryptographic operations for that key.
	//
	// The handler rejects, as a provider bug, an operationMeta that
	// contradicts accepted.
	DestroyKey(ctx context.Context, req *mdl.DestroyKeyRequestV2Dto) (resp *mdl.KeyOperationResponseV2Dto, accepted bool, err error)

	// SignData signs a batch, with CreateKey's accepted semantics: a
	// synchronous 200 carries the signatures inline, an asynchronous 202
	// carries one operationMeta handle for the whole batch.
	//
	// The handler has already rejected identifiers that repeat within
	// req.Data, and rejects a response whose shape contradicts accepted.
	//
	// Signing has no idempotency key: per the contract, a lost accepted
	// response cannot have its handle recovered and a retry starts a new
	// batch.
	SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (resp *mdl.SignDataResponseV2Dto, accepted bool, err error)

	// VerifyData verifies signatures. Always synchronous. The handler has
	// already rejected identifiers that repeat within req.Data or
	// req.Signatures, and required the two identifier sets to be equal.
	VerifyData(ctx context.Context, req *mdl.VerifyDataRequestV2Dto) (*mdl.VerifyDataResponseV2Dto, error)

	// EncryptData encrypts a batch. Always synchronous. The handler has
	// already rejected identifiers that repeat within req.CipherData.
	EncryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.EncryptDataResponseV2Dto, error)

	// DecryptData decrypts a batch. Always synchronous. The handler has
	// already rejected identifiers that repeat within req.CipherData.
	DecryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.DecryptDataResponseV2Dto, error)

	// RandomData generates random bytes on the token. Always synchronous. The
	// handler has already required req.Length to be positive and at most
	// 1,048,576 bytes (1 MiB).
	RandomData(ctx context.Context, req *mdl.RandomDataRequestV2Dto) (*mdl.RandomDataResponseV2Dto, error)
}

// AsyncKeyProvider is implemented by connectors that accept key creation or
// destruction for asynchronous execution. Register it with WithAsyncKeys; the
// four routes are mounted only then, and otherwise answer 404, which the
// contract documents as "endpoint not found or not implemented".
//
// Advertise the feature alongside it with
// Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_ASYNCHRONOUS))):
// FeatureFlag.ASYNCHRONOUS is ENFORCED, so Core gates these operations on it
// and leaves the endpoints unreachable without it.
//
// Tracking handles must be durable: they survive connector restarts and remain
// valid for the operation's entire tracking lifetime, including after it
// reaches a terminal state.
type AsyncKeyProvider interface {
	// CreateKeyStatus reports the state of an async key creation. Unknown
	// handles must return ErrOperationNotTracked.
	//
	// The handler rejects, as a provider bug, a reason or result that
	// contradicts status: reason accompanies failed and cancelled, result
	// accompanies completed. The status arms carry CreateKey's keyRequestType
	// discriminator and it is checked the same way.
	CreateKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error)

	// CancelCreateKey aborts an in-flight async key creation. Nil error renders
	// 204; ErrCancelPastPointOfNoReturn renders 422; ErrOperationNotTracked
	// renders 404.
	CancelCreateKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error

	// DestroyKeyStatus reports the state of an async key destruction, with
	// CreateKeyStatus's semantics. KeyDestructionStatusResponseV2Dto carries
	// status and reason, so the reason rule alone applies.
	DestroyKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyDestructionStatusResponseV2Dto, error)

	// CancelDestroyKey aborts an in-flight async key destruction, with
	// CancelCreateKey's semantics.
	CancelDestroyKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error
}

// AsyncSignProvider is implemented by connectors that accept signing batches
// for asynchronous execution. Register it with WithAsyncSign; AsyncKeyProvider's
// mounting rule and ENFORCED-flag caveat apply here too.
type AsyncSignProvider interface {
	// SignDataStatus reports the state of an async signing batch. Unknown
	// handles must return ErrOperationNotTracked.
	//
	// Each element of Items carries its own status, so the handler checks the
	// reason/signature-matches-status rule once per item.
	SignDataStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.SignOperationStatusResponseV2Dto, error)

	// CancelSignData aborts an in-flight async signing batch. Nil error renders
	// 204; ErrCancelPastPointOfNoReturn renders 422; ErrOperationNotTracked
	// renders 404.
	CancelSignData(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error
}
