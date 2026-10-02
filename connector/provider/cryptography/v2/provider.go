// Package cryptography implements the Cryptography Provider v2 connector
// interface: token status and attribute schemas, key creation and destruction
// with caller-selected execution modes, batch sign and verify, encrypt and
// decrypt, random-data generation, and the import and export of protected
// key material.
//
// Every operation carries its scope in the request body, so every route
// pattern is literal and this package composes with any other provider
// package on one mux.
package cryptography

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// Provider is the surface every v2 cryptography connector implements. A
// synchronous-only connector implements these ten methods and always returns
// accepted == false; attribute schemas and async status/cancel live in separate
// interfaces.
//
// The handler rejects empty and duplicate-bearing batch lists with 422 before
// any method here runs.
//
// req.KeyMeta and operationMeta are caller-supplied selectors the SDK cannot
// check. Authorize both against the requesting principal; a connector that
// resolves keyMeta without checking lets the caller choose which key signs or
// decrypts.
//
// Free-text fields the connector emits reach the caller: status reasons,
// TokenStatusResponseV2Dto.detail and VerificationResponseItemV2Dto.details.
// Sanitize them; never expose exception messages, slot numbers, key labels,
// CKA_ID values or stack frames.
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
	// tracking handle. The handler rejects a response whose shape contradicts
	// accepted. Implementers must:
	//   - populate exactly one oneOf arm and set keyRequestType to the value
	//     naming it ("secret" or "keyPair")
	//   - return the complete payload and no operationMeta on 200, and
	//     operationMeta alone on 202
	//   - honor req.KeyCreationId as an idempotency key over KeyRequestType,
	//     ExecutionMode, TokenAttributes, TokenProfileAttributes and
	//     CreateKeyAttributes. Non-equivalent reuse returns
	//     ErrKeyCreationConflict.
	//   - validate publicKeySpki's DER encoding and algorithm, plus RSA public
	//     length against its modulus
	//   - validate MetadataAttribute
	//
	// A connector that cannot execute asynchronously must leave
	// FEATUREFLAG_ASYNCHRONOUS unadvertised; Core requires 202 for that mode.
	CreateKey(ctx context.Context, req *mdl.CreateKeyRequestV2Dto) (resp *mdl.KeyCreationResponse, accepted bool, err error)

	// DestroyKey destroys a key, with CreateKey's accepted semantics. After
	// accepting asynchronous destruction the connector must reject new
	// operations for that key.
	DestroyKey(ctx context.Context, req *mdl.DestroyKeyRequestV2Dto) (resp *mdl.KeyOperationResponseV2Dto, accepted bool, err error)

	// SignData signs a batch, with CreateKey's accepted semantics; a 202
	// carries one operationMeta handle for the whole batch. There is no
	// idempotency key: a retry after a lost accepted response starts a new
	// batch. Implementers must sign with the algorithm read by SelectedSignatureAlgorithm,
	// and refuse one the key lacks with ErrSignatureAlgorithmUnsupported.
	SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (resp *mdl.SignDataResponseV2Dto, accepted bool, err error)

	// VerifyData verifies signatures. Always synchronous; the handler requires
	// req.Data and req.Signatures to carry the same identifiers.
	VerifyData(ctx context.Context, req *mdl.VerifyDataRequestV2Dto) (*mdl.VerifyDataResponseV2Dto, error)

	// EncryptData encrypts a batch. Always synchronous. Implementers must
	// encrypt with the algorithm read by SelectedEncryptionAlgorithm, and
	// refuse one the key lacks with ErrEncryptionAlgorithmUnsupported.
	EncryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.EncryptDataResponseV2Dto, error)

	// DecryptData decrypts a batch. Always synchronous. Implementers must
	// decrypt with the algorithm read by SelectedEncryptionAlgorithm, and
	// refuse one the key lacks with ErrEncryptionAlgorithmUnsupported.
	DecryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.DecryptDataResponseV2Dto, error)

	// RandomData generates random bytes. Always synchronous; req.Length is
	// between 1 and 1 MiB. The response data must be standard padded base64
	// of exactly req.Length bytes.
	RandomData(ctx context.Context, req *mdl.RandomDataRequestV2Dto) (*mdl.RandomDataResponseV2Dto, error)
}

// AsyncKeyProvider is implemented by connectors that accept key creation or
// destruction for asynchronous execution. Register it with WithAsyncKeys and
// advertise FeatureFlag.ASYNCHRONOUS via Base(handlerbase.WithFeatures(...));
// the flag is ENFORCED, so Core gates these operations on it.
//
// Tracking handles must survive connector restarts and stay valid through the
// terminal state. The handle is also the sole authorization for status and
// cancel, so treat it as a capability token: at least 128 bits from a CSPRNG,
// bound to the tenant, compared in constant time.
type AsyncKeyProvider interface {
	// CreateKeyStatus reports the state of an async key creation. Unknown
	// handles must return ErrOperationNotTracked; the handler rejects a
	// reason or result that contradicts status.
	CreateKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error)

	// CancelCreateKey aborts an in-flight async key creation. Nil error renders
	// 204; ErrCancelPastPointOfNoReturn renders 422; ErrOperationNotTracked
	// renders 404.
	CancelCreateKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error

	// DestroyKeyStatus reports the state of an async key destruction, with
	// CreateKeyStatus's semantics.
	DestroyKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyDestructionStatusResponseV2Dto, error)

	// CancelDestroyKey aborts an in-flight async key destruction, with
	// CancelCreateKey's semantics.
	CancelDestroyKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error
}

// AsyncSignProvider is implemented by connectors that accept signing batches
// for asynchronous execution. Register it with WithAsyncSign; AsyncKeyProvider's
// feature-flag and handle rules apply here too.
type AsyncSignProvider interface {
	// SignDataStatus reports the state of an async signing batch. Unknown
	// handles must return ErrOperationNotTracked; the handler checks the
	// reason/signature rule per item.
	SignDataStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.SignOperationStatusResponseV2Dto, error)

	// CancelSignData aborts an in-flight async signing batch. Nil error renders
	// 204; ErrCancelPastPointOfNoReturn renders 422; ErrOperationNotTracked
	// renders 404.
	CancelSignData(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error
}

// KeyImportProvider is implemented by connectors that import protected key
// material into their technology. Register it with WithKeyImport and
// advertise FeatureFlag.KEY_IMPORT via Base(handlerbase.WithFeatures(...));
// the flag is ENFORCED, so Core sends imports only to a connector that
// advertises it.
//
// An import request carries the key and the passphrase that opens it, so it
// is as sensitive as the key itself: never log it, and keep neither the
// material, the passphrase nor the opened key once the key is stored.
type KeyImportProvider interface {
	// ImportableKeyTypes lists the key types the token context can import,
	// each once, with the algorithms accepted for it. Unknown cannot be
	// declared.
	ImportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ImportableKeyTypeV2Dto, error)

	// ImportKey imports req.Material, with CreateKey's accepted semantics and
	// response shape. The handler has checked the envelope against the pinned
	// profile; open it with OpenKeyMaterial. Implementers must:
	//   - check req.KeyRequestType against the importable key types before
	//     decrypting anything, and refuse a mismatch with
	//     ErrKeyTypeNotImportable
	//   - refuse material of another type or algorithm than declared with
	//     ErrKeyMaterialMismatch, and an exportable key the token cannot keep
	//     exportable with ErrExportableNotSupported
	//   - bind req.KeyReference to the key in the technology, or keep a
	//     durable record of it
	//   - honor req.KeyImportId as an idempotency key over ExecutionMode,
	//     KeyRequestType, KeyReference, TokenAttributes,
	//     TokenProfileAttributes, ImportKeyAttributes, Exportable and the
	//     imported key itself, not the envelope, which changes on every
	//     submission. Non-equivalent reuse returns ErrKeyImportConflict.
	ImportKey(ctx context.Context, req *mdl.ImportKeyRequestV2Dto) (resp *mdl.KeyCreationResponse, accepted bool, err error)

	// ImportKeyResult reports the recorded state of the import
	// req.KeyImportId names, running or final, whichever mode it ran in.
	// Records are kept at least 24 hours after an import reaches a final
	// state; an import never accepted returns ErrOperationNotTracked.
	ImportKeyResult(ctx context.Context, req *mdl.ImportKeyResultRequestV2Dto) (*mdl.KeyCreationStatusResponse, error)
}

// AsyncKeyImportProvider is implemented by connectors that accept key imports
// for asynchronous execution. Register it with WithAsyncKeyImport; a
// connector that advertises both FeatureFlag.ASYNCHRONOUS and
// FeatureFlag.KEY_IMPORT must. AsyncKeyProvider's handle rules apply here too.
type AsyncKeyImportProvider interface {
	// ImportKeyStatus reports the state of an async key import, with
	// CreateKeyStatus's semantics.
	ImportKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error)

	// CancelImportKey aborts an in-flight async key import, with
	// CancelCreateKey's semantics.
	CancelImportKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error
}

// KeyExportProvider is implemented by connectors that export keys as
// protected key material. Register it with WithKeyExport and advertise
// FeatureFlag.KEY_EXPORT; the flag is ENFORCED. A connector that declares it
// publishes KeyExportableDefinition in its create-key attribute schema and
// sets the technology's extractability from SelectedKeyExportable when it
// creates a key.
//
// The request carries the passphrase and the response the envelope it
// protects: never log either.
type KeyExportProvider interface {
	// ExportableKeyTypes lists the key types the token context can export,
	// each once, with the algorithms accepted for it. Unknown cannot be
	// declared.
	ExportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ExportableKeyTypeV2Dto, error)

	// ExportKey exports the key req.KeyMeta identifies, protected with
	// ProtectKeyMaterial under req.Passphrase. Always synchronous.
	// Implementers must:
	//   - refuse a key not created or imported as exportable with
	//     ErrKeyNotExportable, a key type the token will not release with
	//     ErrKeyTypeNotExportable, and a key of another type than
	//     req.KeyRequestType with ErrKeyMaterialMismatch
	//   - describe the exported key in KeyData from the material itself: a key
	//     pair by its public key, a secret key by its algorithm and length
	//   - echo the key's own reference when req.KeyReference is set, and
	//     return none when it is not
	ExportKey(ctx context.Context, req *mdl.ExportKeyRequestV2Dto) (*mdl.ExportKeyResponseV2Dto, error)
}
