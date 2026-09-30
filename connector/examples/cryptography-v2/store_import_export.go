package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/x509"
	"encoding/base64"
	"slices"
	"time"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// transferableKeyTypes is what this Store imports and exports: ECDSA P-256
// key pairs. Its secret keys are placeholders with no material to move.
var transferableKeyTypes = []mdl.KeyAlgorithm{mdl.KEYALGORITHM_ECDSA}

// importRecord makes ImportKey idempotent per keyImportId and answers its
// result route. A retry carries the same key under a fresh envelope, so the
// fingerprint covers the key's public key rather than the envelope.
type importRecord struct {
	fingerprint string
	keyID       string
	accepted    bool
	handle      string // set only when accepted
	startedAt   time.Time
	cancelled   bool
}

func (rec *importRecord) status(delay time.Duration) mdl.OperationStatus {
	switch {
	case rec.cancelled:
		return mdl.OPERATIONSTATUS_CANCELLED
	case !rec.accepted || time.Since(rec.startedAt) >= delay:
		return mdl.OPERATIONSTATUS_COMPLETED
	default:
		return mdl.OPERATIONSTATUS_IN_PROGRESS
	}
}

// importKeyEquivalence holds the fields a keyImportId replay must match.
type importKeyEquivalence struct {
	ExecutionMode          mdl.OperationExecutionMode `json:"executionMode"`
	KeyRequestType         mdl.KeyRequestType         `json:"keyRequestType"`
	KeyReference           string                     `json:"keyReference"`
	TokenAttributes        []mdl.RequestAttribute     `json:"tokenAttributes"`
	TokenProfileAttributes []mdl.RequestAttribute     `json:"tokenProfileAttributes"`
	ImportKeyAttributes    []mdl.RequestAttribute     `json:"importKeyAttributes"`
	Exportable             bool                       `json:"exportable"`
	PublicKey              string                     `json:"publicKey"`
}

// openedKey is a P-256 key read out of protected key material.
type openedKey struct {
	privateKeyInfo []byte
	spki           string
}

// openP256Key opens material and keeps it only when it is an ECDSA P-256
// private key; anything else is a key type this Store cannot import.
func openP256Key(material mdl.EncryptedKeyMaterialV2Dto, passphrase string) (*openedKey, error) {
	privateKeyInfo, err := cryptography.OpenKeyMaterial(material, passphrase)
	if err != nil {
		return nil, err
	}
	spki, ok := p256SPKI(privateKeyInfo)
	if !ok {
		clear(privateKeyInfo)
		return nil, cryptography.ErrKeyTypeNotImportable
	}
	return &openedKey{privateKeyInfo: privateKeyInfo, spki: spki}, nil
}

// p256SPKI returns the base64 DER SubjectPublicKeyInfo of the ECDSA P-256
// private key privateKeyInfo holds, or false when it holds anything else.
func p256SPKI(privateKeyInfo []byte) (string, bool) {
	parsed, err := x509.ParsePKCS8PrivateKey(privateKeyInfo)
	key, isECDSA := parsed.(*ecdsa.PrivateKey)
	if err != nil || !isECDSA || key.Curve != elliptic.P256() {
		return "", false
	}
	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		return "", false
	}
	return base64.StdEncoding.EncodeToString(spki), true
}

// --- Provider: key import ------------------------------------------------------

// ImportableKeyTypes reports ECDSA key pairs.
func (s *Store) ImportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ImportableKeyTypeV2Dto, error) {
	return []mdl.ImportableKeyTypeV2Dto{{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Algorithms: transferableKeyTypes}}, nil
}

// ImportKey imports an ECDSA P-256 key pair, synchronously or asynchronously
// per req.ExecutionMode, bound to req.KeyReference. The private key is kept
// only when the key may be exported.
func (s *Store) ImportKey(ctx context.Context, req *mdl.ImportKeyRequestV2Dto) (*mdl.KeyCreationResponse, bool, error) {
	if req.KeyRequestType != mdl.KEYREQUESTTYPE_KEY_PAIR {
		return nil, false, cryptography.ErrKeyTypeNotImportable
	}
	key, err := openP256Key(req.Material, req.Passphrase)
	if err != nil {
		return nil, false, err
	}
	fp := fingerprintOf(importKeyEquivalence{
		ExecutionMode:          req.ExecutionMode,
		KeyRequestType:         req.KeyRequestType,
		KeyReference:           req.KeyReference,
		TokenAttributes:        req.TokenAttributes,
		TokenProfileAttributes: req.TokenProfileAttributes,
		ImportKeyAttributes:    req.ImportKeyAttributes,
		Exportable:             req.Exportable,
		PublicKey:              key.spki,
	})

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, exists := s.imports[req.KeyImportId]; exists {
		clear(key.privateKeyInfo)
		if rec.fingerprint != fp {
			return nil, false, cryptography.ErrKeyImportConflict.WithProperty("keyImportId", req.KeyImportId)
		}
		return s.importResponse(rec), rec.accepted, nil
	}

	keyID := uuid.NewString()
	record := &keyRecord{algorithm: mdl.KEYALGORITHM_ECDSA, length: 256, spki: key.spki, exportable: req.Exportable, keyReference: req.KeyReference}
	if req.Exportable {
		record.privateKeyInfo = key.privateKeyInfo
	} else {
		clear(key.privateKeyInfo)
	}
	s.keys[keyID] = record
	rec := &importRecord{fingerprint: fp, keyID: keyID, startedAt: time.Now()}
	if req.ExecutionMode == mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS {
		rec.accepted = true
		rec.handle = uuid.NewString()
		s.importHandles[rec.handle] = rec
	}
	s.imports[req.KeyImportId] = rec
	return s.importResponse(rec), rec.accepted, nil
}

// importResponse answers an import, first or replayed. Must be called while
// holding s.mu.
func (s *Store) importResponse(rec *importRecord) *mdl.KeyCreationResponse {
	if rec.accepted {
		return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
			OperationMeta:  []mdl.MetadataAttribute{metaAttr(rec.handle, "importKeyOperation", "Import-key operation handle")},
		}}
	}
	return syncKeyCreationResponse(mdl.KEYREQUESTTYPE_KEY_PAIR, rec.keyID, s.keys[rec.keyID])
}

// importStatus reports an import's state, with the key once completed. Must
// be called while holding s.mu.
func (s *Store) importStatus(rec *importRecord) *mdl.KeyCreationStatusResponse {
	status := rec.status(s.asyncDelay)
	resp := &mdl.KeyPairOperationStatusResponseV2Dto{Status: status, KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR}
	switch status {
	case mdl.OPERATIONSTATUS_CANCELLED:
		reason := cancelledReason
		resp.Reason = &reason
	case mdl.OPERATIONSTATUS_COMPLETED:
		record := s.keys[rec.keyID]
		resp.Result = buildKeyPairPayload(rec.keyID, record.algorithm, record.length, record.spki)
	}
	return &mdl.KeyCreationStatusResponse{KeyPairOperationStatusResponseV2Dto: resp}
}

// ImportKeyResult reports the recorded state of the import req.KeyImportId
// names, whichever mode it ran in.
func (s *Store) ImportKeyResult(ctx context.Context, req *mdl.ImportKeyResultRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.imports[req.KeyImportId]
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}
	return s.importStatus(rec), nil
}

// ImportKeyStatus reports an accepted asynchronous import, completed once
// s.asyncDelay has elapsed.
func (s *Store) ImportKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.importHandles[handle]
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}
	return s.importStatus(rec), nil
}

// CancelImportKey aborts an asynchronous import while it is inProgress; the
// key it brought in is destroyed with it.
func (s *Store) CancelImportKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.importHandles[handle]
	if !ok {
		return cryptography.ErrOperationNotTracked
	}
	if rec.status(s.asyncDelay) != mdl.OPERATIONSTATUS_IN_PROGRESS {
		return cryptography.ErrCancelPastPointOfNoReturn
	}
	rec.cancelled = true
	record := s.keys[rec.keyID]
	record.destroyed = true
	clear(record.privateKeyInfo)
	record.privateKeyInfo = nil
	return nil
}

// --- Provider: key export ------------------------------------------------------

// ExportableKeyTypes reports ECDSA key pairs.
func (s *Store) ExportableKeyTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.ExportableKeyTypeV2Dto, error) {
	return []mdl.ExportableKeyTypeV2Dto{{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Algorithms: transferableKeyTypes}}, nil
}

// ExportKey exports an exportable key pair under req.Passphrase, described by
// the public key of the private key it returns and echoing the key's own
// reference when asked for one. The key is protected after s.mu is released,
// so its key derivation holds up no other request.
func (s *Store) ExportKey(ctx context.Context, req *mdl.ExportKeyRequestV2Dto) (*mdl.ExportKeyResponseV2Dto, error) {
	privateKeyInfo, resp, err := s.exportable(req)
	if err != nil {
		return nil, err
	}
	defer clear(privateKeyInfo)
	spki, ok := p256SPKI(privateKeyInfo)
	if !ok {
		return nil, cryptography.ErrKeyTypeNotExportable
	}
	resp.KeyData = mdl.PublicKeyDataV2DtoAsKeyDataV2(mdl.NewPublicKeyDataV2Dto(mdl.KEYALGORITHM_ECDSA, 256, spki))
	material, err := cryptography.ProtectKeyMaterial(privateKeyInfo, req.Passphrase)
	if err != nil {
		return nil, err
	}
	resp.Material = material
	return resp, nil
}

// exportable checks the key req.KeyMeta names may be exported, and returns a
// copy of its private key with the response to describe and protect it into.
func (s *Store) exportable(req *mdl.ExportKeyRequestV2Dto) ([]byte, *mdl.ExportKeyResponseV2Dto, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, nil, cryptography.ErrKeyNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.keys[keyID]
	if !ok || rec.destroyed {
		return nil, nil, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}
	kind := mdl.KEYREQUESTTYPE_SECRET
	if slices.Contains(transferableKeyTypes, rec.algorithm) {
		kind = mdl.KEYREQUESTTYPE_KEY_PAIR
	}
	switch {
	case req.KeyRequestType != kind:
		return nil, nil, cryptography.ErrKeyMaterialMismatch
	case kind != mdl.KEYREQUESTTYPE_KEY_PAIR:
		return nil, nil, cryptography.ErrKeyTypeNotExportable
	case !rec.exportable:
		return nil, nil, cryptography.ErrKeyNotExportable
	}
	privateKeyInfo, err := privateKeyInfoOf(keyID, rec)
	if err != nil {
		return nil, nil, err
	}
	resp := &mdl.ExportKeyResponseV2Dto{}
	if req.KeyReference != nil && rec.keyReference != "" {
		reference := rec.keyReference
		resp.KeyReference = &reference
	}
	return privateKeyInfo, resp, nil
}

// privateKeyInfoOf returns a copy of an imported key's PKCS#8, or the PKCS#8
// of a created pair's derived key.
func privateKeyInfoOf(keyID string, rec *keyRecord) ([]byte, error) {
	if rec.privateKeyInfo != nil {
		return slices.Clone(rec.privateKeyInfo), nil
	}
	return x509.MarshalPKCS8PrivateKey(keyPairFor(keyID))
}
