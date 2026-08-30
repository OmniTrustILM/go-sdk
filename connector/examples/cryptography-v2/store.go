package main

import (
	"context"
	"crypto/ecdh"
	crand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"sync"
	"time"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// defaultAsyncOperationDelay is how long an accepted asynchronous operation
// stays "inProgress" before the Store reports it "completed". Short enough
// for integration tests to poll to completion in under a second.
const defaultAsyncOperationDelay = 500 * time.Millisecond

// cancelledReason is the "reason" text reported for an operation this Store
// cancelled.
const cancelledReason = "cancelled by caller"

// Store is an in-memory Cryptography Provider v2 implementation. Signatures
// and ciphertext are deterministic placeholders that round-trip only within
// this Store; publicKeySpki is genuine DER, because the platform parses it
// (see spkiFor).
//
// A key's handle is the Uuid of a single MetadataAttribute the Store attaches
// to every KeyMeta, KeyPairMeta and operationMeta it returns; callers echo
// that attribute back unchanged. Both halves of a key pair share one Uuid and
// differ only in the attribute's Name.
type Store struct {
	mu sync.Mutex

	keys map[string]*keyRecord // key handle -> record

	creations map[string]*creationRecord // keyCreationId -> record, for idempotent retries

	asyncCreates  map[string]*asyncCreateOp  // create-key operation handle -> op
	asyncDestroys map[string]*asyncDestroyOp // destroy-key operation handle -> op
	asyncSigns    map[string]*asyncSignOp    // sign operation handle -> op

	// asyncDelay overrides defaultAsyncOperationDelay for this Store.
	asyncDelay time.Duration
}

// NewStore builds an empty Store whose asynchronous operations transition
// from inProgress to completed after asyncDelay.
func NewStore(asyncDelay time.Duration) *Store {
	return &Store{
		keys:          make(map[string]*keyRecord),
		creations:     make(map[string]*creationRecord),
		asyncCreates:  make(map[string]*asyncCreateOp),
		asyncDestroys: make(map[string]*asyncDestroyOp),
		asyncSigns:    make(map[string]*asyncSignOp),
		asyncDelay:    asyncDelay,
	}
}

// Compile-time interface assertions.
var (
	_ cryptography.Provider                      = (*Store)(nil)
	_ cryptography.AsyncKeyProvider              = (*Store)(nil)
	_ cryptography.AsyncSignProvider             = (*Store)(nil)
	_ cryptography.TokenAttributeProvider        = (*Store)(nil)
	_ cryptography.TokenProfileAttributeProvider = (*Store)(nil)
	_ cryptography.CreateKeyAttributeProvider    = (*Store)(nil)
	_ cryptography.EncryptAttributeProvider      = (*Store)(nil)
	_ cryptography.DecryptAttributeProvider      = (*Store)(nil)
	_ cryptography.SignAttributeProvider         = (*Store)(nil)
	_ cryptography.VerifyAttributeProvider       = (*Store)(nil)
	_ cryptography.RandomDataAttributeProvider   = (*Store)(nil)
)

// --- Records --------------------------------------------------------------

// keyRecord is what the Store remembers about a created secret key or key
// pair. destroyed is a soft delete: the record survives so a replayed
// keyCreationId can rebuild its response, while every operation on the key
// is rejected.
type keyRecord struct {
	algorithm mdl.KeyAlgorithm
	length    int32
	destroyed bool
}

// creationRecord makes CreateKey idempotent per keyCreationId. An equivalent
// retry (matching fingerprint) replays the original outcome; reusing the id
// for anything else is a conflict.
type creationRecord struct {
	fingerprint    string
	keyID          string
	keyRequestType mdl.KeyRequestType
	accepted       bool
	handle         string // set only when accepted
}

// asyncCreateOp tracks an accepted asynchronous key creation.
type asyncCreateOp struct {
	keyID          string
	keyRequestType mdl.KeyRequestType
	algorithm      mdl.KeyAlgorithm
	length         int32
	startedAt      time.Time
	cancelled      bool
}

func (op *asyncCreateOp) status(delay time.Duration) mdl.OperationStatus {
	if op.cancelled {
		return mdl.OPERATIONSTATUS_CANCELLED
	}
	if time.Since(op.startedAt) >= delay {
		return mdl.OPERATIONSTATUS_COMPLETED
	}
	return mdl.OPERATIONSTATUS_IN_PROGRESS
}

// asyncDestroyOp tracks an accepted asynchronous key destruction.
//
// Destruction is irreversible from the moment it is accepted: on real
// hardware, erasure of key material cannot be walked back once begun. See
// CancelDestroyKey.
type asyncDestroyOp struct {
	startedAt time.Time
}

func (op *asyncDestroyOp) status(delay time.Duration) mdl.OperationStatus {
	if time.Since(op.startedAt) >= delay {
		return mdl.OPERATIONSTATUS_COMPLETED
	}
	return mdl.OPERATIONSTATUS_IN_PROGRESS
}

// signItem is one element of an accepted asynchronous signing batch.
type signItem struct {
	identifier string
	data       string
}

// asyncSignOp tracks an accepted asynchronous signing batch.
type asyncSignOp struct {
	keyID     string
	items     []signItem
	startedAt time.Time
	cancelled bool
}

func (op *asyncSignOp) status(delay time.Duration) mdl.OperationStatus {
	if op.cancelled {
		return mdl.OPERATIONSTATUS_CANCELLED
	}
	if time.Since(op.startedAt) >= delay {
		return mdl.OPERATIONSTATUS_COMPLETED
	}
	return mdl.OPERATIONSTATUS_IN_PROGRESS
}

// --- Metadata-handle helpers ------------------------------------------------

// metaAttr builds a MetadataAttribute carrying id as its Uuid, this Store's
// opaque durable handle. It always populates the MetadataAttributeV2 variant,
// because the oneOf wrapper's zero value marshals to `nil, nil` and would
// silently write an empty response body.
func metaAttr(id, name, label string) mdl.MetadataAttribute {
	return mdl.MetadataAttribute{
		MetadataAttributeV2: &mdl.MetadataAttributeV2{
			Uuid:        id,
			Name:        name,
			Version:     2,
			Type:        mdl.ATTRIBUTETYPE_META,
			ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
			Properties: mdl.MetadataAttributeProperties{
				Label:   label,
				Visible: true,
			},
		},
	}
}

// metaID extracts the handle metaAttr attached to a slice of metadata
// attributes. It checks shape only; callers resolve the handle against their
// own maps.
func metaID(meta []mdl.MetadataAttribute) (string, bool) {
	for _, m := range meta {
		if m.MetadataAttributeV2 != nil && m.MetadataAttributeV2.Uuid != "" {
			return m.MetadataAttributeV2.Uuid, true
		}
		if m.MetadataAttributeV3 != nil && m.MetadataAttributeV3.Uuid != "" {
			return m.MetadataAttributeV3.Uuid, true
		}
	}
	return "", false
}

// --- keyCreationId equivalence ---------------------------------------------

// createKeyEquivalence mirrors the six fields CreateKey defines request
// equivalence over.
type createKeyEquivalence struct {
	KeyRequestType         mdl.KeyRequestType         `json:"keyRequestType"`
	ExecutionMode          mdl.OperationExecutionMode `json:"executionMode"`
	TokenAttributes        []mdl.RequestAttribute     `json:"tokenAttributes"`
	TokenProfileAttributes []mdl.RequestAttribute     `json:"tokenProfileAttributes"`
	KeyUsages              []mdl.KeyUsage             `json:"keyUsages"`
	CreateKeyAttributes    []mdl.RequestAttribute     `json:"createKeyAttributes"`
}

// fingerprintCreateKey hashes the equivalence fields of req into a stable
// string. Requests sharing a fingerprint are equivalent.
func fingerprintCreateKey(req *mdl.CreateKeyRequestV2Dto) string {
	eq := createKeyEquivalence{
		KeyRequestType:         req.KeyRequestType,
		ExecutionMode:          req.ExecutionMode,
		TokenAttributes:        req.TokenAttributes,
		TokenProfileAttributes: req.TokenProfileAttributes,
		KeyUsages:              req.KeyUsages,
		CreateKeyAttributes:    req.CreateKeyAttributes,
	}
	b, err := json.Marshal(eq)
	if err != nil {
		// Fall back to a fingerprint no retry can match, so the failure
		// surfaces as a 409 rather than a wrong replay.
		return "marshal-error:" + err.Error()
	}
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// --- Placeholder crypto helpers ---------------------------------------------
//
// Deterministic stand-ins that let sign/verify and encrypt/decrypt round-trip
// within this Store. Public-key encoding is real; see spkiFor.

// fakeSign derives a deterministic "signature" from the key handle and data,
// so verifying against the same Store recomputes the same value.
func fakeSign(keyID, data string) string {
	sum := sha256.Sum256([]byte("sign:" + keyID + ":" + data))
	return base64.StdEncoding.EncodeToString(sum[:])
}

// fakeKeyStream derives n deterministic bytes from the key handle, repeating
// a sha256 digest as needed.
func fakeKeyStream(keyID string, n int) []byte {
	digest := sha256.Sum256([]byte("cipher:" + keyID))
	out := make([]byte, n)
	for i := range out {
		out[i] = digest[i%len(digest)]
	}
	return out
}

// fakeXor XORs the base64-decoded in with a key-derived stream and
// base64-encodes the result, making it self-inverse. CipherDataV2Dto.data is
// `format: byte`, so plaintext and ciphertext alike cross the wire as base64.
func fakeXor(keyID, in string) (string, error) {
	src, err := base64.StdEncoding.DecodeString(in)
	if err != nil {
		return "", err
	}
	ks := fakeKeyStream(keyID, len(src))
	out := make([]byte, len(src))
	for i := range src {
		out[i] = src[i] ^ ks[i]
	}
	return base64.StdEncoding.EncodeToString(out), nil
}

// fakeEncrypt encrypts base64 plaintext into base64 ciphertext, erroring when
// plaintext is not valid base64.
func fakeEncrypt(keyID, plaintext string) (string, error) {
	return fakeXor(keyID, plaintext)
}

// fakeDecrypt reverses fakeEncrypt. Returns an error when ciphertext is not
// valid base64.
func fakeDecrypt(keyID, ciphertext string) (string, error) {
	return fakeXor(keyID, ciphertext)
}

// --- Public-key encoding ----------------------------------------------------

// spkiFor encodes a deterministic P-256 public key for keyID as a
// base64 DER SubjectPublicKeyInfo. Core parses this field and checks it
// against the declared algorithm and length, so it must be real DER.
func spkiFor(keyID string) string {
	seed := sha256.Sum256([]byte("spki:" + keyID))
	for {
		priv, err := ecdh.P256().NewPrivateKey(seed[:])
		if err != nil {
			// Scalar outside [1, N-1]; rehash to keep the result a total
			// function of keyID.
			seed = sha256.Sum256(seed[:])
			continue
		}
		der, err := x509.MarshalPKIXPublicKey(priv.PublicKey())
		if err != nil {
			panic(fmt.Sprintf("spkiFor: marshal P-256 public key: %v", err))
		}
		return base64.StdEncoding.EncodeToString(der)
	}
}

// randomBytes returns n bytes from the system entropy source, panicking if
// that source fails (mirrors the helper in examples/secret-v1).
func randomBytes(n int) []byte {
	b := make([]byte, n)
	if _, err := crand.Read(b); err != nil {
		panic(fmt.Sprintf("randomBytes: %v", err))
	}
	return b
}

// --- Key-creation payload builders ------------------------------------------

// buildSecretKeyPayload builds the complete secret-key result for keyID, as
// required on a synchronous 200 and inside a completed status result.
func buildSecretKeyPayload(keyID string, algorithm mdl.KeyAlgorithm, length int32) *mdl.SecretKeyDataResponseV2Dto {
	return &mdl.SecretKeyDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		KeyData:        mdl.NewSecretKeyDataV2Dto(algorithm, length),
		KeyMeta:        []mdl.MetadataAttribute{metaAttr(keyID, "secretKeyHandle", "Secret key handle")},
	}
}

// buildKeyPairPayload builds the complete key-pair result for pairID, as
// required on a synchronous 200 and inside a completed status result. Both
// halves carry pairID as their handle, so later calls resolve to the one
// keyRecord tracking the pair.
func buildKeyPairPayload(pairID string, algorithm mdl.KeyAlgorithm, length int32) *mdl.KeyPairDataResponseV2Dto {
	return &mdl.KeyPairDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		PublicKeyData: &mdl.PublicKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metaAttr(pairID, "publicKeyHandle", "Public key handle")},
			KeyData: *mdl.NewPublicKeyDataV2Dto(algorithm, length, spkiFor(pairID)),
		},
		PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metaAttr(pairID, "privateKeyHandle", "Private key handle")},
			KeyData: *mdl.NewPrivateKeyDataV2Dto(algorithm, length),
		},
		KeyPairMeta: []mdl.MetadataAttribute{metaAttr(pairID, "keyPairHandle", "Key pair handle")},
	}
}

// syncKeyCreationResponse wraps the appropriate builder in the
// KeyCreationResponse oneOf, selecting the variant by kind.
func syncKeyCreationResponse(kind mdl.KeyRequestType, keyID string, algorithm mdl.KeyAlgorithm, length int32) *mdl.KeyCreationResponse {
	if kind == mdl.KEYREQUESTTYPE_KEY_PAIR {
		return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: buildKeyPairPayload(keyID, algorithm, length)}
	}
	return &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: buildSecretKeyPayload(keyID, algorithm, length)}
}

// acceptedKeyCreationResponse builds the 202 shape for kind: operationMeta
// carrying handle, and no payload fragment.
func acceptedKeyCreationResponse(kind mdl.KeyRequestType, handle string) *mdl.KeyCreationResponse {
	meta := []mdl.MetadataAttribute{metaAttr(handle, "createKeyOperation", "Create-key operation handle")}
	if kind == mdl.KEYREQUESTTYPE_KEY_PAIR {
		return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			KeyRequestType: kind,
			OperationMeta:  meta,
		}}
	}
	return &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
		KeyRequestType: kind,
		OperationMeta:  meta,
	}}
}

// replayCreateKey rebuilds the response for an equivalent keyCreationId
// retry. Must be called while holding s.mu.
func (s *Store) replayCreateKey(rec *creationRecord) *mdl.KeyCreationResponse {
	if rec.accepted {
		return acceptedKeyCreationResponse(rec.keyRequestType, rec.handle)
	}
	kr := s.keys[rec.keyID]
	return syncKeyCreationResponse(rec.keyRequestType, rec.keyID, kr.algorithm, kr.length)
}

// --- Provider: token and profile introspection ------------------------------

// TokenStatus always reports the token connected; this example has no backend
// to probe.
func (s *Store) TokenStatus(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) (*mdl.TokenStatusResponseV2Dto, error) {
	return &mdl.TokenStatusResponseV2Dto{Status: mdl.TOKENSTATUSV2_CONNECTED}, nil
}

// TokenProfileKeyUsages reports every key usage this example understands.
func (s *Store) TokenProfileKeyUsages(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.KeyUsage, error) {
	return []mdl.KeyUsage{
		mdl.KEYUSAGE_SIGN,
		mdl.KEYUSAGE_VERIFY,
		mdl.KEYUSAGE_ENCRYPT,
		mdl.KEYUSAGE_DECRYPT,
		mdl.KEYUSAGE_WRAP,
		mdl.KEYUSAGE_UNWRAP,
	}, nil
}

// KeyRequestTypes reports both key request types this example supports.
func (s *Store) KeyRequestTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.KeyRequestType, error) {
	return []mdl.KeyRequestType{mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_KEY_PAIR}, nil
}

// --- Provider: key creation and destruction ---------------------------------

// CreateKey creates a secret key or key pair, synchronously or asynchronously
// per req.ExecutionMode. req.KeyCreationId makes this idempotent: a retry
// whose six equivalence fields fingerprint the same as the original replays
// its result (or tracking handle); a non-equivalent reuse of the same id is a
// conflict. A key pair reports ECDSA at 256 bits; a secret key reports
// Unknown.
func (s *Store) CreateKey(ctx context.Context, req *mdl.CreateKeyRequestV2Dto) (*mdl.KeyCreationResponse, bool, error) {
	fp := fingerprintCreateKey(req)

	s.mu.Lock()
	defer s.mu.Unlock()

	if rec, exists := s.creations[req.KeyCreationId]; exists {
		if rec.fingerprint != fp {
			return nil, false, cryptography.ErrKeyCreationConflict.WithProperty("keyCreationId", req.KeyCreationId)
		}
		return s.replayCreateKey(rec), rec.accepted, nil
	}

	keyID := uuid.NewString()
	// ECDSA/256 matches the P-256 key spkiFor encodes. KeyAlgorithm covers
	// only asymmetric algorithms, so a secret key reports Unknown.
	algorithm := mdl.KEYALGORITHM_UNKNOWN
	if req.KeyRequestType == mdl.KEYREQUESTTYPE_KEY_PAIR {
		algorithm = mdl.KEYALGORITHM_ECDSA
	}
	length := int32(256)
	s.keys[keyID] = &keyRecord{algorithm: algorithm, length: length}

	rec := &creationRecord{fingerprint: fp, keyID: keyID, keyRequestType: req.KeyRequestType}

	if req.ExecutionMode == mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS {
		handle := uuid.NewString()
		rec.accepted = true
		rec.handle = handle
		s.creations[req.KeyCreationId] = rec
		s.asyncCreates[handle] = &asyncCreateOp{
			keyID:          keyID,
			keyRequestType: req.KeyRequestType,
			algorithm:      algorithm,
			length:         length,
			startedAt:      time.Now(),
		}
		return acceptedKeyCreationResponse(req.KeyRequestType, handle), true, nil
	}

	s.creations[req.KeyCreationId] = rec
	return syncKeyCreationResponse(req.KeyRequestType, keyID, algorithm, length), false, nil
}

// DestroyKey destroys a key, synchronously or asynchronously per
// req.ExecutionMode. The key is marked destroyed as soon as destruction is
// accepted, since the contract requires rejecting new operations from that
// point rather than on completion.
func (s *Store) DestroyKey(ctx context.Context, req *mdl.DestroyKeyRequestV2Dto) (*mdl.KeyOperationResponseV2Dto, bool, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, false, cryptography.ErrKeyNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.keys[keyID]
	if !ok || rec.destroyed {
		return nil, false, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}
	rec.destroyed = true

	if req.ExecutionMode == mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS {
		handle := uuid.NewString()
		s.asyncDestroys[handle] = &asyncDestroyOp{startedAt: time.Now()}
		meta := []mdl.MetadataAttribute{metaAttr(handle, "destroyKeyOperation", "Destroy-key operation handle")}
		return &mdl.KeyOperationResponseV2Dto{OperationMeta: meta}, true, nil
	}
	return &mdl.KeyOperationResponseV2Dto{}, false, nil
}

// --- Provider: signing, verification, encryption, decryption ---------------

// SignData signs a batch synchronously or asynchronously per
// req.ExecutionMode, using the fakeSign placeholder.
func (s *Store) SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, false, cryptography.ErrKeyNotFound
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.keys[keyID]
	if !ok || rec.destroyed {
		return nil, false, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}

	if req.ExecutionMode == mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS {
		handle := uuid.NewString()
		items := make([]signItem, len(req.Data))
		for i, d := range req.Data {
			items[i] = signItem{identifier: d.Identifier, data: d.Data}
		}
		s.asyncSigns[handle] = &asyncSignOp{keyID: keyID, items: items, startedAt: time.Now()}
		meta := []mdl.MetadataAttribute{metaAttr(handle, "signOperation", "Sign operation handle")}
		return &mdl.SignDataResponseV2Dto{OperationMeta: meta}, true, nil
	}

	sigs := make([]mdl.SignatureDataV2Dto, len(req.Data))
	for i, d := range req.Data {
		sigs[i] = mdl.SignatureDataV2Dto{Identifier: d.Identifier, Data: fakeSign(keyID, d.Data)}
	}
	return &mdl.SignDataResponseV2Dto{Signatures: sigs}, false, nil
}

// VerifyData verifies a batch of signatures against their signed data. Always
// synchronous; the handler guarantees req.Data and req.Signatures carry the
// same identifier set.
func (s *Store) VerifyData(ctx context.Context, req *mdl.VerifyDataRequestV2Dto) (*mdl.VerifyDataResponseV2Dto, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, cryptography.ErrKeyNotFound
	}

	// Capture rec.destroyed under the lock: DestroyKey writes it after the
	// record is published into s.keys, so reading it off the pointer after
	// Unlock would race.
	s.mu.Lock()
	rec, ok := s.keys[keyID]
	destroyed := ok && rec.destroyed
	s.mu.Unlock()
	if !ok || destroyed {
		return nil, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}

	sigByID := make(map[string]string, len(req.Signatures))
	for _, sg := range req.Signatures {
		sigByID[sg.Identifier] = sg.Data
	}
	out := make([]mdl.VerificationResponseItemV2Dto, len(req.Data))
	for i, d := range req.Data {
		out[i] = mdl.VerificationResponseItemV2Dto{
			Identifier: d.Identifier,
			Result:     sigByID[d.Identifier] == fakeSign(keyID, d.Data),
		}
	}
	return &mdl.VerifyDataResponseV2Dto{Verifications: out}, nil
}

// EncryptData encrypts a batch. Always synchronous; a cipherData element that
// is not valid base64 renders 400.
func (s *Store) EncryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.EncryptDataResponseV2Dto, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, cryptography.ErrKeyNotFound
	}

	s.mu.Lock()
	rec, ok := s.keys[keyID]
	destroyed := ok && rec.destroyed
	s.mu.Unlock()
	if !ok || destroyed {
		return nil, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}

	out := make([]mdl.CipherDataV2Dto, len(req.CipherData))
	for i, d := range req.CipherData {
		ct, err := fakeEncrypt(keyID, d.Data)
		if err != nil {
			return nil, cryptography.ErrInvalidRequest.WithProperty("identifier", d.Identifier)
		}
		out[i] = mdl.CipherDataV2Dto{Identifier: d.Identifier, Data: ct}
	}
	return &mdl.EncryptDataResponseV2Dto{EncryptedData: out}, nil
}

// DecryptData decrypts a batch. Always synchronous; a cipherData element that
// is not valid base64 renders 400.
func (s *Store) DecryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.DecryptDataResponseV2Dto, error) {
	keyID, ok := metaID(req.KeyMeta)
	if !ok {
		return nil, cryptography.ErrKeyNotFound
	}

	s.mu.Lock()
	rec, ok := s.keys[keyID]
	destroyed := ok && rec.destroyed
	s.mu.Unlock()
	if !ok || destroyed {
		return nil, cryptography.ErrKeyNotFound.WithProperty("key", keyID)
	}

	out := make([]mdl.CipherDataV2Dto, len(req.CipherData))
	for i, d := range req.CipherData {
		pt, err := fakeDecrypt(keyID, d.Data)
		if err != nil {
			return nil, cryptography.ErrInvalidRequest.WithProperty("identifier", d.Identifier)
		}
		out[i] = mdl.CipherDataV2Dto{Identifier: d.Identifier, Data: pt}
	}
	return &mdl.DecryptDataResponseV2Dto{DecryptedData: out}, nil
}

// RandomData returns req.Length bytes from the system entropy source,
// base64-encoded. Always synchronous.
func (s *Store) RandomData(ctx context.Context, req *mdl.RandomDataRequestV2Dto) (*mdl.RandomDataResponseV2Dto, error) {
	return &mdl.RandomDataResponseV2Dto{Data: base64.StdEncoding.EncodeToString(randomBytes(int(req.Length)))}, nil
}

// --- AsyncKeyProvider --------------------------------------------------------

// CreateKeyStatus reports the state of an accepted asynchronous key creation,
// moving from inProgress to completed once s.asyncDelay has elapsed, or to
// cancelled if CancelCreateKey ran first.
func (s *Store) CreateKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyCreationStatusResponse, error) {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.asyncCreates[handle]
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	status := op.status(s.asyncDelay)
	var reason *string
	if status == mdl.OPERATIONSTATUS_CANCELLED {
		r := cancelledReason
		reason = &r
	}

	if op.keyRequestType == mdl.KEYREQUESTTYPE_KEY_PAIR {
		resp := &mdl.KeyPairOperationStatusResponseV2Dto{Status: status, Reason: reason, KeyRequestType: op.keyRequestType}
		if status == mdl.OPERATIONSTATUS_COMPLETED {
			resp.Result = buildKeyPairPayload(op.keyID, op.algorithm, op.length)
		}
		return &mdl.KeyCreationStatusResponse{KeyPairOperationStatusResponseV2Dto: resp}, nil
	}
	resp := &mdl.SecretKeyOperationStatusResponseV2Dto{Status: status, Reason: reason, KeyRequestType: op.keyRequestType}
	if status == mdl.OPERATIONSTATUS_COMPLETED {
		resp.Result = buildSecretKeyPayload(op.keyID, op.algorithm, op.length)
	}
	return &mdl.KeyCreationStatusResponse{SecretKeyOperationStatusResponseV2Dto: resp}, nil
}

// CancelCreateKey aborts an in-flight asynchronous key creation. It succeeds
// only while the operation is inProgress; otherwise it is refused as past the
// point of no return.
func (s *Store) CancelCreateKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.asyncCreates[handle]
	if !ok {
		return cryptography.ErrOperationNotTracked
	}
	if op.status(s.asyncDelay) != mdl.OPERATIONSTATUS_IN_PROGRESS {
		return cryptography.ErrCancelPastPointOfNoReturn
	}
	op.cancelled = true
	return nil
}

// DestroyKeyStatus reports the state of an accepted asynchronous key
// destruction, moving from inProgress to completed once s.asyncDelay has
// elapsed.
func (s *Store) DestroyKeyStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.KeyDestructionStatusResponseV2Dto, error) {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.asyncDestroys[handle]
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}
	return &mdl.KeyDestructionStatusResponseV2Dto{Status: op.status(s.asyncDelay)}, nil
}

// CancelDestroyKey refuses every known handle with
// ErrCancelPastPointOfNoReturn, since this example models destruction as
// irreversible once accepted (see asyncDestroyOp).
func (s *Store) CancelDestroyKey(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, ok := s.asyncDestroys[handle]; !ok {
		return cryptography.ErrOperationNotTracked
	}
	return cryptography.ErrCancelPastPointOfNoReturn
}

// --- AsyncSignProvider -------------------------------------------------------

// SignDataStatus reports the per-item state of an accepted asynchronous
// signing batch. Every item shares the batch status, gaining a signature once
// completed or cancelledReason once cancelled.
func (s *Store) SignDataStatus(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) (*mdl.SignOperationStatusResponseV2Dto, error) {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.asyncSigns[handle]
	if !ok {
		return nil, cryptography.ErrOperationNotTracked
	}

	status := op.status(s.asyncDelay)
	items := make([]mdl.SignatureResultItemV2Dto, len(op.items))
	for i, it := range op.items {
		item := mdl.SignatureResultItemV2Dto{Identifier: it.identifier, Status: status}
		switch status {
		case mdl.OPERATIONSTATUS_COMPLETED:
			sig := fakeSign(op.keyID, it.data)
			item.Signature = &sig
		case mdl.OPERATIONSTATUS_CANCELLED:
			reason := cancelledReason
			item.Reason = &reason
		}
		items[i] = item
	}
	return &mdl.SignOperationStatusResponseV2Dto{Items: items}, nil
}

// CancelSignData aborts an in-flight asynchronous signing batch. Same
// succeeds-only-while-inProgress semantics as CancelCreateKey.
func (s *Store) CancelSignData(ctx context.Context, req *mdl.OperationTrackingRequestV2Dto) error {
	handle, ok := metaID(req.OperationMeta)
	if !ok {
		return cryptography.ErrOperationNotTracked
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	op, ok := s.asyncSigns[handle]
	if !ok {
		return cryptography.ErrOperationNotTracked
	}
	if op.status(s.asyncDelay) != mdl.OPERATIONSTATUS_IN_PROGRESS {
		return cryptography.ErrCancelPastPointOfNoReturn
	}
	op.cancelled = true
	return nil
}

// --- Attribute schema providers ---------------------------------------------
//
// This example declares no mandatory attributes, so every method returns an
// empty schema. Registering them exercises the wiring, letting the
// integration tests assert a 200 with `[]`.

// TokenAttributes reports the token attribute schema: none for this example.
func (s *Store) TokenAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// TokenProfileAttributes reports the token profile attribute schema: none for
// this example.
func (s *Store) TokenProfileAttributes(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// CreateKeyAttributes reports the key creation attribute schema: none for
// this example.
func (s *Store) CreateKeyAttributes(ctx context.Context, req *mdl.CreateKeyAttributesRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// EncryptAttributes reports the encryption attribute schema: none for this
// example.
func (s *Store) EncryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// DecryptAttributes reports the decryption attribute schema: none for this
// example.
func (s *Store) DecryptAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// SignAttributes reports the signing attribute schema: none for this example.
func (s *Store) SignAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// VerifyAttributes reports the verification attribute schema: none for this
// example.
func (s *Store) VerifyAttributes(ctx context.Context, req *mdl.KeyScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}

// RandomDataAttributes reports the random-data attribute schema: none for
// this example.
func (s *Store) RandomDataAttributes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}
