package main

import (
	"context"
	crand "crypto/rand"
	"encoding/base64"
	"sync"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v1"
)

// Store is a minimal in-memory Cryptography Provider. Token instances and
// keys are kept in memory only; crypto operations return placeholder bytes.
// Scope is wiring verification, not real cryptography.
type Store struct {
	mu     sync.RWMutex
	tokens map[string]*tokenEntry
	keys   map[string]map[string]*keyEntry // tokenUuid -> keyUuid -> key
}

type tokenEntry struct {
	uuid       string
	name       string
	kind       string
	attributes []mdl.RequestAttribute
	status     mdl.TokenInstanceStatus
}

type keyEntry struct {
	uuid     string
	name     string
	keyType  mdl.KeyType
	rawValue string // base64
}

func NewStore() *Store {
	return &Store{
		tokens: make(map[string]*tokenEntry),
		keys:   make(map[string]map[string]*keyEntry),
	}
}

// --- Token instance management ------------------------------------------

func (s *Store) ListTokenInstances(ctx context.Context) ([]mdl.TokenInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]mdl.TokenInstanceDto, 0, len(s.tokens))
	for _, t := range s.tokens {
		out = append(out, mdl.TokenInstanceDto{
			Uuid:     t.uuid,
			Name:     t.name,
			Metadata: []mdl.MetadataAttribute{},
		})
	}
	return out, nil
}

func (s *Store) CreateTokenInstance(ctx context.Context, req *mdl.TokenInstanceRequestDto) (*mdl.TokenInstanceDto, error) {
	if req == nil || req.Name == "" || req.Kind == "" {
		return nil, cryptography.ErrInvalidRequest.WithProperty("reason", "name and kind are required")
	}
	id := uuid.NewString()
	s.mu.Lock()
	s.tokens[id] = &tokenEntry{
		uuid:       id,
		name:       req.Name,
		kind:       req.Kind,
		attributes: req.Attributes,
		status:     mdl.TOKENINSTANCESTATUS_DEACTIVATED,
	}
	s.keys[id] = make(map[string]*keyEntry)
	s.mu.Unlock()
	return &mdl.TokenInstanceDto{
		Uuid:     id,
		Name:     req.Name,
		Metadata: []mdl.MetadataAttribute{},
	}, nil
}

func (s *Store) GetTokenInstance(ctx context.Context, id string) (*mdl.TokenInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	return &mdl.TokenInstanceDto{
		Uuid:     t.uuid,
		Name:     t.name,
		Metadata: []mdl.MetadataAttribute{},
	}, nil
}

func (s *Store) UpdateTokenInstance(ctx context.Context, id string, req *mdl.TokenInstanceRequestDto) (*mdl.TokenInstanceDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	t.name = req.Name
	t.kind = req.Kind
	t.attributes = req.Attributes
	return &mdl.TokenInstanceDto{
		Uuid:     t.uuid,
		Name:     t.name,
		Metadata: []mdl.MetadataAttribute{},
	}, nil
}

func (s *Store) RemoveTokenInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[id]; !ok {
		return cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	delete(s.tokens, id)
	delete(s.keys, id)
	return nil
}

func (s *Store) GetTokenInstanceStatus(ctx context.Context, id string) (*mdl.TokenInstanceStatusDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	t, ok := s.tokens[id]
	if !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	return &mdl.TokenInstanceStatusDto{Status: t.status}, nil
}

func (s *Store) ActivateTokenInstance(ctx context.Context, id string, attrs []mdl.RequestAttribute) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	t.status = mdl.TOKENINSTANCESTATUS_ACTIVATED
	return nil
}

func (s *Store) DeactivateTokenInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	t, ok := s.tokens[id]
	if !ok {
		return cryptography.ErrTokenNotFound.WithProperty("uuid", id)
	}
	t.status = mdl.TOKENINSTANCESTATUS_DEACTIVATED
	return nil
}

// --- Key management -----------------------------------------------------

func (s *Store) ListKeys(ctx context.Context, tokenUuid string) ([]mdl.KeyDataResponseDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	tokenKeys := s.keys[tokenUuid]
	out := make([]mdl.KeyDataResponseDto, 0, len(tokenKeys))
	for _, k := range tokenKeys {
		out = append(out, keyToDTO(k))
	}
	return out, nil
}

func (s *Store) GetKey(ctx context.Context, tokenUuid, keyUuid string) (*mdl.KeyDataResponseDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	k, ok := s.keys[tokenUuid][keyUuid]
	if !ok {
		return nil, cryptography.ErrKeyNotFound.WithProperty("keyUuid", keyUuid)
	}
	out := keyToDTO(k)
	return &out, nil
}

func (s *Store) DestroyKey(ctx context.Context, tokenUuid, keyUuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	if _, ok := s.keys[tokenUuid][keyUuid]; !ok {
		return cryptography.ErrKeyNotFound.WithProperty("keyUuid", keyUuid)
	}
	delete(s.keys[tokenUuid], keyUuid)
	return nil
}

func (s *Store) CreateSecretKey(ctx context.Context, tokenUuid string, req *mdl.CreateKeyRequestDto) (*mdl.KeyDataResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	k := &keyEntry{
		uuid:     uuid.NewString(),
		name:     "secret-" + uuid.NewString()[:8],
		keyType:  mdl.KEYTYPE_SECRET,
		rawValue: randomB64(32),
	}
	s.keys[tokenUuid][k.uuid] = k
	out := keyToDTO(k)
	return &out, nil
}

func (s *Store) CreateKeyPair(ctx context.Context, tokenUuid string, req *mdl.CreateKeyRequestDto) (*mdl.KeyPairDataResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return nil, cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	assoc := uuid.NewString()
	pub := &keyEntry{
		uuid:     uuid.NewString(),
		name:     "pub-" + assoc[:8],
		keyType:  mdl.KEYTYPE_PUBLIC,
		rawValue: randomB64(64),
	}
	priv := &keyEntry{
		uuid:     uuid.NewString(),
		name:     "priv-" + assoc[:8],
		keyType:  mdl.KEYTYPE_PRIVATE,
		rawValue: randomB64(64),
	}
	s.keys[tokenUuid][pub.uuid] = pub
	s.keys[tokenUuid][priv.uuid] = priv

	pubDTO := keyToDTO(pub)
	privDTO := keyToDTO(priv)
	pubDTO.Association = &assoc
	privDTO.Association = &assoc

	return &mdl.KeyPairDataResponseDto{
		PublicKeyData:  pubDTO,
		PrivateKeyData: privDTO,
	}, nil
}

func (s *Store) RandomData(ctx context.Context, tokenUuid string, req *mdl.RandomDataRequestDto) (*mdl.RandomDataResponseDto, error) {
	if req == nil || req.Length <= 0 {
		return nil, cryptography.ErrInvalidRequest.WithProperty("reason", "length must be > 0")
	}
	return &mdl.RandomDataResponseDto{Data: randomB64(int(req.Length))}, nil
}

// --- Crypto operations --------------------------------------------------

func (s *Store) SignData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.SignDataRequestDto) (*mdl.SignDataResponseDto, error) {
	if err := s.requireKey(tokenUuid, keyUuid); err != nil {
		return nil, err
	}
	out := &mdl.SignDataResponseDto{Signatures: []mdl.SignatureResponseData{}}
	if req == nil {
		return out, nil
	}
	for _, d := range req.Data {
		sig := mdl.SignatureResponseData{
			Data:       randomB64(32),
			Identifier: d.Identifier,
		}
		out.Signatures = append(out.Signatures, sig)
	}
	return out, nil
}

func (s *Store) VerifyData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.VerifyDataRequestDto) (*mdl.VerifyDataResponseDto, error) {
	if err := s.requireKey(tokenUuid, keyUuid); err != nil {
		return nil, err
	}
	out := &mdl.VerifyDataResponseDto{Verifications: []mdl.VerificationResponseData{}}
	if req == nil {
		return out, nil
	}
	for _, d := range req.Signatures {
		out.Verifications = append(out.Verifications, mdl.VerificationResponseData{
			Result:     true,
			Identifier: d.Identifier,
		})
	}
	return out, nil
}

func (s *Store) EncryptData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.CipherDataRequestDto) (*mdl.EncryptDataResponseDto, error) {
	if err := s.requireKey(tokenUuid, keyUuid); err != nil {
		return nil, err
	}
	out := &mdl.EncryptDataResponseDto{EncryptedData: []mdl.CipherResponseData{}}
	if req == nil {
		return out, nil
	}
	for _, d := range req.CipherData {
		out.EncryptedData = append(out.EncryptedData, mdl.CipherResponseData{
			Data:       d.Data, // placeholder pass-through
			Identifier: d.Identifier,
		})
	}
	return out, nil
}

func (s *Store) DecryptData(ctx context.Context, tokenUuid, keyUuid string, req *mdl.CipherDataRequestDto) (*mdl.DecryptDataResponseDto, error) {
	if err := s.requireKey(tokenUuid, keyUuid); err != nil {
		return nil, err
	}
	out := &mdl.DecryptDataResponseDto{DecryptedData: []mdl.CipherResponseData{}}
	if req == nil {
		return out, nil
	}
	for _, d := range req.CipherData {
		out.DecryptedData = append(out.DecryptedData, mdl.CipherResponseData{
			Data:       d.Data,
			Identifier: d.Identifier,
		})
	}
	return out, nil
}

// --- Helpers ------------------------------------------------------------

// requireKey returns an error if the token or key does not exist. Lock-free
// since callers do not need write access for crypto ops.
func (s *Store) requireKey(tokenUuid, keyUuid string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.tokens[tokenUuid]; !ok {
		return cryptography.ErrTokenNotFound.WithProperty("uuid", tokenUuid)
	}
	if _, ok := s.keys[tokenUuid][keyUuid]; !ok {
		return cryptography.ErrKeyNotFound.WithProperty("keyUuid", keyUuid)
	}
	return nil
}

// keyToDTO must be called while holding s.mu (read or write).
func keyToDTO(k *keyEntry) mdl.KeyDataResponseDto {
	raw := &mdl.RawKeyValue{Value: k.rawValue}
	return mdl.KeyDataResponseDto{
		Uuid: k.uuid,
		Name: k.name,
		KeyData: mdl.KeyData{
			Type:      k.keyType,
			Algorithm: mdl.KEYALGORITHM_RSA,
			Format:    mdl.KEYFORMAT_RAW,
			Value:     mdl.RawKeyValueAsKeyDataValue(raw),
		},
	}
}

// randomB64 returns n random bytes encoded as base64.
func randomB64(n int) string {
	b := make([]byte, n)
	_, _ = crand.Read(b)
	return base64.StdEncoding.EncodeToString(b)
}
