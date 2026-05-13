package main

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"sync"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
)

// Store is an in-memory Secret Provider implementation. Keyed by secret name;
// duplicate names are rejected on CreateSecret. Not suitable for production —
// every restart wipes the store.
type Store struct {
	mu      sync.RWMutex
	secrets map[string]*entry
}

// entry is the canonical record kept per secret. Version is a monotonically
// increasing counter encoded as a decimal string; bumped on every successful
// rotation. Metadata mirrors the last UpdateSecret request.
type entry struct {
	name     string
	stype    mdl.SecretType
	content  mdl.SecretContent
	version  int
	metadata []mdl.MetadataAttribute
	created  time.Time
	updated  time.Time
}

func NewStore() *Store {
	return &Store{secrets: make(map[string]*entry)}
}

// CreateSecret stores a new secret. Returns ErrSecretConflict if a secret
// with the same name already exists. Type is inferred from the SecretContent
// oneOf variant that was populated.
func (s *Store) CreateSecret(ctx context.Context, req *mdl.CreateSecretRequestDto) (*mdl.SecretResponseDto, error) {
	if req == nil || req.Name == "" {
		return nil, shared.Invalid("VALIDATION_FAILED", "name is required")
	}
	stype, ok := typeFromContent(req.Secret)
	if !ok {
		return nil, shared.Invalid("VALIDATION_FAILED", "secret content variant is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[req.Name]; exists {
		return nil, secret.ErrSecretConflict.WithProperty("name", req.Name)
	}

	now := time.Now().UTC()
	e := &entry{
		name:    req.Name,
		stype:   stype,
		content: req.Secret,
		version: 1,
		created: now,
		updated: now,
	}
	s.secrets[req.Name] = e
	return toResponse(e), nil
}

// UpdateSecret replaces stored content and metadata. Returns ErrSecretNotFound
// if no secret with this name exists. Bumps version.
func (s *Store) UpdateSecret(ctx context.Context, req *mdl.UpdateSecretRequestDto) (*mdl.SecretResponseDto, error) {
	if req == nil || req.Name == "" {
		return nil, shared.Invalid("VALIDATION_FAILED", "name is required")
	}
	stype, ok := typeFromContent(req.Secret)
	if !ok {
		return nil, shared.Invalid("VALIDATION_FAILED", "secret content variant is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.secrets[req.Name]
	if !exists {
		return nil, secret.ErrSecretNotFound.WithProperty("name", req.Name)
	}
	if e.stype != stype {
		return nil, shared.Invalid("VALIDATION_FAILED", "secret type cannot change on update").
			WithProperty("name", req.Name).
			WithProperty("from", string(e.stype)).
			WithProperty("to", string(stype))
	}

	e.content = req.Secret
	e.metadata = req.Metadata
	e.version++
	e.updated = time.Now().UTC()
	return toResponse(e), nil
}

// DeleteSecret removes the secret. Strict semantics: returns ErrSecretNotFound
// when the secret does not exist (over idempotent silent-success).
func (s *Store) DeleteSecret(ctx context.Context, req *mdl.SecretRequestDto) error {
	if req == nil || req.Name == "" {
		return shared.Invalid("VALIDATION_FAILED", "name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	if _, exists := s.secrets[req.Name]; !exists {
		return secret.ErrSecretNotFound.WithProperty("name", req.Name)
	}
	delete(s.secrets, req.Name)
	return nil
}

// RotateSecret regenerates the secret content. For types whose content is a
// single opaque string (apiKey, generic, secretKey), regenerates a 32-byte
// hex value. For basicAuth, keeps the username and regenerates the password.
// Other types return OPERATION_NOT_SUPPORTED — extending coverage is left as
// an exercise; the example demonstrates the wiring.
func (s *Store) RotateSecret(ctx context.Context, req *mdl.SecretRequestDto) (*mdl.SecretResponseDto, error) {
	if req == nil || req.Name == "" {
		return nil, shared.Invalid("VALIDATION_FAILED", "name is required")
	}

	s.mu.Lock()
	defer s.mu.Unlock()

	e, exists := s.secrets[req.Name]
	if !exists {
		return nil, secret.ErrSecretNotFound.WithProperty("name", req.Name)
	}

	newContent, err := rotateContent(e.content)
	if err != nil {
		return nil, err
	}
	e.content = newContent
	e.version++
	e.updated = time.Now().UTC()
	return toResponse(e), nil
}

// GetSecretContent returns the stored content. Versioning is not retained in
// this example (only the current version is kept), so a non-empty version
// parameter that does not match the current version returns 404.
func (s *Store) GetSecretContent(ctx context.Context, req *mdl.SecretRequestDto, version string) (*mdl.SecretContentResponseDto, error) {
	if req == nil || req.Name == "" {
		return nil, shared.Invalid("VALIDATION_FAILED", "name is required")
	}

	s.mu.RLock()
	defer s.mu.RUnlock()

	e, exists := s.secrets[req.Name]
	if !exists {
		return nil, secret.ErrSecretNotFound.WithProperty("name", req.Name)
	}
	current := fmt.Sprintf("%d", e.version)
	if version != "" && version != current {
		return nil, secret.ErrSecretNotFound.
			WithProperty("name", req.Name).
			WithProperty("requested_version", version).
			WithProperty("current_version", current)
	}
	resp := &mdl.SecretContentResponseDto{
		Version: &current,
		Content: e.content,
	}
	return resp, nil
}

// CheckVaultConnection always succeeds — there is no backend to probe.
func (s *Store) CheckVaultConnection(ctx context.Context, attrs []mdl.RequestAttribute) error {
	return nil
}

// --- helpers ---------------------------------------------------------------

// typeFromContent extracts the discriminator from a SecretContent oneOf.
// Returns false when no variant is populated.
func typeFromContent(c mdl.SecretContent) (mdl.SecretType, bool) {
	switch {
	case c.ApiKeySecretContent != nil:
		return c.ApiKeySecretContent.Type, true
	case c.BasicAuthSecretContent != nil:
		return c.BasicAuthSecretContent.Type, true
	case c.GenericSecretContent != nil:
		return c.GenericSecretContent.Type, true
	case c.JwtTokenSecretContent != nil:
		return c.JwtTokenSecretContent.Type, true
	case c.KeyStoreSecretContent != nil:
		return c.KeyStoreSecretContent.Type, true
	case c.KeyValueSecretContent != nil:
		return c.KeyValueSecretContent.Type, true
	case c.PrivateKeySecretContent != nil:
		return c.PrivateKeySecretContent.Type, true
	case c.SecretKeySecretContent != nil:
		return c.SecretKeySecretContent.Type, true
	}
	return "", false
}

// rotateContent produces a new SecretContent of the same type with freshly
// generated material. Only the simple variants are implemented; others
// surface OPERATION_NOT_SUPPORTED so the limit is explicit to callers.
func rotateContent(old mdl.SecretContent) (mdl.SecretContent, error) {
	switch {
	case old.ApiKeySecretContent != nil:
		next := *old.ApiKeySecretContent
		next.Content = randomHex(32)
		return mdl.ApiKeySecretContentAsSecretContent(&next), nil
	case old.GenericSecretContent != nil:
		next := *old.GenericSecretContent
		next.Content = randomHex(32)
		return mdl.GenericSecretContentAsSecretContent(&next), nil
	case old.SecretKeySecretContent != nil:
		next := *old.SecretKeySecretContent
		next.Content = randomHex(32)
		return mdl.SecretKeySecretContentAsSecretContent(&next), nil
	case old.BasicAuthSecretContent != nil:
		next := *old.BasicAuthSecretContent
		next.Password = randomHex(16)
		return mdl.BasicAuthSecretContentAsSecretContent(&next), nil
	}
	return mdl.SecretContent{}, shared.Invalid("OPERATION_NOT_SUPPORTED",
		"rotation is not implemented for this secret type in the example connector")
}

// randomHex returns a hex-encoded random byte string of nBytes length.
// Panics only if the system entropy source fails, which would be a much
// bigger problem than this example caring about.
func randomHex(nBytes int) string {
	b := make([]byte, nBytes)
	if _, err := rand.Read(b); err != nil {
		panic(fmt.Sprintf("randomHex: %v", err))
	}
	return hex.EncodeToString(b)
}

func toResponse(e *entry) *mdl.SecretResponseDto {
	v := fmt.Sprintf("%d", e.version)
	return &mdl.SecretResponseDto{
		Name:     e.name,
		Type:     e.stype,
		Version:  &v,
		Metadata: e.metadata,
	}
}
