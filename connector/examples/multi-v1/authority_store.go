package main

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v2"
)

// AuthorityStore is a minimal in-memory Authority Provider used to verify
// multi-provider wiring. Authority instances are keyed by UUID; certificate
// management methods return constant placeholder responses since the test
// scope is route coexistence, not PKI behavior.
type AuthorityStore struct {
	mu        sync.RWMutex
	instances map[string]*authorityEntry
}

type authorityEntry struct {
	uuid       string
	name       string
	kind       string
	attributes []mdl.RequestAttribute
}

func NewAuthorityStore() *AuthorityStore {
	return &AuthorityStore{instances: make(map[string]*authorityEntry)}
}

func (s *AuthorityStore) ListAuthorityInstances(ctx context.Context) ([]mdl.AuthorityProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]mdl.AuthorityProviderInstanceDto, 0, len(s.instances))
	for _, e := range s.instances {
		out = append(out, authorityToDTO(e))
	}
	return out, nil
}

func (s *AuthorityStore) CreateAuthorityInstance(ctx context.Context, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error) {
	if req == nil || req.Name == "" {
		return nil, authority.ErrInvalidRequest.WithProperty("reason", "name is required")
	}
	id := uuid.NewString()
	e := &authorityEntry{
		uuid:       id,
		name:       req.Name,
		kind:       req.Kind,
		attributes: req.Attributes,
	}
	s.mu.Lock()
	s.instances[id] = e
	s.mu.Unlock()
	out := authorityToDTO(e)
	return &out, nil
}

func (s *AuthorityStore) GetAuthorityInstance(ctx context.Context, id string) (*mdl.AuthorityProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.instances[id]
	if !ok {
		return nil, authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	out := authorityToDTO(e)
	return &out, nil
}

func (s *AuthorityStore) UpdateAuthorityInstance(ctx context.Context, id string, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.instances[id]
	if !ok {
		return nil, authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	e.name = req.Name
	e.kind = req.Kind
	e.attributes = req.Attributes
	out := authorityToDTO(e)
	return &out, nil
}

func (s *AuthorityStore) RemoveAuthorityInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.instances[id]; !ok {
		return authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	delete(s.instances, id)
	return nil
}

func (s *AuthorityStore) GetConnection(ctx context.Context, id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.instances[id]; !ok {
		return authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	return nil
}

func (s *AuthorityStore) GetCaCertificates(ctx context.Context, id string, req *mdl.CaCertificatesRequestDto) (*mdl.CaCertificatesResponseDto, error) {
	return &mdl.CaCertificatesResponseDto{
		Certificates: []mdl.CertificateDataResponseDto{},
	}, nil
}

func (s *AuthorityStore) GetCrl(ctx context.Context, id string, req *mdl.CertificateRevocationListRequestDto) (*mdl.CertificateRevocationListResponseDto, error) {
	return &mdl.CertificateRevocationListResponseDto{
		CrlData: base64.StdEncoding.EncodeToString([]byte("placeholder-crl")),
	}, nil
}

func (s *AuthorityStore) IssueCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateSignRequestDto) (*mdl.CertificateDataResponseDto, error) {
	if req == nil || req.Request == "" {
		return nil, authority.ErrInvalidRequest.WithProperty("reason", "request is required")
	}
	certUUID := uuid.NewString()
	return &mdl.CertificateDataResponseDto{
		CertificateData: base64.StdEncoding.EncodeToString([]byte("issued-placeholder-cert")),
		Uuid:            &certUUID,
		Meta:            []mdl.MetadataAttribute{},
	}, nil
}

func (s *AuthorityStore) RenewCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateRenewRequestDto) (*mdl.CertificateDataResponseDto, error) {
	certUUID := uuid.NewString()
	return &mdl.CertificateDataResponseDto{
		CertificateData: base64.StdEncoding.EncodeToString([]byte("renewed-placeholder-cert")),
		Uuid:            &certUUID,
		Meta:            []mdl.MetadataAttribute{},
	}, nil
}

func (s *AuthorityStore) RevokeCertificate(ctx context.Context, authorityUuid string, req *mdl.CertRevocationDto) error {
	return nil
}

func (s *AuthorityStore) IdentifyCertificate(ctx context.Context, authorityUuid string, req *mdl.CertificateIdentificationRequestDto) (*mdl.CertificateIdentificationResponseDto, error) {
	return &mdl.CertificateIdentificationResponseDto{
		Meta: []mdl.MetadataAttribute{},
	}, nil
}

// authorityToDTO must be called while holding s.mu (read or write).
func authorityToDTO(e *authorityEntry) mdl.AuthorityProviderInstanceDto {
	return mdl.AuthorityProviderInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}
}
