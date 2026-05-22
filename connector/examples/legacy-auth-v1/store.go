package main

import (
	"context"
	"encoding/base64"
	"fmt"
	"sync"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v1"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v1"
)

// Store is a minimal in-memory Authority Provider Legacy implementation.
// Authority instances are keyed by UUID; end entities keyed by
// (authorityUuid, profileName, name). Certificate management and CRL methods
// return placeholder content. Scope is wiring verification, not PKI behavior.
type Store struct {
	mu          sync.RWMutex
	authorities map[string]*authorityEntry
	endEntities map[string]*mdl.EndEntityDto // key = uuid|profile|name
}

type authorityEntry struct {
	uuid string
	name string
	kind string
}

func NewStore() *Store {
	return &Store{
		authorities: make(map[string]*authorityEntry),
		endEntities: make(map[string]*mdl.EndEntityDto),
	}
}

func endEntityKey(authorityUuid, profile, name string) string {
	return authorityUuid + "|" + profile + "|" + name
}

// --- Authority Management ------------------------------------------------

func (s *Store) ListAuthorityInstances(ctx context.Context) ([]mdl.AuthorityProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]mdl.AuthorityProviderInstanceDto, 0, len(s.authorities))
	for _, e := range s.authorities {
		out = append(out, mdl.AuthorityProviderInstanceDto{
			Uuid:       e.uuid,
			Name:       e.name,
			Attributes: []mdl.BaseAttributeDto{},
		})
	}
	return out, nil
}

func (s *Store) CreateAuthorityInstance(ctx context.Context, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error) {
	if req == nil || req.Name == "" {
		return nil, authority.ErrInvalidRequest.WithProperty("reason", "name is required")
	}
	id := uuid.NewString()
	s.mu.Lock()
	s.authorities[id] = &authorityEntry{uuid: id, name: req.Name, kind: req.Kind}
	s.mu.Unlock()
	return &mdl.AuthorityProviderInstanceDto{
		Uuid:       id,
		Name:       req.Name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) GetAuthorityInstance(ctx context.Context, id string) (*mdl.AuthorityProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.authorities[id]
	if !ok {
		return nil, authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	return &mdl.AuthorityProviderInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) UpdateAuthorityInstance(ctx context.Context, id string, req *mdl.AuthorityProviderInstanceRequestDto) (*mdl.AuthorityProviderInstanceDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.authorities[id]
	if !ok {
		return nil, authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	e.name = req.Name
	e.kind = req.Kind
	return &mdl.AuthorityProviderInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) RemoveAuthorityInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.authorities[id]; !ok {
		return authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	delete(s.authorities, id)
	return nil
}

func (s *Store) GetConnection(ctx context.Context, id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.authorities[id]; !ok {
		return authority.ErrAuthorityNotFound.WithProperty("uuid", id)
	}
	return nil
}

func (s *Store) GetCaCertificates(ctx context.Context, id string, req *mdl.CaCertificatesRequestDto) (*mdl.CaCertificatesResponseDto, error) {
	return &mdl.CaCertificatesResponseDto{
		Certificates: []mdl.CertificateDataResponseDto{},
	}, nil
}

func (s *Store) GetCrl(ctx context.Context, id string, req *mdl.CertificateRevocationListRequestDto) (*mdl.CertificateRevocationListResponseDto, error) {
	return &mdl.CertificateRevocationListResponseDto{
		CrlData: base64.StdEncoding.EncodeToString([]byte("placeholder-crl")),
	}, nil
}

// --- End Entity Management -----------------------------------------------

func (s *Store) ListEndEntities(ctx context.Context, authorityUuid, profile string) ([]mdl.EndEntityDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	prefix := authorityUuid + "|" + profile + "|"
	out := []mdl.EndEntityDto{}
	for k, v := range s.endEntities {
		if len(k) > len(prefix) && k[:len(prefix)] == prefix {
			out = append(out, *v)
		}
	}
	return out, nil
}

func (s *Store) CreateEndEntity(ctx context.Context, authorityUuid, profile string, req *mdl.AddEndEntityRequestDto) error {
	if req == nil || req.Username == "" {
		return authority.ErrInvalidRequest.WithProperty("reason", "username is required")
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	key := endEntityKey(authorityUuid, profile, req.Username)
	if _, exists := s.endEntities[key]; exists {
		return authority.ErrInvalidRequest.WithProperty("reason", fmt.Sprintf("end entity %q already exists", req.Username))
	}
	s.endEntities[key] = &mdl.EndEntityDto{
		Username:       req.Username,
		Email:          req.Email,
		SubjectDN:      req.SubjectDN,
		SubjectAltName: req.SubjectAltName,
		ExtensionData:  req.ExtensionData,
		Status:         "GENERATED",
	}
	return nil
}

func (s *Store) GetEndEntity(ctx context.Context, authorityUuid, profile, name string) (*mdl.EndEntityDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.endEntities[endEntityKey(authorityUuid, profile, name)]
	if !ok {
		return nil, authority.ErrEndEntityNotFound.
			WithProperty("authorityUuid", authorityUuid).
			WithProperty("profile", profile).
			WithProperty("endEntityName", name)
	}
	return e, nil
}

func (s *Store) UpdateEndEntity(ctx context.Context, authorityUuid, profile, name string, req *mdl.EditEndEntityRequestDto) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.endEntities[endEntityKey(authorityUuid, profile, name)]
	if !ok {
		return authority.ErrEndEntityNotFound
	}
	e.Email = req.Email
	e.SubjectDN = req.SubjectDN
	e.SubjectAltName = req.SubjectAltName
	e.ExtensionData = req.ExtensionData
	return nil
}

func (s *Store) RemoveEndEntity(ctx context.Context, authorityUuid, profile, name string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	key := endEntityKey(authorityUuid, profile, name)
	if _, ok := s.endEntities[key]; !ok {
		return authority.ErrEndEntityNotFound
	}
	delete(s.endEntities, key)
	return nil
}

func (s *Store) ResetPassword(ctx context.Context, authorityUuid, profile, name string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.endEntities[endEntityKey(authorityUuid, profile, name)]; !ok {
		return authority.ErrEndEntityNotFound
	}
	return nil
}

// --- Certificate Management ----------------------------------------------

func (s *Store) IssueCertificate(ctx context.Context, authorityUuid, profile string, req *mdl.CertificateSignRequestDto) (*mdl.CertificateSignResponseDto, error) {
	if req == nil || req.Pkcs10 == "" {
		return nil, authority.ErrInvalidRequest.WithProperty("reason", "pkcs10 is required")
	}
	return &mdl.CertificateSignResponseDto{
		CertificateData: base64.StdEncoding.EncodeToString([]byte("placeholder-issued-cert")),
	}, nil
}

func (s *Store) RevokeCertificate(ctx context.Context, authorityUuid, profile string, req *mdl.CertRevocationDto) error {
	return nil
}

// --- Profile lookups -----------------------------------------------------

func (s *Store) ListEntityProfiles(ctx context.Context, authorityUuid string) ([]mdl.NameAndIdDto, error) {
	return []mdl.NameAndIdDto{
		{Id: 1, Name: "default-profile"},
	}, nil
}

func (s *Store) ListCertificateProfiles(ctx context.Context, authorityUuid string, profileID int32) ([]mdl.NameAndIdDto, error) {
	return []mdl.NameAndIdDto{
		{Id: 1, Name: "default-cert-profile"},
	}, nil
}

func (s *Store) ListCAsInProfile(ctx context.Context, authorityUuid string, profileID int32) ([]mdl.NameAndIdDto, error) {
	return []mdl.NameAndIdDto{
		{Id: 1, Name: "default-ca"},
	}, nil
}
