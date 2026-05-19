package main

import (
	"context"
	"encoding/base64"
	"sync"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/entity/v1"
	entity "github.com/OmniTrustILM/go-sdk/connector/provider/entity/v1"
)

// Store is a minimal in-memory Entity Provider. Entity instances are kept in
// memory only; location operations return placeholder content. Scope is
// wiring verification, not real entity-management behavior.
type Store struct {
	mu       sync.RWMutex
	entities map[string]*entityEntry
}

type entityEntry struct {
	uuid       string
	name       string
	kind       string
	attributes []mdl.RequestAttribute
}

func NewStore() *Store {
	return &Store{entities: make(map[string]*entityEntry)}
}

// --- Entity instance management -----------------------------------------

func (s *Store) ListEntityInstances(ctx context.Context) ([]mdl.EntityInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]mdl.EntityInstanceDto, 0, len(s.entities))
	for _, e := range s.entities {
		out = append(out, mdl.EntityInstanceDto{
			Uuid:       e.uuid,
			Name:       e.name,
			Attributes: []mdl.BaseAttributeDto{},
		})
	}
	return out, nil
}

func (s *Store) CreateEntityInstance(ctx context.Context, req *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	if req == nil || req.Name == "" || req.Kind == "" {
		return nil, entity.ErrInvalidRequest.WithProperty("reason", "name and kind are required")
	}
	id := uuid.NewString()
	s.mu.Lock()
	s.entities[id] = &entityEntry{
		uuid:       id,
		name:       req.Name,
		kind:       req.Kind,
		attributes: req.Attributes,
	}
	s.mu.Unlock()
	return &mdl.EntityInstanceDto{
		Uuid:       id,
		Name:       req.Name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) GetEntityInstance(ctx context.Context, id string) (*mdl.EntityInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entities[id]
	if !ok {
		return nil, entity.ErrEntityNotFound.WithProperty("entityUuid", id)
	}
	return &mdl.EntityInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) UpdateEntityInstance(ctx context.Context, id string, req *mdl.EntityInstanceRequestDto) (*mdl.EntityInstanceDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.entities[id]
	if !ok {
		return nil, entity.ErrEntityNotFound.WithProperty("entityUuid", id)
	}
	e.name = req.Name
	e.kind = req.Kind
	e.attributes = req.Attributes
	return &mdl.EntityInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) RemoveEntityInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entities[id]; !ok {
		return entity.ErrEntityNotFound.WithProperty("entityUuid", id)
	}
	delete(s.entities, id)
	return nil
}

// --- Location operations ------------------------------------------------

func (s *Store) GetLocationDetail(ctx context.Context, entityUuid string, req *mdl.LocationDetailRequestDto) (*mdl.LocationDetailResponseDto, error) {
	if err := s.requireEntity(entityUuid); err != nil {
		return nil, err
	}
	return &mdl.LocationDetailResponseDto{
		Certificates:         []mdl.CertificateLocationDto{},
		MultipleEntries:      true,
		SupportKeyManagement: false,
	}, nil
}

func (s *Store) PushCertificateToLocation(ctx context.Context, entityUuid string, req *mdl.PushCertificateRequestDto) (*mdl.PushCertificateResponseDto, error) {
	if err := s.requireEntity(entityUuid); err != nil {
		return nil, err
	}
	if req == nil || req.Certificate == "" {
		return nil, entity.ErrInvalidRequest.WithProperty("reason", "certificate is required")
	}
	withKey := false
	return &mdl.PushCertificateResponseDto{
		CertificateMetadata: []mdl.MetadataAttribute{},
		WithKey:             &withKey,
	}, nil
}

func (s *Store) RemoveCertificateFromLocation(ctx context.Context, entityUuid string, req *mdl.RemoveCertificateRequestDto) (*mdl.RemoveCertificateResponseDto, error) {
	if err := s.requireEntity(entityUuid); err != nil {
		return nil, err
	}
	return &mdl.RemoveCertificateResponseDto{
		CertificateMetadata: []mdl.MetadataAttributeV2{},
	}, nil
}

func (s *Store) GenerateCsrLocation(ctx context.Context, entityUuid string, req *mdl.GenerateCsrRequestDto) (*mdl.GenerateCsrResponseDto, error) {
	if err := s.requireEntity(entityUuid); err != nil {
		return nil, err
	}
	return &mdl.GenerateCsrResponseDto{
		Csr:            base64.StdEncoding.EncodeToString([]byte("placeholder-csr")),
		Metadata:       []mdl.MetadataAttribute{},
		PushAttributes: []mdl.RequestAttribute{},
	}, nil
}

// --- helpers -----------------------------------------------------------

func (s *Store) requireEntity(id string) error {
	s.mu.RLock()
	defer s.mu.RUnlock()
	if _, ok := s.entities[id]; !ok {
		return entity.ErrEntityNotFound.WithProperty("entityUuid", id)
	}
	return nil
}
