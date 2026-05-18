package main

import (
	"context"
	"sync"
	"time"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v1"
)

// DiscoveryStore is a stripped-down in-memory Discovery Provider. Only goal
// here is to prove the discoveryProvider function group coexists with
// authorityProvider on a single Connector — the simulated work and rich
// state machine from the disco-v1 example are not needed.
type DiscoveryStore struct {
	mu      sync.RWMutex
	entries map[string]*discoveryEntry
}

type discoveryEntry struct {
	uuid    string
	name    string
	kind    string
	status  mdl.DiscoveryStatus
	created time.Time
}

func NewDiscoveryStore() *DiscoveryStore {
	return &DiscoveryStore{entries: make(map[string]*discoveryEntry)}
}

func (s *DiscoveryStore) DiscoverCertificate(ctx context.Context, req *mdl.DiscoveryRequestDto) (*mdl.DiscoveryProviderDto, error) {
	if req == nil || req.Name == "" || req.Kind == "" {
		return nil, discovery.ErrInvalidRequest.WithProperty("reason", "name and kind are required")
	}
	id := uuid.NewString()
	e := &discoveryEntry{
		uuid:    id,
		name:    req.Name,
		kind:    req.Kind,
		status:  mdl.DISCOVERYSTATUS_COMPLETED,
		created: time.Now().UTC(),
	}
	s.mu.Lock()
	s.entries[id] = e
	s.mu.Unlock()
	return discoveryToDTO(e), nil
}

func (s *DiscoveryStore) GetDiscovery(ctx context.Context, id string, req *mdl.DiscoveryDataRequestDto) (*mdl.DiscoveryProviderDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.entries[id]
	if !ok {
		return nil, discovery.ErrDiscoveryNotFound.WithProperty("uuid", id)
	}
	return discoveryToDTO(e), nil
}

func (s *DiscoveryStore) DeleteDiscovery(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[id]; !ok {
		return discovery.ErrDiscoveryNotFound.WithProperty("uuid", id)
	}
	delete(s.entries, id)
	return nil
}

// discoveryToDTO must be called while holding s.mu (read or write).
func discoveryToDTO(e *discoveryEntry) *mdl.DiscoveryProviderDto {
	total := int32(0)
	return &mdl.DiscoveryProviderDto{
		Uuid:                        e.uuid,
		Name:                        e.name,
		Status:                      e.status,
		TotalCertificatesDiscovered: &total,
		CertificateData:             []mdl.DiscoveryProviderCertificateDataDto{},
		Meta:                        []mdl.MetadataAttribute{},
	}
}
