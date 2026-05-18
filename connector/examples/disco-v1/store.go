package main

import (
	"context"
	"math/rand/v2"
	"sync"
	"time"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v1"
	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v1"
)

// Store is an in-memory Discovery Provider implementation. Discoveries are
// keyed by a server-generated UUID; the actual "discovery" work is simulated
// by a uniform random sleep between 1 and 10 seconds before the response
// returns with status completed. No certificates are produced — the array
// stays empty so the wire shape remains valid.
type Store struct {
	mu      sync.RWMutex
	entries map[string]*entry
}

type entry struct {
	uuid       string
	name       string
	kind       string
	status     mdl.DiscoveryStatus
	certs      []mdl.DiscoveryProviderCertificateDataDto
	meta       []mdl.MetadataAttribute
	attributes []mdl.RequestAttribute
	created    time.Time
}

func NewStore() *Store {
	return &Store{entries: make(map[string]*entry)}
}

// DiscoverCertificate stores a new discovery and simulates work by sleeping
// 1–10 seconds before returning. The sleep is honored against ctx
// cancellation so client disconnects abort the synthetic scan promptly.
func (s *Store) DiscoverCertificate(ctx context.Context, req *mdl.DiscoveryRequestDto) (*mdl.DiscoveryProviderDto, error) {
	if req == nil || req.Name == "" {
		return nil, discovery.ErrInvalidRequest.WithProperty("reason", "name is required")
	}
	if req.Kind == "" {
		return nil, discovery.ErrInvalidRequest.WithProperty("reason", "kind is required")
	}

	id := uuid.NewString()

	e := &entry{
		uuid:       id,
		name:       req.Name,
		kind:       req.Kind,
		status:     mdl.DISCOVERYSTATUS_IN_PROGRESS,
		certs:      []mdl.DiscoveryProviderCertificateDataDto{},
		meta:       []mdl.MetadataAttribute{},
		attributes: req.Attributes,
		created:    time.Now().UTC(),
	}

	s.mu.Lock()
	s.entries[id] = e
	s.mu.Unlock()

	// Simulate discovery work. 1–10 second random duration.
	dur := time.Duration(1+rand.IntN(10)) * time.Second
	select {
	case <-time.After(dur):
	case <-ctx.Done():
		return nil, ctx.Err()
	}

	s.mu.Lock()
	e.status = mdl.DISCOVERYSTATUS_COMPLETED
	s.mu.Unlock()

	return toDTO(e), nil
}

// GetDiscovery returns the discovery identified by uuid. The pagination
// fields on req are honored against the empty certificate list.
func (s *Store) GetDiscovery(ctx context.Context, uuid string, req *mdl.DiscoveryDataRequestDto) (*mdl.DiscoveryProviderDto, error) {
	s.mu.RLock()
	e, ok := s.entries[uuid]
	s.mu.RUnlock()
	if !ok {
		return nil, discovery.ErrDiscoveryNotFound.WithProperty("uuid", uuid)
	}
	return toDTO(e), nil
}

// DeleteDiscovery removes the discovery. Returns ErrDiscoveryNotFound when
// the uuid is unknown so callers can distinguish missing vs deleted state.
func (s *Store) DeleteDiscovery(ctx context.Context, uuid string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.entries[uuid]; !ok {
		return discovery.ErrDiscoveryNotFound.WithProperty("uuid", uuid)
	}
	delete(s.entries, uuid)
	return nil
}

// toDTO converts a stored entry into the wire DTO. Holds no lock; callers
// must ensure consistent reads.
func toDTO(e *entry) *mdl.DiscoveryProviderDto {
	total := int32(len(e.certs))
	return &mdl.DiscoveryProviderDto{
		Uuid:                        e.uuid,
		Name:                        e.name,
		Status:                      e.status,
		TotalCertificatesDiscovered: &total,
		CertificateData:             e.certs,
		Meta:                        e.meta,
	}
}

