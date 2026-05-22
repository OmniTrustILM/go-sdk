package main

import (
	"context"
	"log/slog"
	"sync"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/notification/v1"
	notification "github.com/OmniTrustILM/go-sdk/connector/provider/notification/v1"
)

// Store is a minimal in-memory Notification Provider. Instances are kept in
// a map; SendNotification just logs the recipients and event. Scope is
// wiring verification, not real delivery.
type Store struct {
	mu        sync.RWMutex
	instances map[string]*instanceEntry
	logger    *slog.Logger
}

type instanceEntry struct {
	uuid       string
	name       string
	kind       string
	attributes []mdl.RequestAttribute
}

func NewStore(logger *slog.Logger) *Store {
	return &Store{
		instances: make(map[string]*instanceEntry),
		logger:    logger,
	}
}

func (s *Store) ListNotificationInstances(ctx context.Context) ([]mdl.NotificationProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	out := make([]mdl.NotificationProviderInstanceDto, 0, len(s.instances))
	for _, e := range s.instances {
		out = append(out, mdl.NotificationProviderInstanceDto{
			Uuid:       e.uuid,
			Name:       e.name,
			Attributes: []mdl.BaseAttributeDto{},
		})
	}
	return out, nil
}

func (s *Store) CreateNotificationInstance(ctx context.Context, req *mdl.NotificationProviderInstanceRequestDto) (*mdl.NotificationProviderInstanceDto, error) {
	if req == nil || req.Name == "" || req.Kind == "" {
		return nil, notification.ErrInvalidRequest.WithProperty("reason", "name and kind are required")
	}
	id := uuid.NewString()
	s.mu.Lock()
	s.instances[id] = &instanceEntry{
		uuid:       id,
		name:       req.Name,
		kind:       req.Kind,
		attributes: req.Attributes,
	}
	s.mu.Unlock()
	return &mdl.NotificationProviderInstanceDto{
		Uuid:       id,
		Name:       req.Name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) GetNotificationInstance(ctx context.Context, id string) (*mdl.NotificationProviderInstanceDto, error) {
	s.mu.RLock()
	defer s.mu.RUnlock()
	e, ok := s.instances[id]
	if !ok {
		return nil, notification.ErrInstanceNotFound.WithProperty("uuid", id)
	}
	return &mdl.NotificationProviderInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) UpdateNotificationInstance(ctx context.Context, id string, req *mdl.NotificationProviderInstanceRequestDto) (*mdl.NotificationProviderInstanceDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	e, ok := s.instances[id]
	if !ok {
		return nil, notification.ErrInstanceNotFound.WithProperty("uuid", id)
	}
	e.name = req.Name
	e.kind = req.Kind
	e.attributes = req.Attributes
	return &mdl.NotificationProviderInstanceDto{
		Uuid:       e.uuid,
		Name:       e.name,
		Attributes: []mdl.BaseAttributeDto{},
	}, nil
}

func (s *Store) RemoveNotificationInstance(ctx context.Context, id string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, ok := s.instances[id]; !ok {
		return notification.ErrInstanceNotFound.WithProperty("uuid", id)
	}
	delete(s.instances, id)
	return nil
}

func (s *Store) SendNotification(ctx context.Context, id string, req *mdl.NotificationProviderNotifyRequestDto) error {
	s.mu.RLock()
	_, ok := s.instances[id]
	s.mu.RUnlock()
	if !ok {
		return notification.ErrInstanceNotFound.WithProperty("uuid", id)
	}
	if req == nil {
		return notification.ErrInvalidRequest.WithProperty("reason", "request body is required")
	}
	recipients := make([]string, 0, len(req.Recipients))
	for _, r := range req.Recipients {
		recipients = append(recipients, r.Name)
	}
	s.logger.Info("notification delivered",
		"instance", id,
		"event_type", req.EventType,
		"recipients", recipients,
	)
	return nil
}
