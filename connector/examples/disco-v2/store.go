package main

import (
	"context"
	"encoding/json"
	"strconv"
	"sync"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	discovery "github.com/OmniTrustILM/go-sdk/connector/provider/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/google/uuid"
)

const checkpointName = "example.discoveryCheckpoint"
const checkpointUUID = "d0235059-d463-4937-a2aa-20efdd000001"
const maxRuns = 64

// Store is a bounded, in-memory reference implementation. Only three fixed
// certificate fixtures are discoverable; status polls produce one item each.
// Buffers and run state are lost on restart; this is not a production store.
type Store struct {
	mu           sync.Mutex
	runs         map[string]*run
	certificates []string
}
type run struct {
	handle   string
	state    mdl.DiscoveryRunState
	produced int64
	ack      int64
	ended    time.Time
}
type checkpoint struct {
	Handle   string `json:"handle"`
	Sequence int64  `json:"sequence"`
}

func NewStore() (*Store, error) {
	certs, e := certificateFixtures()
	if e != nil {
		return nil, e
	}
	return &Store{runs: map[string]*run{}, certificates: certs}, nil
}

var (
	_ discovery.Provider                     = (*Store)(nil)
	_ discovery.AttributeDefinitionsProvider = (*Store)(nil)
)

func validate(id string, resources []mdl.Resource, attrs []mdl.RequestAttribute, resourceAttrs map[string][]mdl.RequestAttribute) error {
	if _, e := uuid.Parse(id); e != nil {
		return discovery.ErrInvalidRequest
	}
	if len(resources) != 1 || resources[0] != mdl.RESOURCE_CERTIFICATES || len(attrs) > 0 {
		return discovery.ErrInvalidRequest
	}
	for resource, values := range resourceAttrs {
		if resource != "certificates" || len(values) > 0 {
			return discovery.ErrInvalidRequest
		}
	}
	return nil
}
func checkpointFor(r *run) []mdl.MetadataAttribute {
	data, _ := json.Marshal(checkpoint{r.handle, r.produced})
	v := mdl.NewMetadataAttributeV3(checkpointUUID, checkpointName, 3, mdl.ATTRIBUTETYPE_META, mdl.ATTRIBUTECONTENTTYPE_STRING, *mdl.NewMetadataAttributeProperties("Discovery checkpoint", false), mdl.ATTRIBUTEVERSION_V3)
	v.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(mdl.NewStringAttributeContentV3(string(data), mdl.ATTRIBUTECONTENTTYPE_STRING))}
	return []mdl.MetadataAttribute{mdl.MetadataAttributeV3AsMetadataAttribute(v)}
}

// get must be called under mu. A replayed handle never grants access to another run.
func (s *Store) get(req *mdl.DiscoveryRunRequestDto) (*run, checkpoint, error) {
	var cp checkpoint
	if req == nil {
		return nil, cp, discovery.ErrInvalidRequest
	}
	if e := validate(req.RunId, req.Resources, req.Attributes, req.ResourceAttributes); e != nil {
		return nil, cp, e
	}
	if len(req.Checkpoint) != 1 {
		return nil, cp, discovery.ErrCheckpointLost
	}
	v := req.Checkpoint[0].MetadataAttributeV3
	if v == nil || v.Uuid != checkpointUUID || v.Name != checkpointName || len(v.Content) != 1 || v.Content[0].StringAttributeContentV3 == nil {
		return nil, cp, discovery.ErrCheckpointLost
	}
	if e := json.Unmarshal([]byte(v.Content[0].StringAttributeContentV3.Data), &cp); e != nil || cp.Sequence < 0 {
		return nil, cp, discovery.ErrCheckpointLost
	}
	r, ok := s.runs[req.RunId]
	if !ok {
		return nil, cp, discovery.ErrDiscoveryNotFound
	}
	if cp.Handle != r.handle || cp.Sequence > r.produced {
		return nil, cp, discovery.ErrCheckpointLost
	}
	return r, cp, nil
}
func (s *Store) Initiate(_ context.Context, req *mdl.DiscoveryInitiateRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	if e := validate(req.RunId, req.Resources, req.Attributes, req.ResourceAttributes); e != nil {
		return nil, e
	}
	if len(req.Checkpoint) > 0 {
		return nil, discovery.ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, ok := s.runs[req.RunId]
	if !ok {
		for id, old := range s.runs {
			if !old.ended.IsZero() && time.Since(old.ended) >= 24*time.Hour {
				delete(s.runs, id)
			}
		}
		if len(s.runs) >= maxRuns {
			return nil, shared.Unavailable("SERVICE_UNAVAILABLE", "example discovery capacity exhausted")
		}
		r = &run{handle: uuid.NewString(), state: mdl.DISCOVERYRUNSTATE_RUNNING}
		s.runs[req.RunId] = r
	}
	return &mdl.DiscoveryInitiateResponseDto{Checkpoint: checkpointFor(r), Stoppable: new(true)}, nil
}
func (s *Store) Status(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStatusResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _, e := s.get(req)
	if e != nil {
		return nil, e
	}
	if r.state == mdl.DISCOVERYRUNSTATE_RUNNING {
		r.produced++
		if r.produced == int64(len(s.certificates)) {
			r.state = mdl.DISCOVERYRUNSTATE_COMPLETED
			r.ended = time.Now()
		}
	}
	phase := string(r.state)
	return &mdl.DiscoveryStatusResponseDto{State: r.state, HighestSequence: r.produced, Progress: &mdl.DiscoveryProgressDto{Phase: &phase, ByResource: map[string]mdl.DiscoveryResourceProgressDto{"certificates": {Produced: new(r.produced)}}}}, nil
}
func (s *Store) Stop(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStopResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _, e := s.get(req)
	if e != nil {
		return nil, e
	}
	if r.state != mdl.DISCOVERYRUNSTATE_RUNNING && r.state != mdl.DISCOVERYRUNSTATE_STOPPED {
		return nil, discovery.ErrPastPointOfNoReturn
	}
	r.state = mdl.DISCOVERYRUNSTATE_STOPPED
	return &mdl.DiscoveryStopResponseDto{Checkpoint: checkpointFor(r)}, nil
}
func (s *Store) Resume(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, cp, e := s.get(req)
	if e != nil {
		return nil, e
	}
	if cp.Sequence != r.produced {
		return nil, discovery.ErrCheckpointLost
	}
	if r.state != mdl.DISCOVERYRUNSTATE_STOPPED && r.state != mdl.DISCOVERYRUNSTATE_RUNNING {
		return nil, discovery.ErrPastPointOfNoReturn
	}
	r.state = mdl.DISCOVERYRUNSTATE_RUNNING
	return &mdl.DiscoveryInitiateResponseDto{Checkpoint: checkpointFor(r), Stoppable: new(true)}, nil
}
func (s *Store) Cancel(_ context.Context, req *mdl.DiscoveryRunRequestDto) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	_, _, e := s.get(req)
	if e != nil {
		return e
	}
	delete(s.runs, req.RunId)
	return nil
}
func (s *Store) Results(_ context.Context, req *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	after, limit, budget := req.GetAfterSequence(), int32(100), int64(1<<20)
	if req.MaxItems != nil {
		limit = *req.MaxItems
	}
	if req.MaxBytes != nil {
		budget = *req.MaxBytes
	}
	if after < 0 || limit < 1 || budget < 1 || budget > discovery.MaxResultBytes {
		return nil, discovery.ErrInvalidRequest
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, _, e := s.get(&mdl.DiscoveryRunRequestDto{RunId: req.RunId, Resources: req.Resources, Checkpoint: req.Checkpoint, Attributes: req.Attributes, ResourceAttributes: req.ResourceAttributes})
	if e != nil {
		return nil, e
	}
	if after < r.ack {
		return nil, discovery.ErrDiscoveryNotFound
	}
	if after > r.produced {
		return nil, discovery.ErrInvalidRequest
	}
	out := &mdl.DiscoveryResultsResponseDto{Items: []mdl.DiscoveredItemDto{}, HighestSequence: r.produced}
	envelope, _ := json.Marshal(out)
	if ceiling := discovery.MaxResultBytes - int64(len(envelope)-2) - 1; budget > ceiling {
		budget = ceiling
	}
	size := int64(2)
	for seq := after + 1; seq <= r.produced && len(out.Items) < int(limit); seq++ {
		item := mdl.DiscoveredItemDto{Sequence: seq, UniqueRef: "example-certificate-" + strconv.FormatInt(seq, 10), Payload: mdl.DiscoveredCertificateDtoAsDiscoveredItemPayload(mdl.NewDiscoveredCertificateDto(mdl.RESOURCE_CERTIFICATES, s.certificates[seq-1]))}
		b, _ := json.Marshal(item)
		extra := int64(len(b))
		if len(out.Items) > 0 {
			extra++
		}
		if size+extra > budget {
			if len(out.Items) == 0 {
				return nil, discovery.ErrInvalidRequest.WithProperty("reason", "maxBytes cannot fit the next item")
			}
			break
		}
		size += extra
		out.Items = append(out.Items, item)
	}
	r.ack = after
	out.More = after+int64(len(out.Items)) < r.produced
	return out, nil
}
func (s *Store) SupportedResources(context.Context) ([]mdl.DiscoverySupportedResourceDto, error) {
	return []mdl.DiscoverySupportedResourceDto{{Resource: mdl.RESOURCE_CERTIFICATES}}, nil
}
func (s *Store) RunAttributes(context.Context) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}
func (s *Store) ResourceAttributes(_ context.Context, r mdl.Resource) ([]mdl.BaseAttributeDto, error) {
	if r != mdl.RESOURCE_CERTIFICATES {
		return nil, discovery.ErrInvalidRequest
	}
	return []mdl.BaseAttributeDto{}, nil
}
func (s *Store) ListDefinitions(context.Context) (*mdl.AttributeDefinitionsDto, error) {
	return &mdl.AttributeDefinitionsDto{ConnectorVersion: connectorVersion, Definitions: []mdl.BaseAttributeDto{}}, nil
}
func (s *Store) GetDefinition(context.Context, string) (*mdl.BaseAttributeDto, error) {
	return nil, discovery.ErrDefinitionNotFound
}
func (s *Store) Callback(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
	return nil, discovery.ErrDefinitionNotFound
}
