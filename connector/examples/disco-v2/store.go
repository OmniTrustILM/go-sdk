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

const (
	checkpointName = "example.discoveryCheckpoint"
	checkpointUUID = "d0235059-d463-4937-a2aa-20efdd000001"
	maxRuns        = 64
	// defaultMaxItems bounds a page when the drain sets no maxItems.
	defaultMaxItems int32 = 100
)

const (
	buffered     = mdl.DISCOVERYDELIVERYMODE_BUFFERED
	checkpointed = mdl.DISCOVERYDELIVERYMODE_CHECKPOINTED
)

// Store is a reference implementation of both delivery modes over three fixed
// certificate fixtures. Initiate takes the first mode Core offers; a Core
// older than delivery modes offers buffered only.
//
// A checkpointed run is served from its checkpoint alone: each results call
// discovers the next fixtures and returns the position after them, so the run
// survives a restart and any instance can serve its next call. A buffered run
// lives in memory: each status poll discovers one fixture into the run's
// buffer, and a restart loses it. A run keeps the mode it started in; the
// contract lets a connector switch on resume, but this example does not.
// Not a production store.
type Store struct {
	mu           sync.Mutex
	runs         map[string]*run // buffered runs only
	certificates []string
}

// run is a buffered run's in-memory state.
type run struct {
	handle   string
	state    mdl.DiscoveryRunState
	produced int64
	ack      int64
	ended    time.Time
}

// checkpoint is a run's position, carried as a schema v3 metadata attribute.
type checkpoint struct {
	Mode     mdl.DiscoveryDeliveryMode `json:"mode"`
	RunID    string                    `json:"runId"`
	Handle   string                    `json:"handle,omitempty"` // buffered: the in-memory run it belongs to
	Sequence int64                     `json:"sequence"`
}

// replay is the scope every lifecycle call carries.
type replay struct {
	runID              string
	resources          []mdl.Resource
	attributes         []mdl.RequestAttribute
	resourceAttributes map[string][]mdl.RequestAttribute
	checkpoint         []mdl.MetadataAttribute
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

func runReplay(r *mdl.DiscoveryRunRequestDto) replay {
	return replay{r.RunId, r.Resources, r.Attributes, r.ResourceAttributes, r.Checkpoint}
}

func drainReplay(r *mdl.DiscoveryDrainRequestDto) replay {
	return replay{r.RunId, r.Resources, r.Attributes, r.ResourceAttributes, r.Checkpoint}
}

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

func encode(cp checkpoint) []mdl.MetadataAttribute {
	data, _ := json.Marshal(cp)
	v := mdl.NewMetadataAttributeV3(checkpointUUID, checkpointName, 3, mdl.ATTRIBUTETYPE_META, mdl.ATTRIBUTECONTENTTYPE_STRING, *mdl.NewMetadataAttributeProperties("Discovery checkpoint", false), mdl.ATTRIBUTEVERSION_V3)
	v.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(mdl.NewStringAttributeContentV3(string(data), mdl.ATTRIBUTECONTENTTYPE_STRING))}
	return []mdl.MetadataAttribute{mdl.MetadataAttributeV3AsMetadataAttribute(v)}
}

func bufferedCheckpoint(id string, r *run) []mdl.MetadataAttribute {
	return encode(checkpoint{Mode: buffered, RunID: id, Handle: r.handle, Sequence: r.produced})
}

// replayed validates the call's scope and reads its checkpoint. A checkpoint
// this connector did not mint for the run is unreadable: unreadable answers
// it, since resume declares 410 where the other calls declare 422.
func (s *Store) replayed(req replay, unreadable error) (checkpoint, error) {
	var cp checkpoint
	if e := validate(req.runID, req.resources, req.attributes, req.resourceAttributes); e != nil {
		return cp, e
	}
	if len(req.checkpoint) != 1 {
		return cp, unreadable
	}
	v := req.checkpoint[0].MetadataAttributeV3
	if v == nil || v.Uuid != checkpointUUID || v.Name != checkpointName || len(v.Content) != 1 || v.Content[0].StringAttributeContentV3 == nil {
		return cp, unreadable
	}
	e := json.Unmarshal([]byte(v.Content[0].StringAttributeContentV3.Data), &cp)
	if e != nil || !cp.Mode.IsValid() || cp.RunID != req.runID || cp.Sequence < 0 || cp.Sequence > int64(len(s.certificates)) {
		return cp, unreadable
	}
	return cp, nil
}

// buffered returns a buffered run's state; it must be called under mu. A
// replayed handle never grants access to another run.
func (s *Store) buffered(id string, cp checkpoint, unreadable error) (*run, error) {
	r, ok := s.runs[id]
	if !ok {
		return nil, discovery.ErrDiscoveryNotFound
	}
	if cp.Handle != r.handle || cp.Sequence > r.produced {
		return nil, unreadable
	}
	return r, nil
}

func accepted(mode mdl.DiscoveryDeliveryMode, cp []mdl.MetadataAttribute) *mdl.DiscoveryInitiateResponseDto {
	return &mdl.DiscoveryInitiateResponseDto{Checkpoint: cp, DeliveryMode: &mode, Stoppable: new(true)}
}

func status(state mdl.DiscoveryRunState, highest int64) *mdl.DiscoveryStatusResponseDto {
	phase := string(state)
	return &mdl.DiscoveryStatusResponseDto{State: state, HighestSequence: highest, Progress: &mdl.DiscoveryProgressDto{Phase: &phase, ByResource: map[string]mdl.DiscoveryResourceProgressDto{"certificates": {Produced: new(highest)}}}}
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
	mode, e := discovery.ChooseDeliveryMode(req.DeliveryModes, checkpointed, buffered)
	if e != nil {
		return nil, e
	}
	if mode == checkpointed {
		// Nothing to hold: the run starts from an empty position, and a
		// repeated initiate answers the same one.
		return accepted(mode, encode(checkpoint{Mode: mode, RunID: req.RunId})), nil
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
	return accepted(mode, bufferedCheckpoint(req.RunId, r)), nil
}

func (s *Store) Status(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStatusResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	cp, e := s.replayed(runReplay(req), discovery.ErrInvalidRequest)
	if e != nil {
		return nil, e
	}
	if cp.Mode == checkpointed {
		state := mdl.DISCOVERYRUNSTATE_RUNNING
		if cp.Sequence == int64(len(s.certificates)) {
			state = mdl.DISCOVERYRUNSTATE_COMPLETED
		}
		return status(state, cp.Sequence), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.buffered(req.RunId, cp, discovery.ErrInvalidRequest)
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
	return status(r.state, r.produced), nil
}

func (s *Store) Stop(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStopResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	cp, e := s.replayed(runReplay(req), discovery.ErrInvalidRequest)
	if e != nil {
		return nil, e
	}
	if cp.Mode == checkpointed {
		if cp.Sequence == int64(len(s.certificates)) {
			return nil, discovery.ErrPastPointOfNoReturn
		}
		// Nothing runs between calls, and Core keeps the checkpoint it holds.
		return &mdl.DiscoveryStopResponseDto{}, nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.buffered(req.RunId, cp, discovery.ErrInvalidRequest)
	if e != nil {
		return nil, e
	}
	if r.state != mdl.DISCOVERYRUNSTATE_RUNNING && r.state != mdl.DISCOVERYRUNSTATE_STOPPED {
		return nil, discovery.ErrPastPointOfNoReturn
	}
	r.state = mdl.DISCOVERYRUNSTATE_STOPPED
	return &mdl.DiscoveryStopResponseDto{Checkpoint: bufferedCheckpoint(req.RunId, r)}, nil
}

func (s *Store) Resume(_ context.Context, req *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	cp, e := s.replayed(runReplay(req), discovery.ErrCheckpointLost)
	if e != nil {
		return nil, e
	}
	mode, e := discovery.ChooseDeliveryMode(req.DeliveryModes, cp.Mode)
	if e != nil {
		return nil, e
	}
	if mode == checkpointed {
		if cp.Sequence == int64(len(s.certificates)) {
			return nil, discovery.ErrInvalidRequest.WithProperty("reason", "the run has already completed")
		}
		return accepted(mode, nil), nil
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.buffered(req.RunId, cp, discovery.ErrCheckpointLost)
	if e != nil {
		return nil, e
	}
	if cp.Sequence != r.produced {
		return nil, discovery.ErrCheckpointLost
	}
	if r.state != mdl.DISCOVERYRUNSTATE_STOPPED && r.state != mdl.DISCOVERYRUNSTATE_RUNNING {
		return nil, discovery.ErrInvalidRequest.WithProperty("reason", "the run has already ended")
	}
	r.state = mdl.DISCOVERYRUNSTATE_RUNNING
	return accepted(mode, bufferedCheckpoint(req.RunId, r)), nil
}

func (s *Store) Cancel(_ context.Context, req *mdl.DiscoveryRunRequestDto) error {
	if req == nil {
		return discovery.ErrInvalidRequest
	}
	cp, e := s.replayed(runReplay(req), discovery.ErrInvalidRequest)
	if e != nil || cp.Mode == checkpointed {
		// A checkpointed run holds nothing here, so there is nothing to discard.
		return e
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	if _, e = s.buffered(req.RunId, cp, discovery.ErrInvalidRequest); e != nil {
		return e
	}
	delete(s.runs, req.RunId)
	return nil
}

func (s *Store) Results(_ context.Context, req *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error) {
	if req == nil {
		return nil, discovery.ErrInvalidRequest
	}
	cp, e := s.replayed(drainReplay(req), discovery.ErrInvalidRequest)
	if e != nil {
		return nil, e
	}
	if cp.Mode == checkpointed {
		return s.checkpointedPage(req, cp)
	}
	return s.bufferedPage(req, cp)
}

// checkpointedPage discovers the fixtures after the replayed position and
// returns them with the position after them.
func (s *Store) checkpointedPage(req *mdl.DiscoveryDrainRequestDto, cp checkpoint) (*mdl.DiscoveryResultsResponseDto, error) {
	if !discovery.Offers(req.DeliveryModes, checkpointed) {
		return nil, discovery.ErrCheckpointedNotOffered
	}
	after := req.GetAfterSequence()
	if after != cp.Sequence {
		return nil, discovery.ErrDiscoveryNotFound
	}
	total := int64(len(s.certificates))
	items, e := s.page(after, total, req.MaxItems, req.MaxBytes, discovery.MaxResultBytes-discovery.CheckpointedResponseReserve)
	if e != nil {
		return nil, e
	}
	cp.Sequence = after + int64(len(items))
	return &mdl.DiscoveryResultsResponseDto{Items: items, HighestSequence: cp.Sequence, More: cp.Sequence < total, Checkpoint: encode(cp)}, nil
}

// bufferedPage returns the buffered items after afterSequence. A drain
// acknowledges everything up to its afterSequence, which may then be dropped.
func (s *Store) bufferedPage(req *mdl.DiscoveryDrainRequestDto, cp checkpoint) (*mdl.DiscoveryResultsResponseDto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	r, e := s.buffered(req.RunId, cp, discovery.ErrInvalidRequest)
	if e != nil {
		return nil, e
	}
	after := req.GetAfterSequence()
	if after < r.ack {
		return nil, discovery.ErrDiscoveryNotFound
	}
	if after > r.produced {
		return nil, discovery.ErrInvalidRequest
	}
	envelope, _ := json.Marshal(&mdl.DiscoveryResultsResponseDto{Items: []mdl.DiscoveredItemDto{}, HighestSequence: r.produced})
	items, e := s.page(after, r.produced, req.MaxItems, req.MaxBytes, discovery.MaxResultBytes-int64(len(envelope)))
	if e != nil {
		return nil, e
	}
	r.ack = after
	return &mdl.DiscoveryResultsResponseDto{Items: items, HighestSequence: r.produced, More: after+int64(len(items)) < r.produced}, nil
}

// page returns the fixtures after sequence after, up to upTo, within the
// drain's bounds. budget is the most the items may take when the drain sets
// no maxBytes, and caps one that does. A single item larger than the bound
// cannot be sent on any page, so it is an error rather than an empty page.
func (s *Store) page(after, upTo int64, maxItems *int32, maxBytes *int64, budget int64) ([]mdl.DiscoveredItemDto, error) {
	limit := defaultMaxItems
	if maxItems != nil {
		limit = *maxItems
	}
	if maxBytes != nil && *maxBytes < budget {
		budget = *maxBytes
	}
	items := []mdl.DiscoveredItemDto{}
	size := int64(2)
	for seq := after + 1; seq <= upTo && len(items) < int(limit); seq++ {
		item := mdl.DiscoveredItemDto{Sequence: seq, UniqueRef: "example-certificate-" + strconv.FormatInt(seq, 10), Payload: mdl.DiscoveredCertificateDtoAsDiscoveredItemPayload(mdl.NewDiscoveredCertificateDto(mdl.RESOURCE_CERTIFICATES, s.certificates[seq-1]))}
		b, _ := json.Marshal(item)
		extra := int64(len(b))
		if len(items) > 0 {
			extra++
		}
		if size+extra > budget {
			if len(items) == 0 {
				return nil, discovery.ErrInvalidRequest.WithProperty("reason", "maxBytes cannot fit the next item")
			}
			break
		}
		size += extra
		items = append(items, item)
	}
	return items, nil
}

func (s *Store) SupportedResources(context.Context) ([]mdl.DiscoverySupportedResourceDto, error) {
	return []mdl.DiscoverySupportedResourceDto{{Resource: mdl.RESOURCE_CERTIFICATES}}, nil
}

func (s *Store) RunAttributes(context.Context) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}

func (s *Store) ResourceAttributes(_ context.Context, r mdl.Resource) ([]mdl.BaseAttributeDto, error) {
	if r != mdl.RESOURCE_CERTIFICATES {
		return nil, discovery.ErrResourceNotSupported
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
