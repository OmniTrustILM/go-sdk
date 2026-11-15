package main

import (
	"context"
	"errors"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const runID = "b11c9be1-b619-4ef5-be1b-a1cd9ef265b7"

var bothModes = []string{"checkpointed", "buffered"}

func newStore(t *testing.T) *Store {
	t.Helper()
	s, e := NewStore()
	if e != nil {
		t.Fatal(e)
	}
	return s
}

func assertCode(t *testing.T, e error, status int, code string) {
	t.Helper()
	var se *shared.Error
	if !errors.As(e, &se) || se.Status != status || se.ErrorCode != code {
		t.Fatalf("want %d %s, got %v", status, code, e)
	}
}

func startCheckpointed(t *testing.T, s *Store) *mdl.DiscoveryDrainRequestDto {
	t.Helper()
	out, e := s.Initiate(context.Background(), &mdl.DiscoveryInitiateRequestDto{RunId: runID, Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}, DeliveryModes: bothModes})
	if e != nil || out.GetDeliveryMode() != checkpointed || len(out.Checkpoint) != 1 || !out.GetStoppable() {
		t.Fatalf("%+v %v", out, e)
	}
	return &mdl.DiscoveryDrainRequestDto{RunId: runID, Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}, Checkpoint: out.Checkpoint, DeliveryModes: bothModes, MaxItems: new(int32(1))}
}

func runRequest(d *mdl.DiscoveryDrainRequestDto) *mdl.DiscoveryRunRequestDto {
	return &mdl.DiscoveryRunRequestDto{RunId: d.RunId, Resources: d.Resources, Checkpoint: d.Checkpoint, DeliveryModes: d.DeliveryModes}
}

// Every page goes to a fresh store, as it would after a restart or on another
// replica: the checkpoint alone carries the run.
func TestCheckpointedRunNeedsNoState(t *testing.T) {
	ctx := context.Background()
	d := startCheckpointed(t, newStore(t))
	for seq := int64(1); seq <= 3; seq++ {
		st, e := newStore(t).Status(ctx, runRequest(d))
		if e != nil || st.State != mdl.DISCOVERYRUNSTATE_RUNNING || st.HighestSequence != seq-1 {
			t.Fatalf("status before page %d: %+v %v", seq, st, e)
		}
		page, e := newStore(t).Results(ctx, d)
		if e != nil || len(page.Items) != 1 || page.Items[0].Sequence != seq || page.HighestSequence != seq || page.More != (seq < 3) || len(page.Checkpoint) != 1 {
			t.Fatalf("page %d: %+v %v", seq, page, e)
		}
		retry, e := newStore(t).Results(ctx, d)
		if e != nil || retry.Items[0].UniqueRef != page.Items[0].UniqueRef {
			t.Fatalf("a retried page must repeat itself: %+v %v", retry, e)
		}
		d.AfterSequence, d.Checkpoint = new(seq), page.Checkpoint
	}
	st, e := newStore(t).Status(ctx, runRequest(d))
	if e != nil || st.State != mdl.DISCOVERYRUNSTATE_COMPLETED || st.HighestSequence != 3 {
		t.Fatalf("%+v %v", st, e)
	}
	ack, e := newStore(t).Results(ctx, d)
	if e != nil || len(ack.Items) != 0 || ack.More || ack.HighestSequence != 3 || len(ack.Checkpoint) != 1 {
		t.Fatalf("acknowledgement: %+v %v", ack, e)
	}
	if e = newStore(t).Cancel(ctx, runRequest(d)); e != nil {
		t.Fatal(e)
	}
}

func TestCheckpointedPageHonoursItsBounds(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	d := startCheckpointed(t, s)
	d.MaxItems = nil
	page, e := s.Results(ctx, d)
	if e != nil || len(page.Items) != 3 || page.More {
		t.Fatalf("all three fit one page: %+v %v", page, e)
	}
	d.MaxBytes = new(int64(10))
	_, e = s.Results(ctx, d)
	assertCode(t, e, 422, "VALIDATION_FAILED")
}

func TestCheckpointedStopAndResumeKeepCoresCheckpoint(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	d := startCheckpointed(t, s)
	stop, e := s.Stop(ctx, runRequest(d))
	if e != nil || stop.Checkpoint != nil {
		t.Fatalf("stop answers without a checkpoint: %+v %v", stop, e)
	}
	resumed, e := s.Resume(ctx, runRequest(d))
	if e != nil || resumed.Checkpoint != nil || resumed.GetDeliveryMode() != checkpointed {
		t.Fatalf("resume answers the mode and no checkpoint: %+v %v", resumed, e)
	}
	d.MaxItems = nil
	page, e := s.Results(ctx, d)
	if e != nil {
		t.Fatal(e)
	}
	d.AfterSequence, d.Checkpoint = new(int64(3)), page.Checkpoint
	_, e = s.Stop(ctx, runRequest(d))
	assertCode(t, e, 422, "OPERATION_PAST_POINT_OF_NO_RETURN")
	_, e = s.Resume(ctx, runRequest(d))
	assertCode(t, e, 422, "VALIDATION_FAILED")
}

func TestCheckpointedRefusals(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	d := startCheckpointed(t, s)

	noOffer := *d
	noOffer.DeliveryModes = []string{"buffered"}
	_, e := s.Results(ctx, &noOffer)
	assertCode(t, e, 503, "SERVICE_UNAVAILABLE")

	ahead := *d
	ahead.AfterSequence = new(int64(2))
	_, e = s.Results(ctx, &ahead)
	assertCode(t, e, 404, "OPERATION_NOT_TRACKED")

	otherRun := *d
	otherRun.RunId = "c22c9be1-b619-4ef5-be1b-a1cd9ef265b7"
	_, e = s.Results(ctx, &otherRun)
	assertCode(t, e, 422, "VALIDATION_FAILED")

	old := runRequest(d)
	old.DeliveryModes = nil
	_, e = s.Resume(ctx, old)
	assertCode(t, e, 422, "VALIDATION_FAILED")

	garbled := runRequest(d)
	garbled.Checkpoint = encode(checkpoint{Mode: "streamed", RunID: runID})
	_, e = s.Status(ctx, garbled)
	assertCode(t, e, 422, "VALIDATION_FAILED")
	_, e = s.Resume(ctx, garbled)
	assertCode(t, e, 410, "CHECKPOINT_LOST")
}

func TestInitiateChoosesTheMode(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	req := &mdl.DiscoveryInitiateRequestDto{RunId: runID, Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}}
	out, e := s.Initiate(ctx, req)
	if e != nil || out.GetDeliveryMode() != buffered {
		t.Fatalf("an older Core gets buffered: %+v %v", out, e)
	}
	req.RunId, req.DeliveryModes = "c22c9be1-b619-4ef5-be1b-a1cd9ef265b7", []string{"buffered", "checkpointed"}
	if out, e = s.Initiate(ctx, req); e != nil || out.GetDeliveryMode() != buffered {
		t.Fatalf("Core's preference wins: %+v %v", out, e)
	}
	req.DeliveryModes = []string{}
	_, e = s.Initiate(ctx, req)
	assertCode(t, e, 422, "VALIDATION_FAILED")
	req.DeliveryModes, req.Checkpoint = bothModes, out.Checkpoint
	_, e = s.Initiate(ctx, req)
	assertCode(t, e, 422, "VALIDATION_FAILED")
}

func TestBufferedRefusals(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	req := &mdl.DiscoveryInitiateRequestDto{RunId: runID, Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}}
	out, e := s.Initiate(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	r := &mdl.DiscoveryRunRequestDto{RunId: runID, Resources: req.Resources, Checkpoint: out.Checkpoint}

	_, e = s.Results(ctx, &mdl.DiscoveryDrainRequestDto{RunId: runID, Resources: req.Resources, Checkpoint: out.Checkpoint, AfterSequence: new(int64(1))})
	assertCode(t, e, 422, "VALIDATION_FAILED")

	resumeOther := *r
	resumeOther.DeliveryModes = []string{"checkpointed"}
	_, e = s.Resume(ctx, &resumeOther)
	assertCode(t, e, 422, "VALIDATION_FAILED")

	for range 3 {
		if _, e = s.Status(ctx, r); e != nil {
			t.Fatal(e)
		}
	}
	_, e = s.Stop(ctx, r)
	assertCode(t, e, 422, "OPERATION_PAST_POINT_OF_NO_RETURN")
	r.Checkpoint = bufferedCheckpoint(runID, s.runs[runID])
	_, e = s.Resume(ctx, r)
	assertCode(t, e, 422, "VALIDATION_FAILED")

	if e = s.Cancel(ctx, r); e != nil {
		t.Fatal(e)
	}
	_, e = s.Status(ctx, r)
	assertCode(t, e, 404, "OPERATION_NOT_TRACKED")
	_, e = s.Resume(ctx, r)
	assertCode(t, e, 404, "OPERATION_NOT_TRACKED")
	_, e = s.Resume(ctx, &mdl.DiscoveryRunRequestDto{RunId: runID, Resources: req.Resources})
	assertCode(t, e, 410, "CHECKPOINT_LOST")
}

func TestNilRequestsAndMetadata(t *testing.T) {
	ctx := context.Background()
	s := newStore(t)
	if _, e := s.Initiate(ctx, nil); e == nil {
		t.Fatal("nil initiate")
	}
	if _, e := s.Status(ctx, nil); e == nil {
		t.Fatal("nil status")
	}
	if _, e := s.Stop(ctx, nil); e == nil {
		t.Fatal("nil stop")
	}
	if _, e := s.Resume(ctx, nil); e == nil {
		t.Fatal("nil resume")
	}
	if e := s.Cancel(ctx, nil); e == nil {
		t.Fatal("nil cancel")
	}
	if _, e := s.Results(ctx, nil); e == nil {
		t.Fatal("nil results")
	}
	_, e := s.ResourceAttributes(ctx, mdl.RESOURCE_KEYS)
	assertCode(t, e, 404, "RESOURCE_NOT_FOUND")
	if attrs, e := s.ResourceAttributes(ctx, mdl.RESOURCE_CERTIFICATES); e != nil || attrs == nil {
		t.Fatalf("%v %v", attrs, e)
	}
	if defs, e := s.ListDefinitions(ctx); e != nil || defs.ConnectorVersion != connectorVersion {
		t.Fatalf("%+v %v", defs, e)
	}
	_, e = s.GetDefinition(ctx, "any")
	assertCode(t, e, 404, "ATTRIBUTE_DEFINITION_NOT_FOUND")
	_, e = s.Callback(ctx, &mdl.AttributeCallbackRequestDto{})
	assertCode(t, e, 404, "ATTRIBUTE_DEFINITION_NOT_FOUND")
}
