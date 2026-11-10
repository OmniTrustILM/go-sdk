package main

import (
	"context"
	"crypto/x509"
	"encoding/base64"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"testing"
)

func TestStoreDrainRetryStopResume(t *testing.T) {
	ctx := context.Background()
	s, e := NewStore()
	if e != nil {
		t.Fatal(e)
	}
	init := &mdl.DiscoveryInitiateRequestDto{RunId: "b11c9be1-b619-4ef5-be1b-a1cd9ef265b7", Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}}
	started, e := s.Initiate(ctx, init)
	if e != nil {
		t.Fatal(e)
	}
	r := &mdl.DiscoveryRunRequestDto{RunId: init.RunId, Resources: init.Resources, Checkpoint: started.Checkpoint}
	st, e := s.Status(ctx, r)
	if e != nil || st.HighestSequence != 1 || st.State != mdl.DISCOVERYRUNSTATE_RUNNING {
		t.Fatalf("%+v %v", st, e)
	}
	if _, e = s.Initiate(ctx, init); e != nil {
		t.Fatal(e)
	}
	stop, e := s.Stop(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Checkpoint = stop.Checkpoint
	st, e = s.Status(ctx, r)
	if e != nil || st.HighestSequence != 1 || st.State != mdl.DISCOVERYRUNSTATE_STOPPED {
		t.Fatalf("%+v %v", st, e)
	}
	d := &mdl.DiscoveryDrainRequestDto{RunId: r.RunId, Resources: r.Resources, Checkpoint: r.Checkpoint, MaxItems: new(int32(1))}
	a, e := s.Results(ctx, d)
	if e != nil || len(a.Items) != 1 || a.Items[0].Sequence != 1 {
		t.Fatalf("%+v %v", a, e)
	}
	b, e := s.Results(ctx, d)
	if e != nil || b.Items[0].UniqueRef != a.Items[0].UniqueRef {
		t.Fatalf("retry changed item: %+v %v", b, e)
	}
	der, e := base64.StdEncoding.DecodeString(a.Items[0].Payload.DiscoveredCertificateDto.CertificateData)
	if e != nil {
		t.Fatal(e)
	}
	if _, e = x509.ParseCertificate(der); e != nil {
		t.Fatal(e)
	}
	resumed, e := s.Resume(ctx, r)
	if e != nil {
		t.Fatal(e)
	}
	r.Checkpoint = resumed.Checkpoint
	st, e = s.Status(ctx, r)
	if e != nil || st.HighestSequence != 2 {
		t.Fatalf("%+v %v", st, e)
	}
	d.Checkpoint = r.Checkpoint
	d.AfterSequence = new(int64(1))
	b, e = s.Results(ctx, d)
	if e != nil || len(b.Items) != 1 || b.Items[0].Sequence != 2 {
		t.Fatalf("%+v %v", b, e)
	}
	d.AfterSequence = new(int64(0))
	if _, e = s.Results(ctx, d); e == nil {
		t.Fatal("lost acknowledged range returned silently")
	}
}

func TestStoreMoreReflectsBufferedItems(t *testing.T) {
	s, e := NewStore()
	if e != nil {
		t.Fatal(e)
	}
	ctx := context.Background()
	req := &mdl.DiscoveryInitiateRequestDto{RunId: "b11c9be1-b619-4ef5-be1b-a1cd9ef265b7", Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}}
	started, e := s.Initiate(ctx, req)
	if e != nil {
		t.Fatal(e)
	}
	d := &mdl.DiscoveryDrainRequestDto{RunId: req.RunId, Resources: req.Resources, Checkpoint: started.Checkpoint, MaxItems: new(int32(1))}
	out, e := s.Results(ctx, d)
	if e != nil || len(out.Items) != 0 || out.More {
		t.Fatalf("empty running run must wait for next poll: %+v %v", out, e)
	}
	r := &mdl.DiscoveryRunRequestDto{RunId: req.RunId, Resources: req.Resources, Checkpoint: started.Checkpoint}
	if _, e = s.Status(ctx, r); e != nil {
		t.Fatal(e)
	}
	out, e = s.Results(ctx, d)
	if e != nil || len(out.Items) != 1 || out.More {
		t.Fatalf("no buffered items beyond this page: %+v %v", out, e)
	}
	if _, e = s.Status(ctx, r); e != nil {
		t.Fatal(e)
	}
	out, e = s.Results(ctx, d)
	if e != nil || len(out.Items) != 1 || !out.More {
		t.Fatalf("second buffered item must advertise another page: %+v %v", out, e)
	}
}
