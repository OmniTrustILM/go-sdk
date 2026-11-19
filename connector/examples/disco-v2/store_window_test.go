package main

import (
	"context"
	"slices"
	"testing"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
)

// discover runs a whole discovery in the given delivery mode and returns the
// unique references of what it found, in sequence order.
func discover(t *testing.T, mode string, since *time.Time) []string {
	t.Helper()
	ctx := context.Background()
	s := newStore(t)
	resources := []mdl.Resource{mdl.RESOURCE_CERTIFICATES}
	started, e := s.Initiate(ctx, &mdl.DiscoveryInitiateRequestDto{RunId: runID, Resources: resources, DeliveryModes: []string{mode}, DiscoverSince: since})
	if e != nil || string(started.GetDeliveryMode()) != mode {
		t.Fatalf("initiate: %+v %v", started, e)
	}
	r := &mdl.DiscoveryRunRequestDto{RunId: runID, Resources: resources, Checkpoint: started.Checkpoint, DeliveryModes: []string{mode}}
	for range 4 {
		st, e := s.Status(ctx, r)
		if e != nil {
			t.Fatal(e)
		}
		if st.State == mdl.DISCOVERYRUNSTATE_COMPLETED {
			break
		}
	}
	d := &mdl.DiscoveryDrainRequestDto{RunId: runID, Resources: resources, Checkpoint: started.Checkpoint, DeliveryModes: []string{mode}, AfterSequence: new(int64(0))}
	var refs []string
	for {
		page, e := s.Results(ctx, d)
		if e != nil {
			t.Fatal(e)
		}
		for _, item := range page.Items {
			if item.Sequence != int64(len(refs))+1 {
				t.Fatalf("sequence %d after %d items", item.Sequence, len(refs))
			}
			refs = append(refs, item.UniqueRef)
		}
		if len(page.Checkpoint) > 0 {
			d.Checkpoint = page.Checkpoint
		}
		if !page.More {
			break
		}
		d.AfterSequence = new(page.HighestSequence)
	}
	st, e := s.Status(ctx, &mdl.DiscoveryRunRequestDto{RunId: runID, Resources: resources, Checkpoint: d.Checkpoint, DeliveryModes: []string{mode}})
	if e != nil || st.State != mdl.DISCOVERYRUNSTATE_COMPLETED || st.HighestSequence != int64(len(refs)) {
		t.Fatalf("final status: %+v %v", st, e)
	}
	return refs
}

func TestDiscoversEveryFixture_WithoutDiscoverSince(t *testing.T) {
	want := []string{"example-certificate-1", "example-certificate-2", "example-certificate-3"}
	for _, mode := range bothModes {
		t.Run(mode, func(t *testing.T) {
			if got := discover(t, mode, nil); !slices.Equal(got, want) {
				t.Fatalf("got %v, want %v", got, want)
			}
		})
	}
}

func TestDiscoversOnlyNewerFixtures_WithDiscoverSince(t *testing.T) {
	for _, tc := range []struct {
		name  string
		since time.Time
		want  []string
	}{
		{"atCreation", time.Date(2026, 2, 1, 0, 0, 0, 0, time.UTC), []string{"example-certificate-2", "example-certificate-3"}},
		{"betweenCreations", time.Date(2026, 2, 1, 0, 0, 1, 0, time.UTC), []string{"example-certificate-3"}},
		{"afterEveryCreation", time.Date(2026, 4, 1, 0, 0, 0, 0, time.UTC), nil},
	} {
		for _, mode := range bothModes {
			t.Run(tc.name+"/"+mode, func(t *testing.T) {
				if got := discover(t, mode, &tc.since); !slices.Equal(got, tc.want) {
					t.Fatalf("got %v, want %v", got, tc.want)
				}
			})
		}
	}
}
