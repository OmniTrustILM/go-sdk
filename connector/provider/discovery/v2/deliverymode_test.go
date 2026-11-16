package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"slices"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

func TestOfferedDeliveryModes(t *testing.T) {
	for _, tc := range []struct {
		name  string
		offer []string
		want  []mdl.DiscoveryDeliveryMode
	}{
		{"absent offer is buffered only", nil, []mdl.DiscoveryDeliveryMode{buffered}},
		{"empty offer is none", []string{}, []mdl.DiscoveryDeliveryMode{}},
		{"keeps Core's order", []string{"checkpointed", "buffered"}, []mdl.DiscoveryDeliveryMode{checkpointed, buffered}},
		{"skips unknown and repeated codes", []string{"streamed", "buffered", "checkpointed", "buffered"}, []mdl.DiscoveryDeliveryMode{buffered, checkpointed}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := OfferedDeliveryModes(tc.offer); !slices.Equal(got, tc.want) {
				t.Fatalf("got %v, want %v", got, tc.want)
			}
		})
	}
}

func TestOffers(t *testing.T) {
	if !Offers(nil, buffered) || Offers(nil, checkpointed) {
		t.Fatal("an absent offer offers buffered only")
	}
	if !Offers([]string{"checkpointed"}, checkpointed) || Offers([]string{}, buffered) {
		t.Fatal("an explicit offer offers exactly its modes")
	}
}

func TestChooseDeliveryModeFollowsCoresPreference(t *testing.T) {
	mode, e := ChooseDeliveryMode([]string{"buffered", "checkpointed"}, checkpointed, buffered)
	if e != nil || mode != buffered {
		t.Fatalf("%v %v", mode, e)
	}
	mode, e = ChooseDeliveryMode([]string{"streamed", "checkpointed"}, buffered, checkpointed)
	if e != nil || mode != checkpointed {
		t.Fatalf("%v %v", mode, e)
	}
	mode, e = ChooseDeliveryMode(nil, checkpointed, buffered)
	if e != nil || mode != buffered {
		t.Fatalf("an older Core gets buffered: %v %v", mode, e)
	}
}

func TestChooseDeliveryModeRefusesWhenNoneIsSupported(t *testing.T) {
	_, e := ChooseDeliveryMode(nil, checkpointed)
	var se *shared.Error
	if !errors.As(e, &se) || se.Status != 422 || se.ErrorCode != "VALIDATION_FAILED" {
		t.Fatalf("%v", e)
	}
	if !strings.Contains(se.Detail, "[buffered]") || !strings.Contains(se.Detail, "[checkpointed]") {
		t.Fatalf("detail must name both lists: %q", se.Detail)
	}
}

const (
	buffered     = mdl.DISCOVERYDELIVERYMODE_BUFFERED
	checkpointed = mdl.DISCOVERYDELIVERYMODE_CHECKPOINTED
)

// modeProvider answers the delivery-mode fields a checkpointed connector sets.
type modeProvider struct {
	testProvider
	offered []string
}

func (p *modeProvider) Initiate(_ context.Context, r *mdl.DiscoveryInitiateRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	p.offered = r.DeliveryModes
	mode, e := ChooseDeliveryMode(r.DeliveryModes, checkpointed)
	if e != nil {
		return nil, e
	}
	return &mdl.DiscoveryInitiateResponseDto{DeliveryMode: &mode}, nil
}

func (p *modeProvider) Results(_ context.Context, r *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error) {
	if !Offers(r.DeliveryModes, checkpointed) {
		return nil, ErrCheckpointedNotOffered
	}
	return &mdl.DiscoveryResultsResponseDto{Checkpoint: r.Checkpoint}, nil
}

func TestDeliveryModesOverHTTP(t *testing.T) {
	p := &modeProvider{}
	c := serve(t, p)

	w := request(t, c, "/v2/discoveryProvider/discoveries/initiate", `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"deliveryModes":["streamed","checkpointed"]}`)
	if w.Code != 202 || !bytes.Contains(w.Body.Bytes(), []byte(`"deliveryMode":"checkpointed"`)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	if !slices.Equal(p.offered, []string{"streamed", "checkpointed"}) {
		t.Fatalf("offer not forwarded as sent: %v", p.offered)
	}

	w = request(t, c, "/v2/discoveryProvider/discoveries/initiate", validBody)
	if w.Code != 422 || !bytes.Contains(w.Body.Bytes(), []byte(`"errorCode":"VALIDATION_FAILED"`)) {
		t.Fatalf("an older Core must be refused: %d %s", w.Code, w.Body)
	}

	w = request(t, c, "/v2/discoveryProvider/discoveries/results", validBody)
	if w.Code != 503 || !bytes.Contains(w.Body.Bytes(), []byte(`"errorCode":"SERVICE_UNAVAILABLE"`)) {
		t.Fatalf("a drain without the checkpointed offer: %d %s", w.Code, w.Body)
	}

	cp := `[{"version":3,"schemaVersion":"v3","uuid":"d0235059-d463-4937-a2aa-20efdd000001","name":"cp","type":"meta","contentType":"string","properties":{"label":"cp","visible":false},"content":[{"contentType":"string","data":"{\"next\":7}"}]}]`
	w = request(t, c, "/v2/discoveryProvider/discoveries/results", `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"deliveryModes":["checkpointed"],"checkpoint":`+cp+`}`)
	if w.Code != 200 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	var out struct {
		Checkpoint []map[string]any `json:"checkpoint"`
	}
	if e := json.Unmarshal(w.Body.Bytes(), &out); e != nil || len(out.Checkpoint) != 1 || !strings.Contains(w.Body.String(), `{\"next\":7}`) {
		t.Fatalf("the page's checkpoint must round-trip: %s %v", w.Body, e)
	}
}

func TestOversizedCheckpointIsRefused(t *testing.T) {
	c := serve(t, &testProvider{})
	data := strings.Repeat("x", MaxCheckpointBytes)
	body := `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"checkpoint":[{"version":3,"schemaVersion":"v3","uuid":"d0235059-d463-4937-a2aa-20efdd000001","name":"cp","type":"meta","contentType":"string","properties":{"label":"cp","visible":false},"content":[{"contentType":"string","data":"` + data + `"}]}]}`
	if w := request(t, c, "/v2/discoveryProvider/discoveries/status", body); w.Code != 422 {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

func TestUnknownResourceAttributesAreNotFound(t *testing.T) {
	c := serve(t, &testProvider{})
	w := request(t, c, "/v2/discoveryProvider/unknown/attributes", "")
	if w.Code != 404 || !bytes.Contains(w.Body.Bytes(), []byte(`"errorCode":"RESOURCE_NOT_FOUND"`)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}

// nilProvider answers every lifecycle call with neither a value nor an error.
type nilProvider struct{ testProvider }

func (nilProvider) Initiate(context.Context, *mdl.DiscoveryInitiateRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	return nil, nil
}
func (nilProvider) Resume(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	return nil, nil
}
func (nilProvider) Stop(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStopResponseDto, error) {
	return nil, nil
}
func (nilProvider) Status(context.Context, *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStatusResponseDto, error) {
	return nil, nil
}
func (nilProvider) Results(context.Context, *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error) {
	return nil, nil
}

func TestNilProviderResponseIsAnInternalError(t *testing.T) {
	h, e := NewHandler(&nilProvider{})
	if e != nil {
		t.Fatal(e)
	}
	c, e := shared.New(shared.Register(h))
	if e != nil {
		t.Fatal(e)
	}
	for _, op := range []string{"initiate", "resume", "stop", "status", "results"} {
		if w := request(t, c, "/v2/discoveryProvider/discoveries/"+op, validBody); w.Code != 500 {
			t.Fatalf("%s: %d %s", op, w.Code, w.Body)
		}
	}
	for _, op := range []string{"initiate", "resume", "stop", "status", "cancel"} {
		if w := request(t, c, "/v2/discoveryProvider/discoveries/"+op, `{}`); w.Code != 422 {
			t.Fatalf("%s invalid body: %d %s", op, w.Code, w.Body)
		}
	}
}

func TestNewHandlerRejectsNilProvider(t *testing.T) {
	if _, e := NewHandler(nil); e == nil {
		t.Fatal("nil provider accepted")
	}
}
