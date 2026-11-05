package discovery

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http/httptest"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

type testProvider struct {
	Provider
	got string
	err error
}

func (p *testProvider) Initiate(_ context.Context, r *mdl.DiscoveryInitiateRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	p.got = r.RunId
	return &mdl.DiscoveryInitiateResponseDto{}, p.err
}
func (p *testProvider) Resume(_ context.Context, r *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryInitiateResponseDto, error) {
	return &mdl.DiscoveryInitiateResponseDto{}, p.err
}
func (p *testProvider) Stop(_ context.Context, r *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStopResponseDto, error) {
	return &mdl.DiscoveryStopResponseDto{}, p.err
}
func (p *testProvider) Status(_ context.Context, r *mdl.DiscoveryRunRequestDto) (*mdl.DiscoveryStatusResponseDto, error) {
	return &mdl.DiscoveryStatusResponseDto{State: mdl.DISCOVERYRUNSTATE_RUNNING}, p.err
}
func (p *testProvider) Results(_ context.Context, r *mdl.DiscoveryDrainRequestDto) (*mdl.DiscoveryResultsResponseDto, error) {
	return &mdl.DiscoveryResultsResponseDto{}, p.err
}
func (p *testProvider) Cancel(_ context.Context, r *mdl.DiscoveryRunRequestDto) error { return p.err }
func (p *testProvider) SupportedResources(context.Context) ([]mdl.DiscoverySupportedResourceDto, error) {
	return []mdl.DiscoverySupportedResourceDto{{Resource: mdl.RESOURCE_CERTIFICATES}}, nil
}
func (p *testProvider) RunAttributes(context.Context) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}
func (p *testProvider) ResourceAttributes(context.Context, mdl.Resource) ([]mdl.BaseAttributeDto, error) {
	return nil, nil
}
func serve(t *testing.T, p *testProvider) *shared.Connector {
	t.Helper()
	h, e := NewHandler(p)
	if e != nil {
		t.Fatal(e)
	}
	c, e := shared.New(shared.Register(h))
	if e != nil {
		t.Fatal(e)
	}
	return c
}
func request(t *testing.T, c *shared.Connector, path, body string) *httptest.ResponseRecorder {
	t.Helper()
	w := httptest.NewRecorder()
	method := "POST"
	if body == "" {
		method = "GET"
	}
	c.Handler().ServeHTTP(w, httptest.NewRequest(method, path, bytes.NewBufferString(body)))
	return w
}

const validBody = `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"]}`

func TestLifecycleHTTP(t *testing.T) {
	p := &testProvider{}
	c := serve(t, p)
	for _, tc := range []struct {
		op   string
		code int
	}{{"initiate", 202}, {"resume", 202}, {"stop", 200}, {"status", 200}, {"results", 200}, {"cancel", 204}} {
		t.Run(tc.op, func(t *testing.T) {
			w := request(t, c, "/v2/discoveryProvider/discoveries/"+tc.op, validBody)
			if w.Code != tc.code {
				t.Fatalf("%d: %s", w.Code, w.Body)
			}
			if tc.op == "results" {
				var m map[string]any
				if e := json.Unmarshal(w.Body.Bytes(), &m); e != nil {
					t.Fatal(e)
				}
				items, ok := m["items"].([]any)
				if !ok || len(items) != 0 {
					t.Fatalf("empty items must be []: %s", w.Body)
				}
			}
		})
	}
	if p.got != "b11c9be1-b619-4ef5-be1b-a1cd9ef265b7" {
		t.Fatal("run identity was not forwarded")
	}
}
func TestInvalidEnvelope(t *testing.T) {
	c := serve(t, &testProvider{})
	for _, body := range []string{`{}`, `{"runId":"bad","resources":["certificates"]}`, `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":[]}`, `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["invalid"]}`, `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"maxBytes":10485761}`, `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"maxItems":0}`, `{"runId":"b11c9be1-b619-4ef5-be1b-a1cd9ef265b7","resources":["certificates"],"afterSequence":-1}`} {
		w := request(t, c, "/v2/discoveryProvider/discoveries/results", body)
		if w.Code != 422 {
			t.Fatalf("%s: %d %s", body, w.Code, w.Body)
		}
	}
}
func TestProviderProblemAndMetadata(t *testing.T) {
	c := serve(t, &testProvider{err: ErrCheckpointLost})
	w := request(t, c, "/v2/discoveryProvider/discoveries/resume", validBody)
	if w.Code != 410 || !bytes.Contains(w.Body.Bytes(), []byte(`"errorCode":"CHECKPOINT_LOST"`)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
	for _, path := range []string{"/attributes", "/certificates/attributes"} {
		w = request(t, c, "/v2/discoveryProvider"+path, "")
		if w.Code != 200 || w.Body.String() != "[]\n" {
			t.Fatalf("%d %s", w.Code, w.Body)
		}
	}
}

type authorityStub struct{ authority.Provider }

func TestAuthorityComposition(t *testing.T) {
	a, e := authority.NewHandler(&authorityStub{})
	if e != nil {
		t.Fatal(e)
	}
	d, e := NewHandler(&testProvider{})
	if e != nil {
		t.Fatal(e)
	}
	c, e := shared.New(shared.Register(a), shared.Register(d))
	if e != nil {
		t.Fatal(e)
	}
	w := request(t, c, "/v2/info", "")
	if w.Code != 200 || !bytes.Contains(w.Body.Bytes(), []byte(`"discovery"`)) {
		t.Fatal(w.Body)
	}
}
func TestPayloadRoundTrip(t *testing.T) {
	var item mdl.DiscoveredItemDto
	raw := `{"sequence":1,"uniqueRef":"one","payload":{"resource":"certificates","certificateData":"YWJj"}}`
	if e := json.Unmarshal([]byte(raw), &item); e != nil {
		t.Fatal(e)
	}
	out, e := json.Marshal(item)
	if e != nil || !bytes.Contains(out, []byte(`"certificateData":"YWJj"`)) {
		t.Fatalf("%s %v", out, e)
	}
}

func TestLostResultsUseDeclaredProblemCode(t *testing.T) {
	c := serve(t, &testProvider{err: ErrDiscoveryNotFound})
	w := request(t, c, "/v2/discoveryProvider/discoveries/results", validBody)
	if w.Code != 404 || !bytes.Contains(w.Body.Bytes(), []byte(`"errorCode":"RESOURCE_NOT_FOUND"`)) {
		t.Fatalf("%d %s", w.Code, w.Body)
	}
}
