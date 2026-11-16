package main_test

import (
	"crypto/x509"
	"encoding/base64"
	"net/http"
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"
	"github.com/google/uuid"
)

const base = "/v2/discoveryProvider"

func startDisco(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{Path: "connector/examples/disco-v2"})
}
func initiate(t *testing.T, h *itest.Harness) *mdl.DiscoveryRunRequestDto {
	t.Helper()
	r := mdl.DiscoveryInitiateRequestDto{RunId: uuid.NewString(), Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}}
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: base + "/discoveries/initiate", Body: r})
	if !itest.AssertStatus(t, resp, 202) {
		t.FailNow()
	}
	var out mdl.DiscoveryInitiateResponseDto
	resp.JSON(t, &out)
	if !out.GetStoppable() || len(out.Checkpoint) == 0 {
		t.Fatalf("missing stop/resume handle: %+v", out)
	}
	return &mdl.DiscoveryRunRequestDto{RunId: r.RunId, Resources: r.Resources, Checkpoint: out.Checkpoint}
}
func TestDiscoV2InfoHealthAndMetadata(t *testing.T) {
	h := startDisco(t)
	h.AssertHealthy(t, "/v2/health")
	var info mdl.InfoResponse
	if status := h.GetJSON(t, "GET", "/v2/info", nil, &info); status != 200 {
		t.Fatal(status)
	}
	found := false
	for _, i := range info.Interfaces {
		if string(i.Code) == "discovery" && i.Version == "v2" {
			found = slices.Contains(i.Features, mdl.FEATUREFLAG_DISCOVERY_STOP_RESUME)
		}
	}
	if !found {
		t.Fatalf("discovery v2 stop/resume absent: %+v", info)
	}
	var resources []mdl.DiscoverySupportedResourceDto
	if status := h.GetJSON(t, "GET", base+"/resources", nil, &resources); status != 200 || len(resources) != 1 || resources[0].Resource != mdl.RESOURCE_CERTIFICATES {
		t.Fatalf("%d %+v", status, resources)
	}
	for _, path := range []string{base + "/attributes", base + "/certificates/attributes"} {
		var attrs []mdl.BaseAttributeDto
		if status := h.GetJSON(t, "GET", path, nil, &attrs); status != 200 || attrs == nil || len(attrs) != 0 {
			t.Fatalf("%s %d %+v", path, status, attrs)
		}
	}
	var defs mdl.AttributeDefinitionsDto
	if status := h.GetJSON(t, "GET", "/v2/attributes", nil, &defs); status != 200 || defs.ConnectorVersion == "" || defs.Definitions == nil {
		t.Fatalf("%d %+v", status, defs)
	}
	resp := h.Do(t, itest.Request{Method: "GET", Path: base + "/keys/attributes"})
	assertProblem(t, resp, 404, "RESOURCE_NOT_FOUND")
	h.AssertMetric(t, `app_build_info{`)
	h.AssertLogsConform(t)
}

// A checkpointed run travels over HTTP with its checkpoint replayed on every
// call; nothing about it is held between calls.
func TestDiscoV2CheckpointedLifecycle(t *testing.T) {
	h := startDisco(t)
	modes := []string{"checkpointed", "buffered"}
	init := mdl.DiscoveryInitiateRequestDto{RunId: uuid.NewString(), Resources: []mdl.Resource{mdl.RESOURCE_CERTIFICATES}, DeliveryModes: modes}
	var started mdl.DiscoveryInitiateResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/initiate", init, &started); status != 202 || started.GetDeliveryMode() != mdl.DISCOVERYDELIVERYMODE_CHECKPOINTED || len(started.Checkpoint) != 1 {
		t.Fatalf("%d %+v", status, started)
	}
	r := mdl.DiscoveryRunRequestDto{RunId: init.RunId, Resources: init.Resources, Checkpoint: started.Checkpoint, DeliveryModes: modes}
	var stopped mdl.DiscoveryStopResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/stop", r, &stopped); status != 200 || stopped.Checkpoint != nil {
		t.Fatalf("%d %+v", status, stopped)
	}
	var resumed mdl.DiscoveryInitiateResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/resume", r, &resumed); status != 202 || resumed.Checkpoint != nil || resumed.GetDeliveryMode() != mdl.DISCOVERYDELIVERYMODE_CHECKPOINTED {
		t.Fatalf("%d %+v", status, resumed)
	}
	d := mdl.DiscoveryDrainRequestDto{RunId: r.RunId, Resources: r.Resources, Checkpoint: r.Checkpoint, DeliveryModes: modes, MaxItems: new(int32(2))}
	var page mdl.DiscoveryResultsResponseDto
	for _, want := range []struct {
		first, last int64
		more        bool
	}{{1, 2, true}, {3, 3, false}} {
		if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &page); status != 200 || len(page.Items) == 0 || page.Items[0].Sequence != want.first || page.Items[len(page.Items)-1].Sequence != want.last || page.More != want.more || len(page.Checkpoint) != 1 {
			t.Fatalf("%d %+v", status, page)
		}
		d.AfterSequence, d.Checkpoint = new(want.last), page.Checkpoint
	}
	r.Checkpoint = d.Checkpoint
	var st mdl.DiscoveryStatusResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.State != mdl.DISCOVERYRUNSTATE_COMPLETED || st.HighestSequence != 3 {
		t.Fatalf("%d %+v", status, st)
	}
	d.DeliveryModes = []string{"buffered"}
	resp := h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/results", Body: d})
	assertProblem(t, resp, 503, "SERVICE_UNAVAILABLE")
	d.DeliveryModes, d.AfterSequence = modes, new(int64(1))
	resp = h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/results", Body: d})
	assertProblem(t, resp, 404, "OPERATION_NOT_TRACKED")
	resp = h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/cancel", Body: r})
	itest.AssertStatus(t, resp, 204)
	h.AssertLogsConform(t)
}
func TestDiscoV2Lifecycle(t *testing.T) {
	h := startDisco(t)
	r := initiate(t, h)
	var st mdl.DiscoveryStatusResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.State != mdl.DISCOVERYRUNSTATE_RUNNING || st.HighestSequence != 1 {
		t.Fatalf("%d %+v", status, st)
	}
	// A repeated initiate must not replace its handle or reset production; the
	// stop and status below prove it.
	resp := h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/initiate", Body: mdl.DiscoveryInitiateRequestDto{RunId: r.RunId, Resources: r.Resources}})
	if !itest.AssertStatus(t, resp, 202) {
		t.FailNow()
	}
	var stopped mdl.DiscoveryStopResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/stop", r, &stopped); status != 200 {
		t.Fatal(status)
	}
	r.Checkpoint = stopped.Checkpoint
	if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.State != mdl.DISCOVERYRUNSTATE_STOPPED || st.HighestSequence != 1 {
		t.Fatalf("%d %+v", status, st)
	}
	d := mdl.DiscoveryDrainRequestDto{RunId: r.RunId, Resources: r.Resources, Checkpoint: r.Checkpoint, MaxItems: new(int32(1))}
	var items mdl.DiscoveryResultsResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &items); status != 200 || len(items.Items) != 1 || items.Items[0].Sequence != 1 {
		t.Fatalf("%d %+v", status, items)
	}
	first := items.Items[0].UniqueRef
	if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &items); status != 200 || len(items.Items) != 1 || items.Items[0].UniqueRef != first {
		t.Fatalf("retry: %d %+v", status, items)
	}
	var resumed mdl.DiscoveryInitiateResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/resume", r, &resumed); status != 202 {
		t.Fatal(status)
	}
	r.Checkpoint = resumed.Checkpoint
	d.Checkpoint = r.Checkpoint
	for n := int64(2); n <= 3; n++ {
		if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.HighestSequence != n {
			t.Fatalf("%d %+v", status, st)
		}
	}
	if st.State != mdl.DISCOVERYRUNSTATE_COMPLETED {
		t.Fatal(st.State)
	}
	d.AfterSequence = new(int64(1))
	for n := int64(2); n <= 3; n++ {
		if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &items); status != 200 || len(items.Items) != 1 || items.Items[0].Sequence != n {
			t.Fatalf("%d %+v", status, items)
		}
		der, e := base64.StdEncoding.DecodeString(items.Items[0].Payload.DiscoveredCertificateDto.CertificateData)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = x509.ParseCertificate(der); e != nil {
			t.Fatal(e)
		}
		d.AfterSequence = new(n)
	}
	if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &items); status != 200 || items.Items == nil || len(items.Items) != 0 || items.More {
		t.Fatalf("%d %+v", status, items)
	}
	resp = h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/cancel", Body: r})
	itest.AssertStatus(t, resp, 204)
	resp = h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/status", Body: r})
	assertProblem(t, resp, 404, "OPERATION_NOT_TRACKED")
	h.AssertLogsConform(t)
}
func assertProblem(t *testing.T, r itest.Response, status int, code string) {
	t.Helper()
	if !itest.AssertStatus(t, r, status) {
		t.FailNow()
	}
	var p mdl.ProblemDetailExtended
	r.JSON(t, &p)
	if string(p.ErrorCode) != code {
		t.Fatalf("problem code: %+v", p)
	}
}
func TestDiscoV2ValidationAndBounds(t *testing.T) {
	h := startDisco(t)
	for _, body := range []any{map[string]any{}, mdl.DiscoveryInitiateRequestDto{RunId: uuid.NewString(), Resources: []mdl.Resource{mdl.RESOURCE_KEYS}}} {
		resp := h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/initiate", Body: body})
		assertProblem(t, resp, 422, "VALIDATION_FAILED")
	}
	r := initiate(t, h)
	var st mdl.DiscoveryStatusResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.HighestSequence != 1 {
		t.Fatalf("%d %+v", status, st)
	}
	d := mdl.DiscoveryDrainRequestDto{RunId: r.RunId, Resources: r.Resources, Checkpoint: r.Checkpoint, MaxBytes: new(int64(1))}
	resp := h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/results", Body: d})
	assertProblem(t, resp, 422, "VALIDATION_FAILED")
	d.MaxBytes = new(int64(1048576))
	var items mdl.DiscoveryResultsResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/results", d, &items); status != 200 || len(items.Items) != 1 || items.Items[0].Sequence != 1 {
		t.Fatalf("byte limit skipped item: %d %+v", status, items)
	}
	r.Checkpoint = nil
	resp = h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/resume", Body: r})
	assertProblem(t, resp, 410, "CHECKPOINT_LOST")
}
