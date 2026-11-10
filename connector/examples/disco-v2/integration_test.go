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
	h.AssertMetric(t, `app_build_info{`)
	h.AssertLogsConform(t)
}
func TestDiscoV2Lifecycle(t *testing.T) {
	h := startDisco(t)
	r := initiate(t, h)
	var st mdl.DiscoveryStatusResponseDto
	if status := h.GetJSON(t, "POST", base+"/discoveries/status", r, &st); status != 200 || st.State != mdl.DISCOVERYRUNSTATE_RUNNING || st.HighestSequence != 1 {
		t.Fatalf("%d %+v", status, st)
	}
	// A repeated initiate must not replace its handle or reset production.
	resp := h.Do(t, itest.Request{Method: "POST", Path: base + "/discoveries/initiate", Body: mdl.DiscoveryInitiateRequestDto{RunId: r.RunId, Resources: r.Resources}})
	if !itest.AssertStatus(t, resp, 202) {
		t.FailNow()
	}
	var repeated mdl.DiscoveryInitiateResponseDto
	resp.JSON(t, &repeated)
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
	assertProblem(t, resp, 404, "RESOURCE_NOT_FOUND")
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
	h.GetJSON(t, "POST", base+"/discoveries/status", r, &st)
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
