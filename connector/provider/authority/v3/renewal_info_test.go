package authority_test

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const renewalInfoPath = "/v3/authorityProvider/certificates/renewalInfo"

type renewalInfoStub struct {
	resp  *mdl.CertificateRenewalInfoResponseDtoV3
	err   error
	calls int
}

func (s *renewalInfoStub) RenewalInfo(context.Context, *mdl.CertificateRenewalInfoRequestDtoV3) (*mdl.CertificateRenewalInfoResponseDtoV3, error) {
	s.calls++
	return s.resp, s.err
}

func renewalInfoServer(t *testing.T, opts ...authority.Option) *httptest.Server {
	t.Helper()
	h, err := authority.NewHandler(stubProvider{}, opts...)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "ari", Name: "ari", Version: "0.0.1"}),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func renewalInfoBody(refs ...string) string {
	items := make([]string, len(refs))
	for i, ref := range refs {
		items[i] = fmt.Sprintf(`{"reference":%q,"certificate":"MIIB"}`, ref)
	}
	return `{"authorityAttributes":[],"raProfileAttributes":[],"certificates":[` + strings.Join(items, ",") + `]}`
}

func postRenewalInfo(t *testing.T, srv *httptest.Server, body string) (int, []byte) {
	t.Helper()
	resp, err := http.Post(srv.URL+renewalInfoPath, "application/json", strings.NewReader(body))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func result(ref string, status mdl.CertificateRenewalInfoStatusV3) mdl.CertificateRenewalInfoResultDtoV3 {
	return *mdl.NewCertificateRenewalInfoResultDtoV3(ref, status)
}

func TestRenewalInfoRouteAbsentWithoutOption(t *testing.T) {
	srv := renewalInfoServer(t)
	code, _ := postRenewalInfo(t, srv, renewalInfoBody("a"))
	if code != http.StatusNotFound && code != http.StatusMethodNotAllowed {
		t.Fatalf("status = %d, want 404/405 without the option", code)
	}
}

func TestWithRenewalInfoRejectsNil(t *testing.T) {
	if _, err := authority.NewHandler(stubProvider{}, authority.WithRenewalInfo(nil)); err == nil {
		t.Fatal("NewHandler accepted a nil renewal info provider")
	}
}

func TestRenewalInfoFlagWithoutOptionFails(t *testing.T) {
	_, err := authority.NewHandler(stubProvider{},
		authority.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_CERTIFICATE_RENEWAL_INFO))))
	if err == nil {
		t.Fatal("NewHandler accepted certificateRenewalInfo without WithRenewalInfo")
	}
}

func TestRenewalInfoFlagWithOptionBuilds(t *testing.T) {
	_, err := authority.NewHandler(stubProvider{},
		authority.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_CERTIFICATE_RENEWAL_INFO))),
		authority.WithRenewalInfo(&renewalInfoStub{}))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
}

func TestRenewalInfoStatusesPassThrough(t *testing.T) {
	start := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	end := start.Add(48 * time.Hour)
	available := result("a", mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE)
	available.WindowStart, available.WindowEnd = &start, &end
	retryAfter := int32(600)
	retry := result("d", mdl.CERTIFICATERENEWALINFOSTATUSV3_RETRY)
	retry.RetryAfter = &retryAfter

	stub := &renewalInfoStub{resp: mdl.NewCertificateRenewalInfoResponseDtoV3([]mdl.CertificateRenewalInfoResultDtoV3{
		available,
		result("b", mdl.CERTIFICATERENEWALINFOSTATUSV3_UNKNOWN),
		result("c", mdl.CERTIFICATERENEWALINFOSTATUSV3_NOT_SUPPORTED),
		retry,
	})}
	srv := renewalInfoServer(t, authority.WithRenewalInfo(stub))

	code, raw := postRenewalInfo(t, srv, renewalInfoBody("a", "b", "c", "d"))
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, raw)
	}
	var out mdl.CertificateRenewalInfoResponseDtoV3
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	want := []mdl.CertificateRenewalInfoStatusV3{
		mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE,
		mdl.CERTIFICATERENEWALINFOSTATUSV3_UNKNOWN,
		mdl.CERTIFICATERENEWALINFOSTATUSV3_NOT_SUPPORTED,
		mdl.CERTIFICATERENEWALINFOSTATUSV3_RETRY,
	}
	if len(out.Results) != len(want) {
		t.Fatalf("results = %d, want %d", len(out.Results), len(want))
	}
	for i, w := range want {
		if out.Results[i].Status != w {
			t.Errorf("result %d status = %s, want %s", i, out.Results[i].Status, w)
		}
	}
	if !out.Results[0].WindowStart.Equal(start) || !out.Results[0].WindowEnd.Equal(end) {
		t.Errorf("available window = %v..%v, want %v..%v", out.Results[0].WindowStart, out.Results[0].WindowEnd, start, end)
	}
	if got := out.Results[3].GetRetryAfter(); got != 600 {
		t.Errorf("retryAfter = %d, want 600", got)
	}
}

func TestRenewalInfoRejectsInvalidRequest(t *testing.T) {
	fifty := make([]string, 50)
	fifty1 := make([]string, 51)
	for i := range fifty1 {
		fifty1[i] = fmt.Sprintf("r%d", i)
	}
	copy(fifty, fifty1)

	cases := map[string]string{
		"no items":            renewalInfoBody(),
		"51 items":            renewalInfoBody(fifty1...),
		"duplicate reference": renewalInfoBody("a", "b", "a"),
		"blank reference":     renewalInfoBody(" "),
		"blank certificate":   `{"authorityAttributes":[],"raProfileAttributes":[],"certificates":[{"reference":"a","certificate":" "}]}`,
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &renewalInfoStub{resp: mdl.NewCertificateRenewalInfoResponseDtoV3(nil)}
			srv := renewalInfoServer(t, authority.WithRenewalInfo(stub))
			code, raw := postRenewalInfo(t, srv, body)
			if code != http.StatusUnprocessableEntity {
				t.Fatalf("status = %d, want 422: %s", code, raw)
			}
			if stub.calls != 0 {
				t.Errorf("provider called %d times for an invalid request", stub.calls)
			}
		})
	}

	t.Run("50 items accepted", func(t *testing.T) {
		stub := &renewalInfoStub{resp: mdl.NewCertificateRenewalInfoResponseDtoV3(nil)}
		srv := renewalInfoServer(t, authority.WithRenewalInfo(stub))
		if code, raw := postRenewalInfo(t, srv, renewalInfoBody(fifty...)); code != http.StatusOK {
			t.Fatalf("status = %d: %s", code, raw)
		}
	})
}

func TestRenewalInfoInvalidWindowBecomesRetry(t *testing.T) {
	start := time.Date(2026, 12, 1, 0, 0, 0, 0, time.UTC)
	retryAfter := int32(300)

	noStart := result("nostart", mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE)
	noStart.WindowEnd = &start
	noEnd := result("noend", mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE)
	noEnd.WindowStart = &start
	equal := result("equal", mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE)
	equal.WindowStart, equal.WindowEnd = &start, &start
	before := result("before", mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE)
	earlier := start.Add(-time.Hour)
	before.WindowStart, before.WindowEnd, before.RetryAfter = &start, &earlier, &retryAfter

	stub := &renewalInfoStub{resp: mdl.NewCertificateRenewalInfoResponseDtoV3([]mdl.CertificateRenewalInfoResultDtoV3{
		noStart, noEnd, equal, before,
	})}
	srv := renewalInfoServer(t, authority.WithRenewalInfo(stub))

	code, raw := postRenewalInfo(t, srv, renewalInfoBody("nostart", "noend", "equal", "before"))
	if code != http.StatusOK {
		t.Fatalf("status = %d: %s", code, raw)
	}
	var out mdl.CertificateRenewalInfoResponseDtoV3
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v", err)
	}
	for _, r := range out.Results {
		if r.Status != mdl.CERTIFICATERENEWALINFOSTATUSV3_RETRY {
			t.Errorf("%s status = %s, want retry", r.Reference, r.Status)
		}
		if r.WindowStart != nil || r.WindowEnd != nil {
			t.Errorf("%s keeps a window after being rewritten to retry", r.Reference)
		}
	}
	if got := out.Results[3].GetRetryAfter(); got != 300 {
		t.Errorf("retryAfter = %d, want the provider's 300 kept", got)
	}
	if noStart.Status != mdl.CERTIFICATERENEWALINFOSTATUSV3_AVAILABLE {
		t.Error("the provider's result was mutated")
	}
}

func TestRenewalInfoProviderErrorAndNilResponse(t *testing.T) {
	t.Run("error", func(t *testing.T) {
		srv := renewalInfoServer(t, authority.WithRenewalInfo(&renewalInfoStub{err: authority.ErrConnectionFailed}))
		if code, _ := postRenewalInfo(t, srv, renewalInfoBody("a")); code != http.StatusServiceUnavailable {
			t.Fatalf("status = %d, want 503", code)
		}
	})
	t.Run("nil response", func(t *testing.T) {
		srv := renewalInfoServer(t, authority.WithRenewalInfo(&renewalInfoStub{}))
		if code, _ := postRenewalInfo(t, srv, renewalInfoBody("a")); code != http.StatusInternalServerError {
			t.Fatalf("status = %d, want 500", code)
		}
	})
	t.Run("malformed body", func(t *testing.T) {
		srv := renewalInfoServer(t, authority.WithRenewalInfo(&renewalInfoStub{}))
		if code, _ := postRenewalInfo(t, srv, `{`); code != http.StatusBadRequest {
			t.Fatalf("status = %d, want 400", code)
		}
	})
}

type eventRecorder struct{ events map[string]int }

func (m *eventRecorder) Handler() http.Handler                             { return http.NotFoundHandler() }
func (m *eventRecorder) ObserveRequest(string, string, int, time.Duration) {}
func (m *eventRecorder) InFlightInc(string)                                {}
func (m *eventRecorder) InFlightDec(string)                                {}
func (m *eventRecorder) IncConnectorEvent(event, outcome string)           { m.events[event+"/"+outcome]++ }

func TestRenewalInfoNilResponseEventFollowsProviderError(t *testing.T) {
	rec := &eventRecorder{events: map[string]int{}}
	h, err := authority.NewHandler(stubProvider{}, authority.WithRenewalInfo(&renewalInfoStub{}))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "ari", Name: "ari", Version: "0.0.1"}),
		shared.WithMetrics(rec),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	if code, _ := postRenewalInfo(t, srv, renewalInfoBody("a")); code != http.StatusInternalServerError {
		t.Fatalf("status = %d, want 500", code)
	}
	if rec.events["renewal_info/ok"] != 1 || rec.events["renewal_info/error"] != 0 {
		t.Errorf("events = %v, want exactly one renewal_info/ok", rec.events)
	}
}
