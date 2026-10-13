package itest

import (
	"net/http"
	"slices"
	"testing"
)

// Helpers over the examples' generated model types. Every interface's model
// package generates its own InfoResponse/EndpointDto/HealthDto, so these are
// generic over the openapi-generator getters (which live on the pointer
// receiver: the P type parameters below are *E / *H, inferred by the compiler)
// rather than over one concrete type. The caller still decodes through its own
// generated model — that decode is part of the drift detection.

// Endpoint is one advertised endpoint of a /v1 listSupportedFunctions function
// group, independent of the model package that decoded it.
type Endpoint struct {
	Name     string // the spec operationId
	Method   string
	Context  string // path template as advertised, e.g. /v1/x/{kind}/attributes
	Required bool   // the SDK marks no endpoint required; a change must be deliberate
}

// endpointDto is the pointer side of a generated EndpointDto.
type endpointDto[E any] interface {
	*E
	GetName() string
	GetMethod() string
	GetContext() string
	GetRequired() bool
}

// AssertEndpoints fails unless got (a function group's EndPoints, decoded
// through the caller's generated InfoResponse) advertises exactly want: every
// want entry matched on all four fields, once, and nothing else. A renamed
// operation, context or method therefore reports both the missing entry and
// the unexpected one. group names the function group in messages.
//
//	itest.AssertEndpoints(t, fg, g.EndPoints, []itest.Endpoint{
//		{Name: "checkHealth", Method: http.MethodGet, Context: "/v1/health"},
//	})
func AssertEndpoints[E any, P endpointDto[E]](t *testing.T, group string, got []E, want []Endpoint) {
	t.Helper()
	unexpected := make([]Endpoint, 0, len(got))
	for i := range got {
		e := P(&got[i])
		unexpected = append(unexpected, Endpoint{e.GetName(), e.GetMethod(), e.GetContext(), e.GetRequired()})
	}
	for _, w := range want {
		i := slices.Index(unexpected, w)
		if i < 0 {
			t.Errorf("%s endPoints missing %+v", group, w)
			continue
		}
		unexpected = slices.Delete(unexpected, i, i+1)
	}
	for _, u := range unexpected {
		t.Errorf("%s endPoints has unexpected %+v", group, u)
	}
}

// healthDto is the pointer side of a generated v1 HealthDto; S is the same
// package's HealthStatus.
type healthDto[H any, S ~string] interface {
	*H
	GetStatus() S
	GetParts() map[string]H
}

// AssertV1HealthDto fetches GET /v1/health and decodes it through the
// caller's generated HealthDto H (S is that package's HealthStatus), so the
// checkHealth schema's status enum and nested parts go through the model
// decoder, then requires status "ok" with liveness and readiness parts "ok".
// It is the typed counterpart of AssertHealthy's v1 branch. H and S cannot be
// inferred, so pass them explicitly. Returns the decoded body.
//
//	itest.AssertV1HealthDto[mdl.HealthDto, mdl.HealthStatus](t, h)
func AssertV1HealthDto[H any, S ~string, P healthDto[H, S]](t *testing.T, h *Harness) H {
	t.Helper()
	var health H
	resp := h.Do(t, Request{Method: http.MethodGet, Path: "/v1/health"})
	if !AssertStatus(t, resp, http.StatusOK) {
		return health
	}
	resp.JSON(t, &health)
	if st := P(&health).GetStatus(); st != "ok" {
		t.Errorf("HealthDto status = %q, want ok\nbody: %s", st, resp.Body)
	}
	parts := P(&health).GetParts()
	for _, name := range []string{"liveness", "readiness"} {
		part := parts[name] // zero value (status "") when absent
		if st := P(&part).GetStatus(); st != "ok" {
			t.Errorf("HealthDto parts.%s.status = %q, want ok\nbody: %s", name, st, resp.Body)
		}
	}
	return health
}

// Find returns the first item whose key equals want, and whether there is
// one. Use it for lists whose order is an implementation detail (search by
// uuid/name, never index):
//
//	rule, ok := itest.Find(rules, ruleUUID, rule1UUID)
func Find[T any, K comparable](items []T, key func(T) K, want K) (T, bool) {
	i := slices.IndexFunc(items, func(it T) bool { return key(it) == want })
	if i < 0 {
		var zero T
		return zero, false
	}
	return items[i], true
}
