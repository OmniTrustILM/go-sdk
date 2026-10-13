# itest — integration-test harness for the connector examples

Shared harness ([#23](https://github.com/OmniTrustILM/go-sdk/issues/23), parent [#15](https://github.com/OmniTrustILM/go-sdk/issues/15))
that runs an example connector as a real container and drives it over its
public HTTP interface. Each example's integration tests import this package;
they never touch the container lifecycle.

## Why

The examples mimic real connectors in every way, so running them as black
boxes catches drift between the three layers that must stay aligned — the
OpenAPI **spec**, the **generated models**, and the **shared/provider
runtime** — before it reaches a connector author or the core.

## Usage

```go
package secretv1_test

import (
	"net/http"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
)

func TestSecretLifecycle(t *testing.T) {
	h := itest.Start(t, itest.Example{
		Path: "connector/examples/secret-v1",       // package path from repo root
		Env:  map[string]string{"APP_USERNAME": "u", "APP_PASSWORD": "p"},
		// HealthPath defaults to "/v2/health"; v1-family examples set "/v1/health".
		// The v1-family examples are cryptography-v1, disco-v1, entity-v1,
		// legacy-auth-v1, multi-v1, notification-v1, compliance-v1,
		// compliance-v2 and credential-v1.
	})

	// Health body conformance (mandatory liveness/readiness on /v2/health).
	h.AssertHealthy(t, "/v2/health")

	// Drive the public API.
	resp := h.Do(t, itest.Request{
		Method: http.MethodPost,
		Path:   "/v1/secretProvider/secrets",
		Body:   map[string]any{"name": "alpha" /* ... */},
	})
	itest.AssertStatus(t, resp, http.StatusCreated)

	var out map[string]any
	resp.JSON(t, &out)
	// ... assert on out ...

	// Logging/tracing contract on the container's own output.
	h.AssertLogsConform(t)
}
```

`Start` builds the example, runs it in a container, waits for health 200, and
registers teardown — transparently. It **skips** (never fails) when Docker is
unavailable or under `-short`.

## API

- `Start(t, Example) *Harness` — build + run + wait + auto-teardown.
- `Example{Path, Env, HealthPath, StartupTimeout}`.
- `Harness.BaseURL` — origin reachable from the test process.
- `Harness.Do(t, Request) Response` / `Harness.GetJSON(t, method, path, body, dst) int`.
- `Response.JSON(t, dst)` — decodes the body; fails unless the Content-Type is
  `application/json` or a `+json` type (e.g. `application/problem+json`).
- `itest.AssertStatus(t, resp, want)`.
- `Request.RawBody` — verbatim body for malformed-JSON cases.
- `itest.AssertV1Error(t, resp, want) string`, `itest.AssertV1MessageEnvelope(t, resp, want) string`,
  `itest.AssertV1ValidationErrors(t, resp) []string` — the v1-family error shapes
  (the envelope and the 422 array both require exactly `application/json`).
- `Harness.AssertHealthy(t, path)` — health body conformance per spec version:
  v2 status `UP` + mandatory components; v1 status `ok` + `parts.liveness` and
  `parts.readiness` status `ok`.
- `itest.AssertV1HealthDto[H, S](t, h) H` — the v1 health body decoded through the caller's
  generated `HealthDto` (`S` its `HealthStatus`): status `ok`, liveness/readiness parts `ok`.
- `Harness.AssertNotServed(t, paths...)` — each GET is the mux's own non-JSON 404 (route not mounted).
- `itest.AssertEndpoints(t, group, got, want []itest.Endpoint)` — a function group's generated
  `EndPoints` advertise exactly `want`, matched on name/method/context/required.
- `itest.Find(items, key, want) (T, bool)` — first item whose key equals `want` (order-free lookup).
- `Harness.Logs() string`, `Harness.LogLines(t)`, `Harness.AssertLogsConform(t)` —
  connector.log v1 envelope + trace-or-correlation invariant.
- `Harness.AssertLogged(t, message, want) LogLine` — polling lookup of one connector.log line
  (parses only lines added since the previous poll);
  each `want` key matches a top-level field (e.g. `correlation_id`) first, else one inside
  `attributes`, compared as JSON values (a Go `404` matches the number, not the string `"404"`).
- `Harness.AssertMetric(t, series) string` — Prometheus series presence on `/v1/metrics`
  (prefix match: include the closing `}` unless a prefix is intended).
- `itest.RequireDocker(t)` — the skip gate (called by `Start`).

## Running

```sh
# Full integration suite (needs a reachable Docker/Podman daemon):
go test ./connector/examples/...

# Skip containers (unit-only, fast, Docker-less):
go test -short ./...
```

## How an example becomes a container

The example is compiled on the host (`CGO_ENABLED=0`, `GOOS=linux` — the
`scratch` image is always linux — on the host architecture; the examples are
pure Go) and testcontainers builds a minimal `scratch` image around the
prebuilt static binary. This avoids depending on a matching `golang`
base-image tag, reuses the host build cache, and keeps the per-image build to
a tar + `COPY` of one binary. Assumes a local Docker/Podman daemon, whose
architecture therefore matches the host's (including Apple Silicon →
linux/arm64 containers).
