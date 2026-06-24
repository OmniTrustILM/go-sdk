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
- `Response.JSON(t, dst)`, `itest.AssertStatus(t, resp, want)`.
- `Harness.AssertHealthy(t, path)` — health body conformance per spec version.
- `Harness.Logs() string`, `Harness.LogLines(t)`, `Harness.AssertLogsConform(t)` —
  connector.log v1 envelope + trace-or-correlation invariant.
- `itest.RequireDocker(t)` — the skip gate (called by `Start`).

## Running

```sh
# Full integration suite (needs a reachable Docker/Podman daemon):
go test ./connector/examples/...

# Skip containers (unit-only, fast, Docker-less):
go test -short ./...
```

## How an example becomes a container

The example is compiled on the host (`CGO_ENABLED=0`, daemon platform — the
examples are pure Go) and testcontainers builds a minimal `scratch` image
around the prebuilt static binary. This avoids depending on a matching
`golang` base-image tag, reuses the host build cache, and keeps the per-image
build to a tar + `COPY` of one binary. Assumes a local Docker/Podman daemon
(same architecture as the host).
