# go-sdk

Go SDK for building ILM / OmniTrust **connectors**.

It provides the two things a connector author would otherwise hand-roll:

- **Contract types** — Go DTOs for every connector interface, generated from the platform's OpenAPI specs (`connector/model/<interface>/<version>`) and patched for correct polymorphic (`oneOf`) JSON round-tripping.
- **Server scaffolding** — `connector/shared` gives you the HTTP server, `/v2/info` + `/v2/health` + metrics, RFC 9457 problem responses, structured `connector.log` logging with W3C trace/correlation context, and a small router. `connector/provider/<interface>/<version>` turns your business logic (a `Provider` interface you implement) into the interface's routes.

Supported provider interfaces: `authority`, `compliance`, `credential`, `cryptography`, `discovery`, `entity`, `notification`, `secret`, plus the connector-global Attributes v2 surface (`attributes`). One connector process can register several.

Requires **Go 1.26+**.

## Install

```sh
go get github.com/OmniTrustILM/go-sdk@vX.Y.Z
```

Pin an explicit released tag (see [Versioning & releases](#versioning--releases)). This records a `require github.com/OmniTrustILM/go-sdk vX.Y.Z` line in your `go.mod`.

## Quickstart

A minimal Secret Provider connector. Implement the interface's `Provider`, wrap it in the interface handler, register it on a `shared.Connector`, and run:

```go
package main

import (
	"context"
	"os/signal"
	"syscall"

	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// store is your connector's backend. It must implement secret.Provider
// (CreateSecret, GetSecretContent, …); those methods are elided here.
type store struct{ /* ... */ }

func main() {
	handler, err := secret.NewHandler(&store{})
	if err != nil {
		panic(err)
	}

	c, err := shared.New(
		shared.WithAddr(":8080"),
		shared.WithInfo(shared.Info{ID: "my-secret-connector", Name: "My Secret Connector", Version: "1.0.0"}),
		shared.Register(handler),
	)
	if err != nil {
		panic(err)
	}

	ctx, stop := signal.NotifyContext(context.Background(), syscall.SIGINT, syscall.SIGTERM)
	defer stop()
	if err := c.Run(ctx); err != nil {
		panic(err)
	}
}
```

This is a skeleton, not a copy-paste-runnable program: it compiles once `store` implements the `secret.Provider` methods — see the runnable [`secret-v1` example](connector/examples/secret-v1) for a complete version. Once it does, the connector serves `/v2/info`, `/v2/health`, and the secret-provider routes under `/v1/secretProvider`.

## Examples

Runnable reference connectors live under [`connector/examples/`](connector/examples) — one per interface, plus `multi-v1` (several interfaces in one process). Each is a real, self-contained connector (in-memory backends; reference-only, not for production):

```sh
go run ./connector/examples/secret-v1
```

`authority-v3`, `legacy-auth-v1` (legacy v1 authority interface), `compliance-v1`/`v2`, `credential-v1`, `cryptography-v1`, `disco-v1`, `entity-v1`, `notification-v1`, `secret-v1`, `multi-v1`. They double as the SDK's integration-test suite (see `connector/examples/internal/itest`).

## Versioning & releases

This is a **Go library**, released the standard Go way — **semantic-version git tags**. There is **no Docker image** (a library is consumed as source by the Go toolchain, not run as a container).

The module follows [semantic versioning](https://semver.org/): `vMAJOR.MINOR.PATCH` (breaking / feature / fix).

**Cutting a release** (maintainers): tag the chosen commit on `main` and push the tag —

```sh
git tag v1.2.0
git push origin v1.2.0
```

That is the entire release: the Go module proxy and `go get` resolve the module at that tag. Publish release notes from the tag on GitHub as desired. (Pre-1.0 the API may change between minor versions per semver's `0.y.z` rule.)

## Consuming a released version

Dependent connectors pin an explicit release in their own `go.mod`:

```
require github.com/OmniTrustILM/go-sdk v1.2.0
```

Add or move to a release with:

```sh
go get github.com/OmniTrustILM/go-sdk@v1.2.0   # pins that exact tag
go mod tidy
```

To upgrade, re-run `go get …@vX.Y.Z` against the newer tag and commit the updated `go.mod`/`go.sum`. Because the pin is an exact tag, builds are reproducible until you deliberately bump it — always pin a released tag rather than tracking a branch or `@latest`.

## License

[MIT](LICENSE) — © Identity Lifecycle Management (ILM).
