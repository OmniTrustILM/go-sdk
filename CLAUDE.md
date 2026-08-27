# CLAUDE.md

Guidance for agents working in this repository.

## What this is

The Go SDK for building ILM platform connectors: a shared HTTP server
framework plus, per connector interface and version, a provider handler
package (hand-written) and a model package (generated from the OpenAPI
specs). Org connectors (e.g. `dlm-connector`, `otpki-connector`) consume
this module, so its exported API is a compatibility surface.

## Repo map

| Path                              | Purpose                                                                     |
|-----------------------------------|-----------------------------------------------------------------------------|
| `connector/shared`                | The server framework: router and route helpers, request codec and body limits, health/info endpoints, structured log handler, metrics, tracing, correlation, RFC 9457 problem rendering (`problem.go`, `v1errors.go`), middleware. |
| `connector/provider/<iface>/<vN>` | Hand-written provider handler packages, one per connector interface and version. Each defines the Provider interface a connector implements and mounts its routes. |
| `connector/model/<iface>/<vN>`    | **Generated** DTO packages — produced by `gen.sh` from `connector/spec`, then post-processed by `tools/fixoneof`. Never hand-edit (see Conventions). |
| `connector/spec`                  | The OpenAPI specifications the model packages are generated from.           |
| `connector/examples`              | Runnable example connectors per interface plus `internal/itest`, a testcontainers harness their integration tests use (Docker required). |
| `tools/fixoneof`                  | Post-generation fixup: replaces the generator's broken oneOf UnmarshalJSON with discriminator-aware decoders. |
| `gen.sh`                          | Regenerates every model package (runs the openapi-generator Docker image, then `tools/fixoneof`). |

## Commands

- Build: `go build ./...`
- Tests: `go test -race ./...` (includes the examples' testcontainers
  integration tests, so Docker must be running)
- Format check: `gofmt -l . | grep -v '^connector/model/'` (no output means
  clean — generated model code is exempt, see Conventions)
- Vulnerability scan: `go tool govulncheck ./...` (version pinned via the
  go.mod tool directive)
- Regenerate models: `./gen.sh` (Docker required); commit spec and generated
  changes together

Run every command above from the repo root before considering a change done.

## Conventions

- `connector/model/**` is generated code. Never hand-edit it: change the
  spec in `connector/spec` and rerun `gen.sh`. It is exempt from the gofmt
  gate (the generator's output is not gofmt-clean) and excluded from
  SonarCloud analysis (`sonar-project.properties`).
- The exported API of `connector/shared` and every `connector/provider`
  package is consumed by org connectors. Do not make breaking changes
  (signature changes, removed exports, changed defaults) without
  coordinating a migration across consumers; prefer additive evolution.
- Every third-party GitHub Action reference is pinned to a full commit SHA
  with the human-readable version as a trailing comment, e.g.
  `owner/action@<full-sha> # vX.Y.Z`. Org-internal `OmniTrustILM/.github`
  reusable workflows are the deliberate exception (org release tags or
  `@main`).
- Commit messages are one plain, descriptive line. No co-author trailers and
  no mention of AI assistance or tooling.

## Quality gates

A change is not done until all of these pass:

- **SonarCloud** — quality gate must pass (coverage on new code, duplication,
  zero new issues). The PR analysis chain is `Check PR` →
  `Dispatch Sonar` → `Sonar` (fork-safe, quality gate blocking); `Sonar Main`
  maintains the main-branch baseline on push.
- **CodeQL** (`codeql.yml`) — `go` and `actions` analysis, no new findings.
- **govulncheck** — no known vulnerabilities in the module or its
  dependencies.
- **Dependency review** — no newly introduced dependency with a `high`+
  severity advisory.
