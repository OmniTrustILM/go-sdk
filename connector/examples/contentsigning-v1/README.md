# Content Signing Formatting Provider v1 example

Run `go run ./connector/examples/contentsigning-v1` from the SDK repository root;
`main.go`'s package doc lists the environment variables.

The connector advertises `contentSigningFormatting/v1` with v2 info and health
endpoints and the SDK metrics endpoint. It serves one signature family, `demo`,
at the `signed` level, with `inline` document transfer and no restriction on the
signature algorithm.

The family has no real format. It declares one profile attribute of
`computeDtbs`, `prefix` (a required string), accepts the signature algorithm
`SHA256withRSA` only, and works as follows:

- `computeDtbs` returns the prefix bytes followed by the SHA-256 of the document
  as `dtbs`, the SHA-256 as `documentDigest`, and the same `dtbs` as the
  formatting context.
- `embedSignatureValue` returns the formatting context followed by the signature
  value, as `application/octet-stream`.

Operations above the signed level, such as `extendToLevel`, are answered with
422 `PARAMETER_UNSUPPORTED`.

## Tests

Run its Docker-backed HTTP integration tests with:

```sh
go test -race -v ./connector/examples/contentsigning-v1
```

Container tests use the shared harness; see
[internal/itest](../internal/itest/README.md) for its Docker requirements. The
formatter unit tests also run under `-short`.
