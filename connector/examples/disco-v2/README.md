# Discovery Provider v2 example

Run `go run ./connector/examples/disco-v2` from the SDK repository root.
`ADDR` defaults to `:8080`; `LOG_LEVEL` and `STRICT_DECODE` follow the other
reference examples.

The connector advertises `discovery/v2` with `discoveryStopResume`, uses v2
info/health and common attribute endpoints, and exposes the SDK metrics endpoint.
It discovers three self-signed X.509 certificate fixtures. Each status poll
produces one certificate; results drains return the produced items in contiguous
sequence order. Repeat a drain with the same cursor to retrieve the same items.
Send the last sequence received as `afterSequence` to acknowledge those items.

Stop preserves the undrained items and returns a checkpoint. Resume with that
checkpoint continues numbering. Cancellation discards the run. Requests must
replay the run ID, `resources: ["certificates"]`, and the returned checkpoint.
This example defines no run or resource attributes and rejects unsupported ones.

This is a bounded in-memory demonstration, not a production scanner: at most 64
runs with three certificate fixtures each. Completed runs remain available for
24 hours and expire when a new run is initiated. Restart loses the buffers;
subsequent requests return 404 rather than skipping missing results. A production
provider needs durable buffering or an explicit recovery strategy.

Run its Docker-backed HTTP integration tests with:

```sh
go test -race -v ./connector/examples/disco-v2
```

The shared harness skips container tests under `-short` or when Docker is
unavailable. The store lifecycle unit tests still run in short mode. If Docker
uses a non-default socket, set `DOCKER_HOST` explicitly. Colima may also need
`TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`. Use a Docker runtime
matching the host architecture, as required by the shared harness.
To put an example binary in the ignored build output folder:

```sh
mkdir -p built-artifacts
go build -o built-artifacts/disco-v2 ./connector/examples/disco-v2
```
