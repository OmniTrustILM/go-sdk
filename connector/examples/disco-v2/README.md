# Discovery Provider v2 example

Run `go run ./connector/examples/disco-v2` from the SDK repository root.
`ADDR` defaults to `:8080`; `LOG_LEVEL` and `STRICT_DECODE` follow the other
reference examples.

The connector advertises `discovery/v2` with `discoveryStopResume`, uses v2
info/health and common attribute endpoints, and exposes the SDK metrics endpoint.
It discovers three self-signed X.509 certificate fixtures. Requests must replay
the run ID, `resources: ["certificates"]` and the run's checkpoint. This example
defines no run or resource attributes and rejects unsupported ones.

## Delivery modes

Initiate takes the first delivery mode Core offers in `deliveryModes`. A Core
that sends no `deliveryModes` predates delivery modes and gets buffered
delivery. A run keeps the mode it started in.

**Checkpointed.** The connector holds nothing between calls, so a run survives
a restart and any instance can serve its next call. Each results call discovers
the fixtures after `afterSequence`, numbers them from `afterSequence + 1` and
returns the position after them in `checkpoint`, which Core replays on the next
call. Status reports the run from that checkpoint. Stop and resume answer
without a checkpoint, because Core keeps the one it holds. A drain that does not
offer `checkpointed` gets a 503, and one whose `afterSequence` disagrees with
its checkpoint gets a 404.

**Buffered.** Each status poll discovers one certificate into the run's
in-memory buffer; results drains return the buffered items in contiguous
sequence order. Repeat a drain with the same cursor to retrieve the same items,
and send the last sequence received as `afterSequence` to acknowledge them.
Stop keeps the undrained items and returns a checkpoint; resume with it
continues numbering. Cancellation discards the run.

Buffered runs are bounded: at most 64, each kept for 24 hours after it completes
and expired when a new run is initiated. A restart loses the buffers, and later
requests get a 404 rather than skipping missing results. A production provider
needs durable buffering, an explicit recovery strategy or checkpointed delivery.

## Tests

Run its Docker-backed HTTP integration tests with:

```sh
go test -race -v ./connector/examples/disco-v2
```

The shared harness skips container tests under `-short` or when Docker is
unavailable. The store unit tests still run in short mode. If Docker uses a
non-default socket, set `DOCKER_HOST` explicitly. Colima may also need
`TESTCONTAINERS_DOCKER_SOCKET_OVERRIDE=/var/run/docker.sock`. Use a Docker runtime
matching the host architecture, as required by the shared harness.
To put an example binary in the ignored build output folder:

```sh
mkdir -p built-artifacts
go build -o built-artifacts/disco-v2 ./connector/examples/disco-v2
```
