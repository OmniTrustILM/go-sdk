// Package itest is the shared integration-test harness for the connector
// example services under connector/examples/. It builds an example into a
// container and runs it as a black box, so an example's tests can drive the
// real compiled connector over its public HTTP interface — the same path a
// CZERTAINLY/OmniTrust core takes — and catch any drift between the OpenAPI
// spec, the generated models, and the shared/provider runtime.
//
// It is an internal package: only the example test packages import it.
//
// # Usage
//
//	func TestSecretLifecycle(t *testing.T) {
//	    h := itest.Start(t, itest.Example{
//	        Path: "connector/examples/secret-v1",
//	        Env:  map[string]string{"APP_USERNAME": "u", "APP_PASSWORD": "p"},
//	    })
//	    var body map[string]any
//	    status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &body)
//	    // assert on status / body ...
//	}
//
// Start handles build, container start, readiness wait, and teardown
// transparently; the caller never touches the container lifecycle. When
// Docker is unavailable (or -short is set) Start skips the test rather than
// failing it, so plain `go test -short ./...` and Docker-less CI stay green.
//
// # How an example becomes a container
//
// The example is compiled on the host with CGO disabled, for linux (the
// scratch image is always linux) on the host architecture (the example
// services are pure Go), then testcontainers builds a minimal scratch image
// around the prebuilt static binary. This avoids depending on a matching
// golang base-image tag and reuses the host build cache, so the per-example
// image build is a tar + COPY of one binary. It assumes a local
// Docker/Podman daemon, whose architecture therefore matches the host's.
package itest

import (
	"bytes"
	"context"
	"go/build"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
	"github.com/testcontainers/testcontainers-go/wait"
)

// containerPort is the port every example binary listens on inside its
// container. Examples default their listen address to ":8080"; the harness
// does not override it, so this stays fixed.
const containerPort = "8080"

// defaultStartupTimeout bounds the host `go build` and the container
// start/readiness wait for one example. (The intermediate docker image
// build is bounded by testcontainers' own build handling, not this value.)
const defaultStartupTimeout = 90 * time.Second

// Example describes one connector example to run as a container.
type Example struct {
	// Path is the example's package path relative to the repo root,
	// e.g. "connector/examples/secret-v1". Required.
	Path string

	// Env is passed to the container as environment variables. Use it for
	// the example's APP_* / bare config knobs (credentials, kinds, ...).
	// The listen address is intentionally not settable here — the harness
	// fixes the in-container port.
	Env map[string]string

	// HealthPath is polled for HTTP 200 to decide readiness. Defaults to
	// "/v2/health"; v1-family examples should set "/v1/health".
	HealthPath string

	// StartupTimeout overrides defaultStartupTimeout when non-zero.
	StartupTimeout time.Duration
}

// Harness is a running example container plus helpers to drive it. Obtain
// one from Start; it tears itself down via t.Cleanup.
type Harness struct {
	// BaseURL is the http://host:port origin of the running example,
	// reachable from the test process. No trailing slash.
	BaseURL string

	ctr    testcontainers.Container
	client *http.Client
	logs   *logConsumer
}

// Start builds the example, runs it in a container, waits until its health
// endpoint returns 200, and registers teardown — all transparently. It skips
// the test (never fails it) when Docker is unavailable or -short is set.
//
// The returned Harness is ready to receive requests at BaseURL.
func Start(t *testing.T, ex Example) *Harness {
	t.Helper()
	RequireDocker(t)

	if ex.Path == "" {
		t.Fatal("itest: Example.Path is required")
	}
	healthPath := ex.HealthPath
	if healthPath == "" {
		healthPath = "/v2/health"
	}
	timeout := ex.StartupTimeout
	if timeout == 0 {
		timeout = defaultStartupTimeout
	}

	ctx := context.Background()
	buildCtx := buildExampleImageContext(t, ex.Path, timeout)

	consumer := &logConsumer{}
	ctr, err := testcontainers.Run(ctx, "",
		testcontainers.WithDockerfile(testcontainers.FromDockerfile{
			Context:       buildCtx,
			Dockerfile:    "Dockerfile",
			PrintBuildLog: false,
			KeepImage:     false,
		}),
		testcontainers.WithEnv(ex.Env),
		testcontainers.WithExposedPorts(containerPort+"/tcp"),
		testcontainers.WithLogConsumers(consumer),
		testcontainers.WithWaitStrategyAndDeadline(timeout,
			wait.ForHTTP(healthPath).
				WithPort(containerPort+"/tcp").
				WithStatusCodeMatcher(func(status int) bool { return status == http.StatusOK }).
				WithStartupTimeout(timeout),
		),
	)
	// Register teardown before checking the error: CleanupContainer is nil-safe
	// and also surfaces container logs on a failed start.
	testcontainers.CleanupContainer(t, ctr)
	if err != nil {
		t.Fatalf("itest: start %s: %v\n--- container logs ---\n%s", ex.Path, err, consumer.String())
	}

	endpoint, err := ctr.PortEndpoint(ctx, containerPort+"/tcp", "http")
	if err != nil {
		t.Fatalf("itest: resolve endpoint for %s: %v", ex.Path, err)
	}

	return &Harness{
		BaseURL: strings.TrimRight(endpoint, "/"),
		ctr:     ctr,
		client:  &http.Client{Timeout: 30 * time.Second},
		logs:    consumer,
	}
}

// Logs returns everything the container has written to stdout/stderr so far.
// Use it to assert the connector.log v1 envelope and trace fields.
func (h *Harness) Logs() string { return h.logs.String() }

// --- host build + image context --------------------------------------------

// Build caches and locks. buildMu is held only for the brief map
// lookups/inserts below — never across a `go build` — so distinct examples
// compile concurrently while builds for the same example dedupe via a
// per-path lock.
var (
	buildMu    sync.Mutex                 // guards builtPaths and buildLocks
	builtPaths = map[string]string{}      // example path (as given) -> build-context dir
	buildLocks = map[string]*sync.Mutex{} // example path (as given) -> per-path build lock
)

// buildExampleImageContext compiles the example into a fresh temp dir and
// drops a minimal Dockerfile next to the binary. The temp dir is the Docker
// build context: testcontainers tars it (just the binary + Dockerfile) and
// builds a scratch image. Returns the context directory path.
//
// The binary is built for linux — the FROM scratch image is always linux,
// regardless of the host OS — using the host architecture. That matches the
// harness's documented assumption of a local Docker/Podman daemon (so the
// daemon's arch equals the host's, including Apple Silicon). timeout bounds
// the build.
func buildExampleImageContext(t *testing.T, examplePath string, timeout time.Duration) string {
	t.Helper()
	root := repoRoot(t)
	pkgDir := filepath.Join(root, filepath.FromSlash(examplePath))
	if _, err := os.Stat(pkgDir); err != nil {
		t.Fatalf("itest: example path %q not found at %s: %v", examplePath, pkgDir, err)
	}

	// Acquire (or create) the per-path build lock without holding buildMu
	// across the build itself, and fast-path an already-built context.
	buildMu.Lock()
	if dir, ok := builtPaths[examplePath]; ok {
		buildMu.Unlock()
		return dir
	}
	pathLock, ok := buildLocks[examplePath]
	if !ok {
		pathLock = &sync.Mutex{}
		buildLocks[examplePath] = pathLock
	}
	buildMu.Unlock()

	pathLock.Lock()
	defer pathLock.Unlock()

	// Re-check under the per-path lock: a concurrent builder of the same
	// example may have finished while we waited.
	buildMu.Lock()
	if dir, ok := builtPaths[examplePath]; ok {
		buildMu.Unlock()
		return dir
	}
	buildMu.Unlock()

	// Process-lifetime temp dir (not t.TempDir): the context is cached and
	// reused across tests that share this example, so it must outlive the
	// first test's cleanup. It holds only one small binary + a Dockerfile;
	// the OS reclaims it when the test binary exits.
	dir, err := os.MkdirTemp("", "itest-"+sanitize(examplePath)+"-")
	if err != nil {
		t.Fatalf("itest: temp dir: %v", err)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	binPath := filepath.Join(dir, "connector")
	cmd := exec.CommandContext(ctx, goToolPath(t), "build", "-trimpath", "-o", binPath, "./"+examplePath)
	cmd.Dir = root
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux", // the FROM scratch image is always linux, whatever the host
		"GOARCH="+runtime.GOARCH,
	)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("itest: build %s: %v\n%s", examplePath, err, stderr.String())
	}

	dockerfile := "FROM scratch\n" +
		"COPY connector /connector\n" +
		"EXPOSE " + containerPort + "\n" +
		`ENTRYPOINT ["/connector"]` + "\n"
	if err := os.WriteFile(filepath.Join(dir, "Dockerfile"), []byte(dockerfile), 0o644); err != nil {
		t.Fatalf("itest: write Dockerfile: %v", err)
	}

	buildMu.Lock()
	builtPaths[examplePath] = dir
	buildMu.Unlock()
	return dir
}

// goToolPath returns the absolute path of the Go toolchain that built the
// test binary: $GOROOT/bin/go. It deliberately does NOT search $PATH — a
// writable directory on PATH could shadow the real `go` with a planted
// binary that then runs during the build (sonar go:S4036). build.Default.GOROOT
// is the toolchain root resolved at init from GOROOT/the running toolchain,
// a fixed, unwriteable location.
func goToolPath(t *testing.T) string {
	t.Helper()
	goroot := build.Default.GOROOT
	if goroot == "" {
		t.Fatal("itest: GOROOT is empty; cannot locate the go toolchain without searching PATH")
	}
	name := "go"
	if runtime.GOOS == "windows" {
		name = "go.exe"
	}
	p := filepath.Join(goroot, "bin", name)
	if _, err := os.Stat(p); err != nil {
		t.Fatalf("itest: go toolchain not found at %s: %v", p, err)
	}
	return p
}

// repoRoot walks up from this source file to the directory containing go.mod.
func repoRoot(t *testing.T) string {
	t.Helper()
	_, thisFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("itest: runtime.Caller failed")
	}
	dir := filepath.Dir(thisFile)
	for {
		if _, err := os.Stat(filepath.Join(dir, "go.mod")); err == nil {
			return dir
		}
		parent := filepath.Dir(dir)
		if parent == dir {
			t.Fatal("itest: go.mod not found walking up from " + thisFile)
		}
		dir = parent
	}
}

// sanitize makes an example path safe for a temp-dir name component.
func sanitize(s string) string {
	return strings.NewReplacer("/", "-", "\\", "-", " ", "_").Replace(s)
}
