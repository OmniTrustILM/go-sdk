package itest

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// logConsumer is a testcontainers.LogConsumer that accumulates the
// container's stdout/stderr so tests can assert on emitted log lines.
type logConsumer struct {
	mu  sync.Mutex
	buf strings.Builder
}

func (c *logConsumer) Accept(l testcontainers.Log) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.buf.Write(l.Content)
}

func (c *logConsumer) String() string {
	c.mu.Lock()
	defer c.mu.Unlock()
	return c.buf.String()
}

// dockerOnce caches the Docker-availability probe for the whole test binary
// so every Start does not re-dial the daemon.
var (
	dockerOnce sync.Once
	dockerOK   bool
)

// RequireDocker skips the test when the integration suite cannot or should
// not run: under -short, or when no Docker daemon is reachable. It never
// fails — Docker-less and short runs stay green. Start calls it; tests may
// also call it directly before any non-harness Docker work.
func RequireDocker(t *testing.T) {
	t.Helper()
	if testing.Short() {
		t.Skip("itest: skipping integration test in -short mode")
	}
	dockerOnce.Do(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Second)
		defer cancel()
		provider, err := testcontainers.NewDockerProvider()
		if err != nil {
			return
		}
		defer func() { _ = provider.Close() }()
		if err := provider.Health(ctx); err != nil {
			return
		}
		dockerOK = true
	})
	if !dockerOK {
		t.Skip("itest: skipping — no reachable Docker daemon")
	}
}
