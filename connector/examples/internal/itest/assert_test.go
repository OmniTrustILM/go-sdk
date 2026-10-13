package itest

import (
	"testing"
	"time"

	"github.com/testcontainers/testcontainers-go"
)

// TestAssertLoggedPartialLine pins AssertLogged's incremental parsing without
// Docker: a line that arrives in two chunks is only parsed once its newline
// lands, and a line already consumed by an earlier poll is still matched.
func TestAssertLoggedPartialLine(t *testing.T) {
	const (
		envelope = `{"schema":{"name":"connector.log","version":1},`
		first    = envelope + `"message":"m","attributes":{"n":1}}` + "\n"
		second   = envelope + `"message":"m","attributes":{"n":2}}` + "\n"
	)
	logs := &logConsumer{}
	h := &Harness{logs: logs}

	// The first line and half of the second are present before the first
	// poll; the rest of the second line arrives a few polls later.
	logs.Accept(testcontainers.Log{Content: []byte(first + second[:20])})
	go func() {
		time.Sleep(200 * time.Millisecond)
		logs.Accept(testcontainers.Log{Content: []byte(second[20:])})
	}()

	if l := h.AssertLogged(t, "m", map[string]any{"n": 2}); l == nil {
		t.Fatal("split line not matched once complete")
	}
	if l := h.AssertLogged(t, "m", map[string]any{"n": 1}); l == nil {
		t.Fatal("earlier line not matched")
	}
}
