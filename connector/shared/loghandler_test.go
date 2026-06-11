package shared

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"log/slog"
	"math"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"
)

// decodeLine parses the single JSON log line written to buf.
func decodeLine(t *testing.T, buf *bytes.Buffer) map[string]any {
	t.Helper()
	line := strings.TrimSpace(buf.String())
	if line == "" {
		t.Fatal("no log line written")
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(line), &m); err != nil {
		t.Fatalf("log line is not JSON: %v\n%s", err, line)
	}
	return m
}

func TestLogHandlerEnvelope(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{
		ServiceName:    "test-connector",
		ServiceVersion: "9.9.9",
	}))

	logger.Info("hello world", "foo", "bar", "n", 42)
	m := decodeLine(t, &buf)

	schema, ok := m["schema"].(map[string]any)
	if !ok || schema["name"] != "connector.log" || schema["version"] != float64(1) {
		t.Errorf("schema = %v, want {name: connector.log, version: 1}", m["schema"])
	}
	tsRaw, _ := m["@timestamp"].(string)
	if _, err := time.Parse(time.RFC3339Nano, tsRaw); err != nil {
		t.Errorf("@timestamp %q is not RFC 3339: %v", tsRaw, err)
	}
	if m["severity"] != "INFO" {
		t.Errorf("severity = %v, want INFO", m["severity"])
	}
	if m["message"] != "hello world" {
		t.Errorf("message = %v", m["message"])
	}
	svc, _ := m["service"].(map[string]any)
	if svc["name"] != "test-connector" || svc["version"] != "9.9.9" {
		t.Errorf("service = %v", m["service"])
	}
	attrs, _ := m["attributes"].(map[string]any)
	if attrs["foo"] != "bar" || attrs["n"] != float64(42) {
		t.Errorf("attributes = %v", m["attributes"])
	}
	// No request context: the trace-or-correlation invariant must hold via
	// the fallback correlation id.
	if m["correlation_id"] == nil || m["correlation_id"] == "" {
		t.Error("correlation_id missing on un-traced record (invariant violated)")
	}
	if m["trace_id"] != nil {
		t.Errorf("unexpected trace_id %v on un-traced record", m["trace_id"])
	}
}

func TestLogHandlerSeverityMapping(t *testing.T) {
	cases := []struct {
		level slog.Level
		want  string
	}{
		{slog.LevelDebug - 4, "TRACE"},
		{slog.LevelDebug, "DEBUG"},
		{slog.LevelInfo, "INFO"},
		{slog.LevelWarn, "WARN"},
		{slog.LevelError, "ERROR"},
		{slog.LevelError + 4, "FATAL"},
	}
	for _, tc := range cases {
		if got := severity(tc.level); got != tc.want {
			t.Errorf("severity(%v) = %q, want %q", tc.level, got, tc.want)
		}
	}
}

func TestLogHandlerTraceFromContext(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))

	tid, _ := trace.TraceIDFromHex("0123456789abcdef0123456789abcdef")
	sid, _ := trace.SpanIDFromHex("0123456789abcdef")
	sc := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: tid, SpanID: sid, TraceFlags: trace.FlagsSampled,
	})
	ctx := trace.ContextWithSpanContext(context.Background(), sc)
	ctx = context.WithValue(ctx, ctxKeyCorrelationID, "corr-123")

	logger.InfoContext(ctx, "traced")
	m := decodeLine(t, &buf)

	if m["trace_id"] != "0123456789abcdef0123456789abcdef" {
		t.Errorf("trace_id = %v", m["trace_id"])
	}
	if m["span_id"] != "0123456789abcdef" {
		t.Errorf("span_id = %v", m["span_id"])
	}
	if m["trace_flags"] != "01" {
		t.Errorf("trace_flags = %v, want 01", m["trace_flags"])
	}
	if m["correlation_id"] != "corr-123" {
		t.Errorf("correlation_id = %v, want corr-123", m["correlation_id"])
	}
}

func TestLogHandlerPromotesBoundTraceAttrs(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))

	// The middleware binds these via With; even context-free calls must
	// surface them as top-level envelope fields, not inside attributes.
	bound := logger.With(
		"trace_id", "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa",
		"span_id", "bbbbbbbbbbbbbbbb",
		"trace_flags", "01",
		"correlation_id", "corr-x",
		"method", "POST",
	)
	bound.Info("via with")
	m := decodeLine(t, &buf)

	if m["trace_id"] != "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa" {
		t.Errorf("trace_id = %v (promotion from With failed)", m["trace_id"])
	}
	if m["span_id"] != "bbbbbbbbbbbbbbbb" {
		t.Errorf("span_id = %v", m["span_id"])
	}
	if m["correlation_id"] != "corr-x" {
		t.Errorf("correlation_id = %v", m["correlation_id"])
	}
	attrs, _ := m["attributes"].(map[string]any)
	if attrs["method"] != "POST" {
		t.Errorf("attributes.method = %v", attrs["method"])
	}
	if _, leaked := attrs["trace_id"]; leaked {
		t.Error("trace_id leaked into attributes instead of being promoted")
	}
}

func TestLogHandlerGroups(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))

	logger.WithGroup("req").With("verb", "GET").Info("grouped", "code", 200)
	m := decodeLine(t, &buf)

	attrs, _ := m["attributes"].(map[string]any)
	req, _ := attrs["req"].(map[string]any)
	if req == nil || req["verb"] != "GET" || req["code"] != float64(200) {
		t.Errorf("attributes = %v, want req group with verb+code", attrs)
	}
}

// TestLogHandlerNeverDropsRecords guards against silent whole-record loss:
// one unmarshalable attribute value (NaN, a channel, an error type that
// json.Marshal chokes on) must never fail the envelope Marshal — slog
// discards Handle errors, so a failed Marshal means the line (message and
// all) vanishes without trace. Found by adversarial review; the SDK's own
// "panic in handler" diagnostics were affected.
func TestLogHandlerNeverDropsRecords(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))

	type chanErr struct{ C chan int }
	cases := []struct {
		name  string
		value any
	}{
		{"nan", math.NaN()},
		{"inf", math.Inf(1)},
		{"channel", make(chan int)},
		{"unmarshalable struct", chanErr{C: make(chan int)}},
	}
	for _, tc := range cases {
		buf.Reset()
		logger.Info("must survive", "bad", tc.value)
		m := decodeLine(t, &buf)
		if m["message"] != "must survive" {
			t.Errorf("%s: record lost or corrupted: %v", tc.name, m)
		}
		attrs, _ := m["attributes"].(map[string]any)
		bad, _ := attrs["bad"].(string)
		if !strings.HasPrefix(bad, "!ERROR:") {
			t.Errorf("%s: attributes.bad = %v, want !ERROR: marker", tc.name, attrs["bad"])
		}
	}
}

// TestLogHandlerRendersErrorValues pins error attrs to their Error() text;
// json.Marshal renders most error types as {} which loses the message.
func TestLogHandlerRendersErrorValues(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{ServiceName: "t"}))

	logger.Error("operation failed", "err", errors.New("backend exploded"))
	m := decodeLine(t, &buf)
	attrs, _ := m["attributes"].(map[string]any)
	if attrs["err"] != "backend exploded" {
		t.Errorf("attributes.err = %v, want the Error() string", attrs["err"])
	}
}

func TestLogHandlerLevelFilter(t *testing.T) {
	var buf bytes.Buffer
	logger := slog.New(NewLogHandler(&buf, &LogHandlerOptions{
		ServiceName: "t",
		Level:       slog.LevelWarn,
	}))
	logger.Info("dropped")
	if buf.Len() != 0 {
		t.Errorf("info record not filtered at warn level: %s", buf.String())
	}
	logger.Warn("kept")
	if buf.Len() == 0 {
		t.Error("warn record filtered out")
	}
}
