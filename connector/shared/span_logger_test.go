package shared

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"testing"

	"go.opentelemetry.io/contrib/instrumentation/net/http/otelhttp"
	"go.opentelemetry.io/otel/propagation"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

// TestRequestLogCarriesTracerMiddlewareSpan installs otelhttp through
// WithMiddleware, as connectors do, and checks that the handler's
// context-free log record and the "request completed" line carry the ids of
// the server span otelhttp recorded, with and without an inbound traceparent,
// and when a later middleware answers without calling the handler.
func TestRequestLogCarriesTracerMiddlewareSpan(t *testing.T) {
	const inboundTrace = "4bf92f3577b34da6a3ce929d0e0e4736"
	tests := []struct {
		name         string
		traceparent  string
		shortCircuit bool
	}{
		{name: "new trace"},
		{name: "inbound traceparent", traceparent: "00-" + inboundTrace + "-00f067aa0ba902b7-01"},
		{name: "later middleware answers", shortCircuit: true},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			recorder := tracetest.NewSpanRecorder()
			tp := sdktrace.NewTracerProvider(sdktrace.WithSpanProcessor(recorder))
			tracer := func(next http.Handler) http.Handler {
				return otelhttp.NewHandler(next, "server",
					otelhttp.WithTracerProvider(tp),
					otelhttp.WithPropagators(propagation.TraceContext{}))
			}

			middleware := []Middleware{tracer}
			if tt.shortCircuit {
				middleware = append(middleware, func(http.Handler) http.Handler {
					return http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
						w.WriteHeader(http.StatusTooManyRequests)
					})
				})
			}

			var buf bytes.Buffer
			c := newTestConnector(t, &buf,
				WithMiddleware(middleware...),
				WithExtraEndpoints(ExtraEndpoint{
					FunctionGroupCode: "test", Method: http.MethodGet, Context: "/traced", Name: "traced",
					Handler: func(w http.ResponseWriter, r *http.Request) {
						LoggerFromContext(r.Context()).Info("handler record")
						w.WriteHeader(http.StatusNoContent)
					},
				}),
			)

			req := httptest.NewRequest(http.MethodGet, "/traced", nil)
			if tt.traceparent != "" {
				req.Header.Set("traceparent", tt.traceparent)
			}
			c.Handler().ServeHTTP(httptest.NewRecorder(), req)

			spans := recorder.Ended()
			if len(spans) != 1 {
				t.Fatalf("recorded %d spans, want 1", len(spans))
			}
			sc := spans[0].SpanContext()
			wantTrace, wantSpan := sc.TraceID().String(), sc.SpanID().String()
			if tt.traceparent != "" && wantTrace != inboundTrace {
				t.Fatalf("otelhttp span trace id = %s, want inbound %s", wantTrace, inboundTrace)
			}

			seen := map[string]bool{}
			for _, l := range logLines(t, &buf) {
				msg, _ := l["message"].(string)
				if msg != "handler record" && msg != "request completed" {
					continue
				}
				seen[msg] = true
				if l["trace_id"] != wantTrace || l["span_id"] != wantSpan {
					t.Errorf("%q ids = (%v, %v), want the otelhttp span's (%s, %s)",
						msg, l["trace_id"], l["span_id"], wantTrace, wantSpan)
				}
			}
			if !seen["request completed"] || seen["handler record"] == tt.shortCircuit {
				t.Fatalf("log lines missing: %v", seen)
			}
		})
	}
}
