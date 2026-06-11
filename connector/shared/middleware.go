package shared

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"

	"go.opentelemetry.io/otel/trace"
)

type ctxKey int

const (
	ctxKeyLogger ctxKey = iota
	ctxKeyCorrelationID
	ctxKeyMetrics
	ctxKeyErrorRenderer
)

// CorrelationHeader is the canonical correlation header per the ILM
// logging-and-tracing spec: read inbound, generated when absent, and always
// echoed back to the client on the response.
const CorrelationHeader = "Correlation-Id"

// maxCorrelationIDLength caps the correlation id per the spec (128 chars).
// Longer inbound values are rejected and replaced with a generated id.
const maxCorrelationIDLength = 128

// statusReader is implemented by statusRecorder. Lets inner middleware
// (e.g. metrics) read the response status set by handlers (or by recover
// rendering a 500) without owning its own recorder.
type statusReader interface {
	Status() int
}

// LoggerFromContext returns the request-scoped slog.Logger attached by the
// shared middleware chain. Returns slog.Default() when called outside a
// connector request (e.g. during tests).
func LoggerFromContext(ctx context.Context) *slog.Logger {
	if l, ok := ctx.Value(ctxKeyLogger).(*slog.Logger); ok && l != nil {
		return l
	}
	return slog.Default()
}

// CorrelationIDFromContext returns the correlation id assigned by the
// correlation middleware (inbound Correlation-Id header, or generated).
// Empty string when called outside a connector request.
func CorrelationIDFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyCorrelationID).(string); ok {
		return s
	}
	return ""
}

// RequestIDFromContext returns the request correlation id.
//
// Deprecated: the request id was replaced by the spec's correlation id; use
// CorrelationIDFromContext. This alias returns the same value.
func RequestIDFromContext(ctx context.Context) string {
	return CorrelationIDFromContext(ctx)
}

// withCorrelationID implements the spec's correlation-id handling: read the
// Correlation-Id header (falling back to aliasHeader for back-compat when
// set), validate it (≤128 chars, printable characters only), generate a
// fresh id when absent or invalid, store it in context, and echo it back to
// the client on the canonical Correlation-Id response header.
func withCorrelationID(aliasHeader string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := sanitizeCorrelationID(r.Header.Get(CorrelationHeader))
			if id == "" && aliasHeader != "" {
				id = sanitizeCorrelationID(r.Header.Get(aliasHeader))
			}
			if id == "" {
				id = newCorrelationID()
			}
			w.Header().Set(CorrelationHeader, id)
			ctx := context.WithValue(r.Context(), ctxKeyCorrelationID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// sanitizeCorrelationID validates an inbound correlation id. Returns "" when
// the value is empty, exceeds 128 characters, or contains characters outside
// printable ASCII — the caller then generates a fresh id rather than
// propagating a malformed or header-injection-prone value into logs.
func sanitizeCorrelationID(v string) string {
	if v == "" || len(v) > maxCorrelationIDLength {
		return ""
	}
	for i := 0; i < len(v); i++ {
		if v[i] < 0x21 || v[i] > 0x7e {
			return ""
		}
	}
	return v
}

// withSlogLogger builds the request-scoped logger and emits the built-in
// "request completed" line. It binds trace_id / span_id / trace_flags (from
// the span context established by the tracing middleware) and correlation_id
// onto the logger, so every record logged through LoggerFromContext carries
// the spec's conditional fields even when callers use the context-free slog
// methods. The connector.log handler promotes those bound keys to top-level
// envelope fields.
func withSlogLogger(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()

			args := make([]any, 0, 14)
			if sc := trace.SpanContextFromContext(r.Context()); sc.IsValid() {
				args = append(args,
					logKeyTraceID, sc.TraceID().String(),
					logKeySpanID, sc.SpanID().String(),
					logKeyTraceFlags, flagsHex(sc.TraceFlags()),
				)
			}
			if cid := CorrelationIDFromContext(r.Context()); cid != "" {
				args = append(args, logKeyCorrelationID, cid)
			}
			args = append(args,
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
			)
			log := base.With(args...)
			ctx := context.WithValue(r.Context(), ctxKeyLogger, log)

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(ctx))

			log.InfoContext(ctx, "request completed",
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

func withRecover(base *slog.Logger, renderer ErrorRenderer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			defer func() {
				v := recover()
				if v == nil {
					return
				}
				log := base
				if l, ok := r.Context().Value(ctxKeyLogger).(*slog.Logger); ok && l != nil {
					log = l
				}
				log.Error("panic in handler",
					"panic", v,
					"stack", string(debug.Stack()),
				)
				renderer(w, r, Internal("PANIC", "internal server error"))
			}()
			next.ServeHTTP(w, r)
		})
	}
}

// withErrorRenderer attaches the connector-wide ErrorRenderer to request
// context so handlers can resolve it via RenderError without holding a
// Connector reference.
func withErrorRenderer(renderer ErrorRenderer) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := context.WithValue(r.Context(), ctxKeyErrorRenderer, renderer)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// RenderError writes err using the request-scoped ErrorRenderer (set by the
// connector). Provider handlers should prefer this over WriteProblem so the
// response shape always matches the connector's configured renderer.
func RenderError(w http.ResponseWriter, r *http.Request, err error) {
	if rndr, ok := r.Context().Value(ctxKeyErrorRenderer).(ErrorRenderer); ok && rndr != nil {
		rndr(w, r, err)
		return
	}
	WriteProblem(w, r, err)
}

func withContextDecorator(fn func(context.Context, *http.Request) context.Context) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			ctx := fn(r.Context(), r)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

// statusRecorder captures the response status code and byte count for the
// completion log line. Tracks whether WriteHeader was called explicitly so
// implicit 200 responses are still logged correctly.
type statusRecorder struct {
	http.ResponseWriter
	status int
	bytes  int
	wrote  bool
}

func (r *statusRecorder) Status() int { return r.status }

func (r *statusRecorder) WriteHeader(code int) {
	if r.wrote {
		return
	}
	r.status = code
	r.wrote = true
	r.ResponseWriter.WriteHeader(code)
}

func (r *statusRecorder) Write(b []byte) (int, error) {
	if !r.wrote {
		r.wrote = true
	}
	n, err := r.ResponseWriter.Write(b)
	r.bytes += n
	return n, err
}

func newCorrelationID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "corr-fallback"
	}
	return hex.EncodeToString(b[:])
}
