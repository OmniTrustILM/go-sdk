package shared

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"log/slog"
	"net/http"
	"runtime/debug"
	"time"
)

type ctxKey int

const (
	ctxKeyLogger ctxKey = iota
	ctxKeyRequestID
	ctxKeyMetrics
)

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

// RequestIDFromContext returns the request id assigned by withRequestID.
// Empty string when called outside a connector request.
func RequestIDFromContext(ctx context.Context) string {
	if s, ok := ctx.Value(ctxKeyRequestID).(string); ok {
		return s
	}
	return ""
}

func withRequestID(header string) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			id := r.Header.Get(header)
			if id == "" {
				id = newRequestID()
			}
			w.Header().Set(header, id)
			ctx := context.WithValue(r.Context(), ctxKeyRequestID, id)
			next.ServeHTTP(w, r.WithContext(ctx))
		})
	}
}

func withSlogLogger(base *slog.Logger) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			start := time.Now()
			log := base.With(
				"req_id", RequestIDFromContext(r.Context()),
				"method", r.Method,
				"path", r.URL.Path,
				"remote", r.RemoteAddr,
			)
			ctx := context.WithValue(r.Context(), ctxKeyLogger, log)

			rec := &statusRecorder{ResponseWriter: w, status: http.StatusOK}
			next.ServeHTTP(rec, r.WithContext(ctx))

			log.Info("request completed",
				"status", rec.status,
				"bytes", rec.bytes,
				"duration_ms", time.Since(start).Milliseconds(),
			)
		})
	}
}

func withRecover(base *slog.Logger) Middleware {
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
				WriteProblem(w, r, Internal("PANIC", "internal server error"))
			}()
			next.ServeHTTP(w, r)
		})
	}
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

func newRequestID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		return "req-fallback"
	}
	return hex.EncodeToString(b[:])
}
