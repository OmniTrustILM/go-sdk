package shared

import (
	"context"
	"encoding/json"
	"io"
	"log/slog"
	"sync"
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

// Field names of the connector.log v1 schema. Attributes bound to a logger
// under one of the conditional keys (via Logger.With or per-call args) are
// promoted to top-level envelope fields instead of landing in attributes{}.
const (
	logKeyTraceID       = "trace_id"
	logKeySpanID        = "span_id"
	logKeyTraceFlags    = "trace_flags"
	logKeyCorrelationID = "correlation_id"
)

// logSchema is the fixed schema marker every connector.log v1 entry carries.
var logSchema = map[string]any{"name": "connector.log", "version": 1}

// LogHandlerOptions configures NewLogHandler.
type LogHandlerOptions struct {
	// Level reports the minimum record level that will be logged.
	// Default slog.LevelInfo.
	Level slog.Leveler

	// ServiceName fills the required service.name envelope field.
	// Default "connector".
	ServiceName string

	// ServiceVersion fills the optional service.version envelope field.
	ServiceVersion string
}

// logHandler is a slog.Handler emitting the ILM connector.log v1 envelope:
//
//	{
//	  "schema": {"name": "connector.log", "version": 1},
//	  "@timestamp": "2026-01-02T15:04:05.999Z07:00",
//	  "severity": "INFO",
//	  "message": "...",
//	  "service": {"name": "...", "version": "..."},
//	  "trace_id": "32 lowercase hex",      (when a span context is present)
//	  "span_id": "16 lowercase hex",
//	  "trace_flags": "00" | "01",
//	  "correlation_id": "...",             (when known)
//	  "attributes": { ... }                (every other attribute)
//	}
//
// Trace fields are read from the OpenTelemetry span context carried by the
// record's context (use the *Context logging methods) or from attributes
// bound under the trace_id/span_id/trace_flags keys — the shared middleware
// binds them on the request-scoped logger so even context-free log calls
// carry them. correlation_id resolves the same way.
//
// Spec invariant: every entry must carry either trace_id+span_id or
// correlation_id (or both). When a record has neither — typical for process
// lifecycle logs emitted outside any request — the handler falls back to a
// process-scoped correlation id generated at construction, so the invariant
// holds for every line the SDK emits.
type logHandler struct {
	opts         LogHandlerOptions
	fallbackCorr string
	prebound     []slog.Attr // attrs accumulated via WithAttrs, group-qualified
	groups       []string    // open groups from WithGroup
	mu           *sync.Mutex
	w            io.Writer
}

// NewLogHandler returns a slog.Handler that writes connector.log v1 JSON
// entries to w. Pass it to slog.New to build a conformant logger:
//
//	logger := slog.New(shared.NewLogHandler(os.Stdout, &shared.LogHandlerOptions{
//	    ServiceName:    "my-connector",
//	    ServiceVersion: "1.2.0",
//	}))
//
// The Connector uses this handler by default when WithLogger is not supplied,
// deriving the service identity from WithInfo.
func NewLogHandler(w io.Writer, opts *LogHandlerOptions) slog.Handler {
	o := LogHandlerOptions{}
	if opts != nil {
		o = *opts
	}
	if o.Level == nil {
		o.Level = slog.LevelInfo
	}
	if o.ServiceName == "" {
		o.ServiceName = "connector"
	}
	return &logHandler{
		opts:         o,
		fallbackCorr: uuid.NewString(),
		mu:           &sync.Mutex{},
		w:            w,
	}
}

func (h *logHandler) Enabled(_ context.Context, level slog.Level) bool {
	return level >= h.opts.Level.Level()
}

// severity maps slog levels onto the connector.log severity enum
// (TRACE / DEBUG / INFO / WARN / ERROR / FATAL).
func severity(l slog.Level) string {
	switch {
	case l < slog.LevelDebug:
		return "TRACE"
	case l < slog.LevelInfo:
		return "DEBUG"
	case l < slog.LevelWarn:
		return "INFO"
	case l < slog.LevelError:
		return "WARN"
	case l < slog.LevelError+4:
		return "ERROR"
	default:
		return "FATAL"
	}
}

// logEnvelope is the serialized connector.log v1 entry. Field order follows
// the schema documentation; encoding/json preserves struct order.
type logEnvelope struct {
	Schema        map[string]any `json:"schema"`
	Timestamp     string         `json:"@timestamp"`
	Severity      string         `json:"severity"`
	Message       string         `json:"message"`
	Service       logService     `json:"service"`
	TraceID       string         `json:"trace_id,omitempty"`
	SpanID        string         `json:"span_id,omitempty"`
	TraceFlags    string         `json:"trace_flags,omitempty"`
	CorrelationID string         `json:"correlation_id,omitempty"`
	Attributes    map[string]any `json:"attributes,omitempty"`
}

type logService struct {
	Name    string `json:"name"`
	Version string `json:"version,omitempty"`
}

func (h *logHandler) Handle(ctx context.Context, rec slog.Record) error {
	env := logEnvelope{
		Schema:   logSchema,
		Severity: severity(rec.Level),
		Message:  rec.Message,
		Service:  logService{Name: h.opts.ServiceName, Version: h.opts.ServiceVersion},
	}
	ts := rec.Time
	if ts.IsZero() {
		ts = time.Now()
	}
	env.Timestamp = ts.Format(time.RFC3339Nano)

	// Trace fields from the record's context (set by the tracing middleware
	// or by any OpenTelemetry instrumentation).
	if sc := trace.SpanContextFromContext(ctx); sc.IsValid() {
		env.TraceID = sc.TraceID().String()
		env.SpanID = sc.SpanID().String()
		env.TraceFlags = flagsHex(sc.TraceFlags())
	}
	if cid := CorrelationIDFromContext(ctx); cid != "" {
		env.CorrelationID = cid
	}

	attrs := make(map[string]any)
	promote := func(groups []string, a slog.Attr) bool {
		if len(groups) > 0 {
			return false // grouped attrs never promote to envelope fields
		}
		switch a.Key {
		case logKeyTraceID:
			env.TraceID = a.Value.String()
		case logKeySpanID:
			env.SpanID = a.Value.String()
		case logKeyTraceFlags:
			env.TraceFlags = a.Value.String()
		case logKeyCorrelationID:
			env.CorrelationID = a.Value.String()
		default:
			return false
		}
		return true
	}

	for _, a := range h.prebound {
		addAttr(attrs, h.splitGroups(a), promote)
	}
	rec.Attrs(func(a slog.Attr) bool {
		addAttr(attrs, groupedAttr{groups: h.groups, attr: a}, promote)
		return true
	})

	// Invariant: trace_id+span_id, or correlation_id, or both — never neither.
	if (env.TraceID == "" || env.SpanID == "") && env.CorrelationID == "" {
		env.CorrelationID = h.fallbackCorr
	}
	if len(attrs) > 0 {
		env.Attributes = attrs
	}

	buf, err := json.Marshal(env)
	if err != nil {
		return err
	}
	buf = append(buf, '\n')

	h.mu.Lock()
	defer h.mu.Unlock()
	_, err = h.w.Write(buf)
	return err
}

// groupedAttr pairs an attribute with the group path it belongs to.
type groupedAttr struct {
	groups []string
	attr   slog.Attr
}

// splitGroups reconstructs a prebound attr's group path. Prebound attrs are
// stored already qualified (see WithAttrs), so the stored attr carries no
// extra path.
func (h *logHandler) splitGroups(a slog.Attr) groupedAttr {
	return groupedAttr{attr: a}
}

// addAttr resolves ga into the attrs tree, nesting per the group path.
// promote intercepts envelope-level keys at the top level.
func addAttr(attrs map[string]any, ga groupedAttr, promote func([]string, slog.Attr) bool) {
	a := ga.attr
	a.Value = a.Value.Resolve()
	if a.Equal(slog.Attr{}) {
		return
	}
	if promote(ga.groups, a) {
		return
	}
	dst := attrs
	for _, g := range ga.groups {
		next, ok := dst[g].(map[string]any)
		if !ok {
			next = make(map[string]any)
			dst[g] = next
		}
		dst = next
	}
	putAttr(dst, a)
}

// putAttr writes one resolved attr into dst, recursing into slog groups.
func putAttr(dst map[string]any, a slog.Attr) {
	if a.Value.Kind() == slog.KindGroup {
		ga := a.Value.Group()
		if len(ga) == 0 {
			return
		}
		if a.Key == "" {
			for _, sub := range ga {
				sub.Value = sub.Value.Resolve()
				putAttr(dst, sub)
			}
			return
		}
		next, ok := dst[a.Key].(map[string]any)
		if !ok {
			next = make(map[string]any)
			dst[a.Key] = next
		}
		for _, sub := range ga {
			sub.Value = sub.Value.Resolve()
			putAttr(next, sub)
		}
		return
	}
	dst[a.Key] = safeJSONValue(a.Value.Any())
}

// safeJSONValue guards the envelope's single json.Marshal call against
// values encoding/json cannot serialize. Without it one bad attribute (NaN,
// Inf, a channel, an error type with unmarshalable fields, ...) fails the
// whole-envelope Marshal in Handle, and because slog.Logger discards Handle
// errors the ENTIRE record — message included — would be silently dropped.
// That must never happen to SDK-owned diagnostics like the "panic in
// handler" line, so:
//
//   - error values render as their Error() string (matches what readers
//     expect; json.Marshal would render most error types as {})
//   - any other value that fails a probe Marshal is replaced by an inline
//     "!ERROR:" string, mirroring stdlib slog.JSONHandler's behavior
func safeJSONValue(v any) any {
	if err, ok := v.(error); ok {
		return err.Error()
	}
	if _, err := json.Marshal(v); err != nil {
		return "!ERROR:" + err.Error()
	}
	return v
}

func (h *logHandler) WithAttrs(attrs []slog.Attr) slog.Handler {
	if len(attrs) == 0 {
		return h
	}
	nh := *h
	// Qualify incoming attrs with the currently open group path so Handle
	// can place them without tracking per-attr group state.
	qualified := make([]slog.Attr, 0, len(attrs))
	for _, a := range attrs {
		for i := len(h.groups) - 1; i >= 0; i-- {
			a = slog.Group(h.groups[i], a)
		}
		qualified = append(qualified, a)
	}
	nh.prebound = append(append([]slog.Attr{}, h.prebound...), qualified...)
	return &nh
}

func (h *logHandler) WithGroup(name string) slog.Handler {
	if name == "" {
		return h
	}
	nh := *h
	nh.groups = append(append([]string{}, h.groups...), name)
	return &nh
}

// flagsHex renders W3C trace flags as the spec's 2-char lowercase hex form.
func flagsHex(f trace.TraceFlags) string {
	if f.IsSampled() {
		return "01"
	}
	return "00"
}
