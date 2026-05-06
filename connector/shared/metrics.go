package shared

import (
	"context"
	"net/http"
	"time"

	"github.com/prometheus/client_golang/prometheus"
	"github.com/prometheus/client_golang/prometheus/collectors"
	"github.com/prometheus/client_golang/prometheus/promhttp"
)

// MetricsCollector is the abstraction used by the connector to record
// per-request metrics and to serve /v1/metrics. DefaultPrometheus returns a
// production-ready implementation; tests can supply a no-op or fake.
//
// All metric names and label sets are dictated by the connector spec
// (x-metrics-profile.required). Implementations must register the same set
// to remain spec-compliant.
type MetricsCollector interface {
	// Handler returns the HTTP handler that serves the metrics exposition.
	Handler() http.Handler

	// ObserveRequest records one completed inbound HTTP request.
	ObserveRequest(method, route string, status int, d time.Duration)

	// InFlightInc / InFlightDec maintain http_server_in_flight_requests.
	// Callers must pair every Inc with a Dec (typically via defer).
	InFlightInc(route string)
	InFlightDec(route string)

	// IncConnectorEvent bumps the connector_events_total counter. Provider
	// code calls this for domain events ("secret_rotate", outcome "ok"|"error").
	IncConnectorEvent(event, outcome string)
}

// BuildInfo populates app_build_info{version, commit, runtime}=1 at construction.
type BuildInfo struct {
	Version string
	Commit  string
	Runtime string
}

// Spec-required histogram buckets (x-metrics-profile.histograms).
var (
	httpServerLatencyBuckets = []float64{0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
	httpClientLatencyBuckets = []float64{0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1, 2.5, 5, 10}
)

// prometheusCollector implements MetricsCollector backed by a private
// prom registry (no pollution of the default global registry).
type prometheusCollector struct {
	reg *prometheus.Registry

	appBuildInfo       *prometheus.GaugeVec
	httpRequestsTotal  *prometheus.CounterVec
	httpReqDuration    *prometheus.HistogramVec
	httpInFlight       *prometheus.GaugeVec
	httpClientReqs     *prometheus.CounterVec
	httpClientDuration *prometheus.HistogramVec
	connectorEvents    *prometheus.CounterVec
}

// DefaultPrometheus constructs a MetricsCollector wired with every metric
// listed in the spec's x-metrics-profile. Registers Go runtime + process
// collectors against a private registry. Pass BuildInfo so the
// app_build_info gauge is populated at startup.
func DefaultPrometheus(b BuildInfo) MetricsCollector {
	reg := prometheus.NewRegistry()
	reg.MustRegister(collectors.NewGoCollector())
	reg.MustRegister(collectors.NewProcessCollector(collectors.ProcessCollectorOpts{}))

	c := &prometheusCollector{
		reg: reg,
		appBuildInfo: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "app_build_info",
			Help: "Application build metadata; value is always 1.",
		}, []string{"version", "commit", "runtime"}),
		httpRequestsTotal: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_requests_total",
			Help: "Total inbound HTTP requests handled.",
		}, []string{"method", "route", "status"}),
		httpReqDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_request_duration_seconds",
			Help:    "Inbound HTTP request latency in seconds.",
			Buckets: httpServerLatencyBuckets,
		}, []string{"method", "route"}),
		httpInFlight: prometheus.NewGaugeVec(prometheus.GaugeOpts{
			Name: "http_server_in_flight_requests",
			Help: "Current number of in-flight inbound HTTP requests.",
		}, []string{"route"}),
		httpClientReqs: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "http_client_requests_total",
			Help: "Total outbound HTTP requests issued by the connector.",
		}, []string{"method", "target", "status"}),
		httpClientDuration: prometheus.NewHistogramVec(prometheus.HistogramOpts{
			Name:    "http_client_request_duration_seconds",
			Help:    "Outbound HTTP request latency in seconds.",
			Buckets: httpClientLatencyBuckets,
		}, []string{"method", "target"}),
		connectorEvents: prometheus.NewCounterVec(prometheus.CounterOpts{
			Name: "connector_events_total",
			Help: "Domain events emitted by the connector.",
		}, []string{"event", "outcome"}),
	}

	reg.MustRegister(
		c.appBuildInfo,
		c.httpRequestsTotal,
		c.httpReqDuration,
		c.httpInFlight,
		c.httpClientReqs,
		c.httpClientDuration,
		c.connectorEvents,
	)

	c.appBuildInfo.WithLabelValues(b.Version, b.Commit, b.Runtime).Set(1)
	return c
}

func (c *prometheusCollector) Handler() http.Handler {
	return promhttp.HandlerFor(c.reg, promhttp.HandlerOpts{
		Registry:          c.reg,
		EnableOpenMetrics: true,
	})
}

func (c *prometheusCollector) ObserveRequest(method, route string, status int, d time.Duration) {
	c.httpRequestsTotal.WithLabelValues(method, route, statusLabel(status)).Inc()
	c.httpReqDuration.WithLabelValues(method, route).Observe(d.Seconds())
}

func (c *prometheusCollector) InFlightInc(route string) {
	c.httpInFlight.WithLabelValues(route).Inc()
}

func (c *prometheusCollector) InFlightDec(route string) {
	c.httpInFlight.WithLabelValues(route).Dec()
}

func (c *prometheusCollector) IncConnectorEvent(event, outcome string) {
	c.connectorEvents.WithLabelValues(event, outcome).Inc()
}

// MetricsFromContext returns the request-scoped MetricsCollector attached by
// the metrics middleware. Returns a no-op collector when metrics are
// disabled, so provider code can call IncConnectorEvent unconditionally.
func MetricsFromContext(ctx context.Context) MetricsCollector {
	if m, ok := ctx.Value(ctxKeyMetrics).(MetricsCollector); ok && m != nil {
		return m
	}
	return noopMetrics{}
}

// noopMetrics discards every observation. Returned when WithMetrics was not
// supplied.
type noopMetrics struct{}

func (noopMetrics) Handler() http.Handler                                 { return http.NotFoundHandler() }
func (noopMetrics) ObserveRequest(string, string, int, time.Duration)     {}
func (noopMetrics) InFlightInc(string)                                    {}
func (noopMetrics) InFlightDec(string)                                    {}
func (noopMetrics) IncConnectorEvent(string, string)                      {}

// withMetrics measures every served request. Requires the wrapped mux so it
// can resolve the matched route pattern (avoiding cardinality blow-up from
// raw URL paths). Sits between slog (outer) and recover (inner) so that
// panics rendered as 500 by recover are still attributed correctly.
func withMetrics(mux *http.ServeMux, mc MetricsCollector) Middleware {
	return func(next http.Handler) http.Handler {
		return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			route := matchedRoute(mux, r)
			start := time.Now()

			ctx := context.WithValue(r.Context(), ctxKeyMetrics, mc)
			r = r.WithContext(ctx)

			mc.InFlightInc(route)
			defer func() {
				mc.InFlightDec(route)
				status := http.StatusOK
				if sr, ok := w.(statusReader); ok {
					status = sr.Status()
				}
				mc.ObserveRequest(r.Method, route, status, time.Since(start))
			}()

			next.ServeHTTP(w, r)
		})
	}
}

// matchedRoute returns the registered pattern for r. Falls back to the raw
// path if the mux did not match (rare; covers /v1/metrics and similar).
// Strips the optional method prefix introduced by Go 1.22 method-scoped
// patterns ("GET /foo" -> "/foo").
func matchedRoute(mux *http.ServeMux, r *http.Request) string {
	_, pattern := mux.Handler(r)
	if pattern == "" {
		return "<not_found>"
	}
	for i := 0; i < len(pattern); i++ {
		if pattern[i] == ' ' {
			return pattern[i+1:]
		}
	}
	return pattern
}

// statusLabel renders an HTTP status code as a Prometheus label without
// allocating ("200", "404", ...). strconv.Itoa would also work; this is a
// tiny optimization for the hot path.
func statusLabel(status int) string {
	if status < 100 || status > 999 {
		return "0"
	}
	var b [3]byte
	b[0] = byte('0' + status/100)
	b[1] = byte('0' + (status/10)%10)
	b[2] = byte('0' + status%10)
	return string(b[:])
}
