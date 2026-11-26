package shared

import (
	"fmt"
	"net/http"
	"strings"
)

// Router abstracts route registration so provider packages do not depend on
// the concrete *http.ServeMux. Lets the Connector swap routers later (e.g.
// chi) without touching provider code.
type Router interface {
	// Handle registers h for the given method and pattern. method may be empty
	// to match any method; pattern follows stdlib http.ServeMux syntax,
	// including wildcard segments like "/foo/{id}".
	Handle(method, pattern string, h http.HandlerFunc)
}

// muxRouter adapts *http.ServeMux (stdlib pattern matching) to Router.
type muxRouter struct{ mux *http.ServeMux }

func newMuxRouter(mux *http.ServeMux) *muxRouter { return &muxRouter{mux: mux} }

func (r *muxRouter) Handle(method, pattern string, h http.HandlerFunc) {
	method = strings.ToUpper(strings.TrimSpace(method))
	if method == "" {
		r.mux.Handle(pattern, h)
		return
	}
	r.mux.Handle(fmt.Sprintf("%s %s", method, pattern), h)
}

// routingErrors serves mux and renders the requests it cannot route (an
// unknown path or a method the path does not accept) through the
// connector's ErrorRenderer instead of the mux's plain-text replies. The
// status code and, on 405, the mux's Allow header are kept. Other
// unmatched outcomes, such as the mux's path-cleaning redirects, and the
// "*" request target the mux rejects itself pass through unchanged.
func routingErrors(mux *http.ServeMux) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		h, pattern := mux.Handler(r)
		if pattern != "" || r.RequestURI == "*" {
			mux.ServeHTTP(w, r)
			return
		}
		rw := &routingErrorWriter{ResponseWriter: w}
		h.ServeHTTP(rw, r)
		switch rw.status {
		case http.StatusNotFound:
			RenderError(w, r, NotFound("RESOURCE_NOT_FOUND", "no route for %s", r.URL.Path))
		case http.StatusMethodNotAllowed:
			RenderError(w, r, newError(http.StatusMethodNotAllowed, "OPERATION_NOT_SUPPORTED",
				"method %s is not allowed for %s", r.Method, r.URL.Path))
		}
	})
}

// routingErrorWriter swallows the mux's plain-text 404 and 405 replies so
// routingErrors can render them; any other reply is written through. Header
// changes reach the underlying writer, which keeps the mux's Allow header.
type routingErrorWriter struct {
	http.ResponseWriter
	status int
}

func (w *routingErrorWriter) WriteHeader(code int) {
	if code == http.StatusNotFound || code == http.StatusMethodNotAllowed {
		w.status = code
		return
	}
	w.ResponseWriter.WriteHeader(code)
}

func (w *routingErrorWriter) Write(b []byte) (int, error) {
	if w.status != 0 {
		return len(b), nil
	}
	return w.ResponseWriter.Write(b)
}
