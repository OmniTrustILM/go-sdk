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
