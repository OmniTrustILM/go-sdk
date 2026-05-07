package shared

import (
	"net/http"
)

// ConnectorInterface enum values from the spec. Shared interfaces ("info",
// "health", "metrics") are owned by this package and added to /v2/info
// automatically. Provider-specific values ("secret", "authority", ...) are
// supplied by Registrable handlers via Interface().
const (
	InterfaceCodeInfo         = "info"
	InterfaceCodeHealth       = "health"
	InterfaceCodeMetrics      = "metrics"
	InterfaceCodeAuthority    = "authority"
	InterfaceCodeDiscovery    = "discovery"
	InterfaceCodeEntity       = "entity"
	InterfaceCodeCompliance   = "compliance"
	InterfaceCodeCryptography = "cryptography"
	InterfaceCodeNotification = "notification"
	InterfaceCodeSecret       = "secret"
)

// Info holds caller-supplied connector identity surfaced by /v2/info. ID,
// Name, Version are required by the spec; Description and Metadata are
// optional. Metadata renders as a JSON object of arbitrary keys.
type Info struct {
	ID          string
	Name        string
	Version     string
	Description string
	Metadata    map[string]any
}

// InterfaceInfo describes one connector interface implemented by the running
// service. Returned from Registrable.Interface() and aggregated by the
// /v2/info handler. Code matches the ConnectorInterface enum.
type InterfaceInfo struct {
	Code     string   `json:"code"`
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
}

// InfoResponse is the JSON wire shape returned by /v2/info. Mirrors
// ConnectorInfo + ConnectorInterfaceInfo from every spec; hoisted into the
// shared package so the handler does not depend on a generated model.
type InfoResponse struct {
	Connector  ConnectorInfoDTO `json:"connector"`
	Interfaces []InterfaceInfo  `json:"interfaces"`
}

// ConnectorInfoDTO is the wire shape for the "connector" object of InfoResponse.
type ConnectorInfoDTO struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// mountInfo attaches GET /v2/info. shared owns "info" and "health" interfaces
// always; "metrics" is added when WithMetrics is supplied. Provider
// interfaces come from registered handlers.
func mountInfo(r Router, info Info, regs []Registrable, metricsEnabled bool) {
	r.Handle(http.MethodGet, "/v2/info", infoHandler(info, regs, metricsEnabled))
}

func infoHandler(info Info, regs []Registrable, metricsEnabled bool) http.HandlerFunc {
	// Interface list is stable across requests; build once at mount time.
	ifaces := make([]InterfaceInfo, 0, 3+len(regs))
	ifaces = append(ifaces,
		InterfaceInfo{Code: InterfaceCodeInfo, Version: "2"},
		InterfaceInfo{Code: InterfaceCodeHealth, Version: "2"},
	)
	if metricsEnabled {
		ifaces = append(ifaces, InterfaceInfo{Code: InterfaceCodeMetrics, Version: "1"})
	}
	for _, reg := range regs {
		ifaces = append(ifaces, reg.Interface())
	}

	resp := InfoResponse{
		Connector: ConnectorInfoDTO{
			ID:          info.ID,
			Name:        info.Name,
			Version:     info.Version,
			Description: info.Description,
			Metadata:    info.Metadata,
		},
		Interfaces: ifaces,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if err := WriteJSON(w, http.StatusOK, resp); err != nil {
			LoggerFromContext(r.Context()).Error("write info failed", "err", err)
		}
	}
}
