package shared

import (
	"net/http"
)

// ConnectorInterface enum values from the spec. Shared interfaces ("info",
// "health", "metrics") are owned by this package; provider-specific values
// ("secret", "authority", ...) are supplied by Registrable handlers via
// Interface().
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

// Version constants used by interface version fields. All version strings in
// /v2/info responses are emitted with a "v" prefix (e.g. "v1", "v2") per the
// observed convention from production connectors.
const (
	VersionV1 = "v1"
	VersionV2 = "v2"
)

// Info holds caller-supplied connector identity surfaced by info endpoints.
// ID, Name, Version are required by the spec; Description and Metadata are
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
// /v2/info handler.
type InterfaceInfo struct {
	Code     string   `json:"code"`
	Version  string   `json:"version"`
	Features []string `json:"features,omitempty"`
}

// V2InfoResponse is the JSON wire shape returned by /v2/info.
type V2InfoResponse struct {
	Connector  ConnectorInfoDTO `json:"connector"`
	Interfaces []InterfaceInfo  `json:"interfaces"`
}

// ConnectorInfoDTO is the wire shape for the "connector" object of /v2/info.
type ConnectorInfoDTO struct {
	ID          string         `json:"id"`
	Name        string         `json:"name"`
	Version     string         `json:"version"`
	Description string         `json:"description,omitempty"`
	Metadata    map[string]any `json:"metadata,omitempty"`
}

// V1FunctionGroup is one entry in the /v1 listSupportedFunctions response.
// FunctionGroupCode comes from the generated FunctionGroupCode enum of the
// provider's model package (e.g. "discoveryProvider", "authorityProvider").
type V1FunctionGroup struct {
	FunctionGroupCode string       `json:"functionGroupCode"`
	Kinds             []string     `json:"kinds"`
	EndPoints         []V1Endpoint `json:"endPoints"`
}

// V1Endpoint is one HTTP endpoint advertised in a V1FunctionGroup. UUID is
// nullable (renders as JSON null when nil) so callers that don't track
// stable IDs per endpoint can leave it unset.
type V1Endpoint struct {
	UUID     *string `json:"uuid"`
	Name     string  `json:"name"`
	Context  string  `json:"context"`
	Method   string  `json:"method"`
	Required bool    `json:"required"`
}

// V1Reporter is the optional Registrable extension implemented by handlers
// that contribute to /v1 listSupportedFunctions. Handlers whose spec uses
// /v2/info only (e.g. secret) do not implement it.
type V1Reporter interface {
	FunctionGroup() V1FunctionGroup
}

// ExtraEndpoint is a user-supplied HTTP handler that is mounted on the
// Connector's mux and surfaced under a function group in /v1 info. Use this
// for callback URLs or custom helpers that are not part of any provider's
// canonical spec.
//
// FunctionGroupCode determines where the endpoint shows up in /v1 info: if
// it matches a registered V1Reporter group, the endpoint is appended to that
// group; otherwise a fresh function group is emitted.
type ExtraEndpoint struct {
	FunctionGroupCode string
	Method            string
	Context           string
	Name              string
	Handler           http.HandlerFunc
	UUID              *string
	Required          bool
}

// mountInfo mounts the configured info endpoint(s). cfg.infoVersion is
// expected to be VersionV1 or VersionV2 (validated in config.validate).
func mountInfo(r Router, cfg *config) {
	switch cfg.infoVersion {
	case VersionV1:
		r.Handle(http.MethodGet, "/v1", v1InfoHandler(cfg))
	default: // v2
		r.Handle(http.MethodGet, "/v2/info", v2InfoHandler(cfg))
	}
}

// v2InfoHandler builds the /v2/info response once at mount time. Interface
// versions reflect the actual mounted endpoints (e.g. healthVersion=v1 makes
// the "health" interface report "v1").
func v2InfoHandler(cfg *config) http.HandlerFunc {
	ifaces := make([]InterfaceInfo, 0, 3+len(cfg.registrables))
	ifaces = append(ifaces,
		InterfaceInfo{Code: InterfaceCodeInfo, Version: cfg.infoVersion},
		InterfaceInfo{Code: InterfaceCodeHealth, Version: cfg.healthVersion},
	)
	if cfg.metrics != nil {
		ifaces = append(ifaces, InterfaceInfo{Code: InterfaceCodeMetrics, Version: VersionV1})
	}
	for _, reg := range cfg.registrables {
		ifaces = append(ifaces, reg.Interface())
	}

	resp := V2InfoResponse{
		Connector: ConnectorInfoDTO{
			ID:          cfg.info.ID,
			Name:        cfg.info.Name,
			Version:     cfg.info.Version,
			Description: cfg.info.Description,
			Metadata:    cfg.info.Metadata,
		},
		Interfaces: ifaces,
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if err := WriteJSON(w, http.StatusOK, resp); err != nil {
			LoggerFromContext(r.Context()).Error("write info failed", "err", err)
		}
	}
}

// v1InfoHandler builds the /v1 listSupportedFunctions response: an array of
// function groups assembled from every V1Reporter registrable, merged with
// extras keyed by FunctionGroupCode. Extras whose code does not match any
// V1Reporter group become standalone groups (with empty Kinds).
func v1InfoHandler(cfg *config) http.HandlerFunc {
	// Bucket extras by function group code.
	extrasByGroup := make(map[string][]V1Endpoint, len(cfg.extras))
	for _, e := range cfg.extras {
		extrasByGroup[e.FunctionGroupCode] = append(extrasByGroup[e.FunctionGroupCode], V1Endpoint{
			UUID:     e.UUID,
			Name:     e.Name,
			Context:  e.Context,
			Method:   e.Method,
			Required: e.Required,
		})
	}

	// Start with one group per V1Reporter; append matching extras (and
	// remove them from the bucket so they don't appear twice).
	groups := make([]V1FunctionGroup, 0, len(cfg.registrables))
	for _, reg := range cfg.registrables {
		vr, ok := reg.(V1Reporter)
		if !ok {
			continue
		}
		fg := vr.FunctionGroup()
		if extra, has := extrasByGroup[fg.FunctionGroupCode]; has {
			fg.EndPoints = append(fg.EndPoints, extra...)
			delete(extrasByGroup, fg.FunctionGroupCode)
		}
		groups = append(groups, fg)
	}

	// Remaining extras have no matching V1Reporter — emit as standalone
	// groups. Multiple extras sharing the same code are merged in the
	// bucketing pass above, so each code appears at most once.
	for code, eps := range extrasByGroup {
		groups = append(groups, V1FunctionGroup{
			FunctionGroupCode: code,
			Kinds:             []string{},
			EndPoints:         eps,
		})
	}

	return func(w http.ResponseWriter, r *http.Request) {
		if err := WriteJSON(w, http.StatusOK, groups); err != nil {
			LoggerFromContext(r.Context()).Error("write v1 info failed", "err", err)
		}
	}
}

// mountExtras registers every user-supplied ExtraEndpoint on the router.
// Entries with a nil Handler are info-only and skipped here — they still
// surface in /v1 info via v1InfoHandler. Patterns honor stdlib
// http.ServeMux precedence — extras can introduce new paths but must not
// collide with provider routes.
func mountExtras(r Router, extras []ExtraEndpoint) {
	for _, e := range extras {
		if e.Handler == nil {
			continue
		}
		r.Handle(e.Method, e.Context, e.Handler)
	}
}
