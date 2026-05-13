package secret

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/secretProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "secret" connector interface.
const InterfaceVersion = "1"

// Default decode configuration. Mirrors shared.config defaults so behavior
// stays consistent unless the caller explicitly opts in.
const (
	defaultMaxBytes = 1 << 20 // 1 MiB
)

// Handler adapts a Provider implementation (and any registered attribute
// providers) to an HTTP surface mountable on a shared.Connector.
//
// Construct with NewHandler; mount via shared.Register(handler) on the
// Connector. Handler is goroutine-safe once constructed; configuration is
// frozen after NewHandler returns.
type Handler struct {
	provider Provider

	secretAttrs       SecretAttributeProvider
	vaultAttrs        VaultAttributeProvider
	vaultProfileAttrs VaultProfileAttributeProvider
	rotateAttrs       RotateAttributeProvider

	basePath string
	maxBytes int64
	strict   bool
	logger   *slog.Logger
}

// NewHandler builds a Handler for the given Provider, applying functional
// options. Returns an error if p is nil or any option fails.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("secret: provider must not be nil")
	}
	h := &Handler{
		provider: p,
		basePath: DefaultBasePath,
		maxBytes: defaultMaxBytes,
	}
	for _, opt := range opts {
		if err := opt(h); err != nil {
			return nil, fmt.Errorf("secret: apply option: %w", err)
		}
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports "secret" interface code
// with version 1.
func (h *Handler) Interface() shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:    shared.InterfaceCodeSecret,
		Version: InterfaceVersion,
	}
}

// Mount attaches every Secret Provider v1 route onto r. Routes that depend on
// an optional attribute provider are mounted unconditionally — when the
// provider is unregistered, the handler responds 404 RESOURCE_NOT_FOUND.
//
// Pattern precedence note: GET /secrets/rotate/attributes is registered as a
// literal path so it wins over GET /secrets/{secretType}/attributes per
// stdlib ServeMux specificity rules.
func (h *Handler) Mount(r shared.Router) {
	base := h.basePath

	// Secret Management
	r.Handle(http.MethodPost, base+"/secrets", h.createSecret)
	r.Handle(http.MethodPut, base+"/secrets", h.updateSecret)
	r.Handle(http.MethodDelete, base+"/secrets", h.deleteSecret)
	r.Handle(http.MethodPost, base+"/secrets/rotate", h.rotateSecret)
	r.Handle(http.MethodPost, base+"/secrets/content", h.getSecretContent)

	// Vault Management
	r.Handle(http.MethodPost, base+"/vaults", h.checkVaultConnection)

	// Attribute endpoints
	r.Handle(http.MethodGet, base+"/vaults/attributes", h.listVaultAttributes)
	r.Handle(http.MethodPost, base+"/vaultProfiles/attributes", h.listVaultProfileAttributes)
	r.Handle(http.MethodGet, base+"/secrets/rotate/attributes", h.getRotateAttributes)
	r.Handle(http.MethodGet, base+"/secrets/{secretType}/attributes", h.getSecretAttributes)
}

// loggerFor returns the request-scoped logger, falling back to the handler
// override and finally to slog.Default().
func (h *Handler) loggerFor(r *http.Request) *slog.Logger {
	if h.logger != nil {
		return h.logger
	}
	return shared.LoggerFromContext(r.Context())
}
