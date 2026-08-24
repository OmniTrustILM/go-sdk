package cryptography

import (
	"errors"
	"net/http"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix for every Cryptography Provider v2 route.
const DefaultBasePath = "/v2/cryptographyProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "cryptography" connector interface.
const InterfaceVersion = shared.VersionV2

// Handler adapts a Provider implementation (and any optional attribute or
// async sub-providers) to an HTTP surface mountable on a shared.Connector.
// Implements shared.Registrable and renders errors through the default
// WriteProblem.
type Handler struct {
	handlerbase.Config

	provider Provider

	asyncKeys AsyncKeyProvider
	asyncSign AsyncSignProvider

	tokenAttrs        TokenAttributeProvider
	tokenProfileAttrs TokenProfileAttributeProvider
	createKeyAttrs    CreateKeyAttributeProvider
	encryptAttrs      EncryptAttributeProvider
	decryptAttrs      DecryptAttributeProvider
	signAttrs         SignAttributeProvider
	verifyAttrs       VerifyAttributeProvider
	randomAttrs       RandomDataAttributeProvider
}

// NewHandler builds a Handler for the given Provider.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("cryptography: provider must not be nil")
	}
	h := &Handler{
		Config:   handlerbase.NewConfig(DefaultBasePath),
		provider: p,
	}
	if err := handlerbase.ApplyOptions(h, opts, "cryptography"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "cryptography"
// interface at version v2, plus any features configured via
// Base(handlerbase.WithFeatures(...)).
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCryptography, InterfaceVersion)
}

// Mount attaches every Cryptography Provider v2 route onto r. All patterns are
// literal — v2 has no path parameters — so this provider composes with any
// other provider package on one mux.
//
// Eighteen routes are always mounted. The six async status/cancel routes are
// mounted only when their sub-interface was registered (WithAsyncKeys,
// WithAsyncSign), reaching the package's full 24.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	r.Handle(http.MethodGet, base+"/tokens/attributes", h.listTokenAttributes)
	r.Handle(http.MethodPost, base+"/tokens/tokenProfile/attributes", h.listTokenProfileAttributes)
	r.Handle(http.MethodPost, base+"/keys/create/attributes", h.listCreateKeyAttributes)
	r.Handle(http.MethodPost, base+"/operations/encrypt/attributes", h.listEncryptAttributes)
	r.Handle(http.MethodPost, base+"/operations/decrypt/attributes", h.listDecryptAttributes)
	r.Handle(http.MethodPost, base+"/operations/sign/attributes", h.listSignAttributes)
	r.Handle(http.MethodPost, base+"/operations/verify/attributes", h.listVerifyAttributes)
	r.Handle(http.MethodPost, base+"/operations/random/attributes", h.listRandomDataAttributes)

	r.Handle(http.MethodPost, base+"/tokens/status", h.tokenStatus)
	r.Handle(http.MethodPost, base+"/tokens/tokenProfile/keyUsages", h.tokenProfileKeyUsages)
	r.Handle(http.MethodPost, base+"/tokens/keyRequestTypes", h.keyRequestTypes)

	r.Handle(http.MethodPost, base+"/keys", h.createKey)
	r.Handle(http.MethodPost, base+"/keys/destroy", h.destroyKey)

	r.Handle(http.MethodPost, base+"/operations/sign", h.signData)
	r.Handle(http.MethodPost, base+"/operations/encrypt", h.encryptData)
	r.Handle(http.MethodPost, base+"/operations/decrypt", h.decryptData)
	r.Handle(http.MethodPost, base+"/operations/verify", h.verifyData)
	r.Handle(http.MethodPost, base+"/operations/random", h.randomData)

	// Mounted only when the sub-interface is registered; otherwise the
	// framework answers 404, which the contract documents as "endpoint not
	// found or not implemented".
	if h.asyncKeys != nil {
		r.Handle(http.MethodPost, base+"/keys/create/status", h.createKeyStatus)
		r.Handle(http.MethodPost, base+"/keys/create/cancel", h.cancelCreateKey)
		r.Handle(http.MethodPost, base+"/keys/destroy/status", h.destroyKeyStatus)
		r.Handle(http.MethodPost, base+"/keys/destroy/cancel", h.cancelDestroyKey)
	}

	if h.asyncSign != nil {
		r.Handle(http.MethodPost, base+"/operations/sign/status", h.signDataStatus)
		r.Handle(http.MethodPost, base+"/operations/sign/cancel", h.cancelSignData)
	}
}
