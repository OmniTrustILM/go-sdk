package cryptography

import (
	"errors"
	"net/http"
	"slices"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix for every Cryptography Provider v2 route.
const DefaultBasePath = "/v2/cryptographyProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "cryptography" connector interface.
const InterfaceVersion = shared.VersionV2

// Handler adapts a Provider and its optional sub-providers to an HTTP surface
// mountable on a shared.Connector. Build it with NewHandler: a zero-value
// Handler panics on every provider-backed route, and Config must not change
// after Mount.
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
	// FeatureFlag.ASYNCHRONOUS is ENFORCED and covers the whole interface:
	// once advertised, Core may select asynchronous execution for key
	// creation, key destruction and signing alike, so every accepted
	// operation needs its status and cancel routes served.
	if slices.Contains(h.Features, string(mdl.FEATUREFLAG_ASYNCHRONOUS)) && (h.asyncKeys == nil || h.asyncSign == nil) {
		return nil, errors.New("cryptography: asynchronous feature advertised without both WithAsyncKeys and WithAsyncSign")
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "cryptography"
// interface at version v2, plus any features configured via
// Base(handlerbase.WithFeatures(...)).
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCryptography, InterfaceVersion)
}

// Mount attaches all 24 routes onto r unconditionally; the patterns are literal,
// so this package composes with any other on one mux. The six async routes
// answer 404 OPERATION_NOT_SUPPORTED when their sub-interface was not
// registered.
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

	r.Handle(http.MethodPost, base+"/keys/create/status", h.createKeyStatus)
	r.Handle(http.MethodPost, base+"/keys/create/cancel", h.cancelCreateKey)
	r.Handle(http.MethodPost, base+"/keys/destroy/status", h.destroyKeyStatus)
	r.Handle(http.MethodPost, base+"/keys/destroy/cancel", h.cancelDestroyKey)

	r.Handle(http.MethodPost, base+"/operations/sign/status", h.signDataStatus)
	r.Handle(http.MethodPost, base+"/operations/sign/cancel", h.cancelSignData)
}
