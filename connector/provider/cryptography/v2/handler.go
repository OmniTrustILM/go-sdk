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

	keyImport   KeyImportProvider
	asyncImport AsyncKeyImportProvider
	keyExport   KeyExportProvider

	tokenAttrs        TokenAttributeProvider
	tokenProfileAttrs TokenProfileAttributeProvider
	createKeyAttrs    CreateKeyAttributeProvider
	encryptAttrs      EncryptAttributeProvider
	decryptAttrs      DecryptAttributeProvider
	signAttrs         SignAttributeProvider
	verifyAttrs       VerifyAttributeProvider
	randomAttrs       RandomDataAttributeProvider
	importAttrs       ImportKeyAttributeProvider
	exportAttrs       ExportKeyAttributeProvider
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
	if err := h.requireFeatureProviders(); err != nil {
		return nil, err
	}
	return h, nil
}

// requireFeatureProviders refuses an ENFORCED feature advertised without the
// providers behind the routes Core then calls. FeatureFlag.ASYNCHRONOUS covers
// the whole interface: once advertised, Core may select asynchronous
// execution for key creation, key destruction, signing and key import alike,
// so every accepted operation needs its status and cancel routes served.
func (h *Handler) requireFeatureProviders() error {
	advertised := func(flag mdl.FeatureFlag) bool { return slices.Contains(h.Features, string(flag)) }
	async := advertised(mdl.FEATUREFLAG_ASYNCHRONOUS)
	switch {
	case async && (h.asyncKeys == nil || h.asyncSign == nil):
		return errors.New("cryptography: asynchronous feature advertised without both WithAsyncKeys and WithAsyncSign")
	case advertised(mdl.FEATUREFLAG_KEY_IMPORT) && h.keyImport == nil:
		return errors.New("cryptography: keyImport feature advertised without WithKeyImport")
	case async && advertised(mdl.FEATUREFLAG_KEY_IMPORT) && h.asyncImport == nil:
		return errors.New("cryptography: asynchronous and keyImport features advertised without WithAsyncKeyImport")
	case advertised(mdl.FEATUREFLAG_KEY_EXPORT) && h.keyExport == nil:
		return errors.New("cryptography: keyExport feature advertised without WithKeyExport")
	}
	return nil
}

// Interface satisfies shared.Registrable. Reports the "cryptography"
// interface at version v2, plus any features configured via
// Base(handlerbase.WithFeatures(...)).
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCryptography, InterfaceVersion)
}

// Mount attaches every route onto r unconditionally; the patterns are literal,
// so this package composes with any other on one mux. The async, key import
// and key export routes answer 404 OPERATION_NOT_SUPPORTED when their
// sub-interface was not registered, except the attribute routes, which answer
// 200 with an empty array as every attribute route does.
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

	r.Handle(http.MethodPost, base+"/keys/import/keyTypes", h.listImportableKeyTypes)
	r.Handle(http.MethodPost, base+"/keys/import/attributes", h.listImportKeyAttributes)
	r.Handle(http.MethodPost, base+"/keys/import", h.importKey)
	r.Handle(http.MethodPost, base+"/keys/import/result", h.importKeyResult)
	r.Handle(http.MethodPost, base+"/keys/import/status", h.importKeyStatus)
	r.Handle(http.MethodPost, base+"/keys/import/cancel", h.cancelImportKey)

	r.Handle(http.MethodPost, base+"/keys/export/keyTypes", h.listExportableKeyTypes)
	r.Handle(http.MethodPost, base+"/keys/export/attributes", h.listExportKeyAttributes)
	r.Handle(http.MethodPost, base+"/keys/export", h.exportKey)
}
