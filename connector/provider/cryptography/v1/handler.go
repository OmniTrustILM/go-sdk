package cryptography

import (
	"errors"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the route prefix every endpoint mounts under.
const DefaultBasePath = "/v1/cryptographyProvider"

// InterfaceVersion is reported via /v2/info as the implemented version of
// the "cryptography" connector interface.
const InterfaceVersion = shared.VersionV1

// FunctionGroupCode is the canonical code emitted in /v1 info, pulled from
// the generated FunctionGroupCode enum. Matches the path token.
const FunctionGroupCode = string(mdl.FUNCTIONGROUPCODE_CRYPTOGRAPHY_PROVIDER)

// Handler adapts a Provider implementation (and optional attribute providers)
// to an HTTP surface mountable on a shared.Connector. Implements both
// shared.Registrable (Mount + Interface) and shared.V1Reporter (FunctionGroup).
type Handler struct {
	handlerbase.Config

	provider Provider

	kindAttrs            KindAttributeProvider
	tokenProfileAttrs    TokenProfileAttributeProvider
	tokenActivationAttrs TokenActivationAttributeProvider
	createSecretKeyAttrs CreateSecretKeyAttributeProvider
	createKeyPairAttrs   CreateKeyPairAttributeProvider
	randomDataAttrs      RandomDataAttributeProvider
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

// Interface satisfies shared.Registrable.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeCryptography, InterfaceVersion)
}

// FunctionGroup implements shared.V1Reporter. Endpoints mirror the routes
// mounted by Mount. The generic kind-attribute endpoints render their
// Context using the spec template ({kind} wildcard) even though Mount
// substitutes literal kinds — the /v1 info convention uses the template form.
func (h *Handler) FunctionGroup() shared.V1FunctionGroup {
	base := h.BasePath

	endpoints := []shared.V1Endpoint{
		// Generic kind attributes.
		{Name: "listAttributeDefinitions", Method: http.MethodGet, Context: base + "/{kind}/attributes"},
		{Name: "validateAttributes", Method: http.MethodPost, Context: base + "/{kind}/attributes/validate"},

		// Token instance management.
		{Name: "listTokenInstances", Method: http.MethodGet, Context: base + "/tokens"},
		{Name: "createTokenInstance", Method: http.MethodPost, Context: base + "/tokens"},
		{Name: "getTokenInstance", Method: http.MethodGet, Context: base + "/tokens/{uuid}"},
		{Name: "updateTokenInstance", Method: http.MethodPost, Context: base + "/tokens/{uuid}"},
		{Name: "removeTokenInstance", Method: http.MethodDelete, Context: base + "/tokens/{uuid}"},
		{Name: "getTokenInstanceStatus", Method: http.MethodGet, Context: base + "/tokens/{uuid}/status"},
		{Name: "activateTokenInstance", Method: http.MethodPatch, Context: base + "/tokens/{uuid}/activate"},
		{Name: "deactivateTokenInstance", Method: http.MethodPatch, Context: base + "/tokens/{uuid}/deactivate"},

		// Token profile attributes.
		{Name: "listTokenProfileAttributes", Method: http.MethodGet, Context: base + "/tokens/{uuid}/tokenProfile/attributes"},
		{Name: "validateTokenProfileAttributes", Method: http.MethodPost, Context: base + "/tokens/{uuid}/tokenProfile/attributes/validate"},

		// Token activation attributes.
		{Name: "listTokenInstanceActivationAttributes", Method: http.MethodGet, Context: base + "/tokens/{uuid}/activate/attributes"},
		{Name: "validateTokenInstanceActivationAttributes", Method: http.MethodPost, Context: base + "/tokens/{uuid}/activate/attributes/validate"},

		// Keys.
		{Name: "listKeys", Method: http.MethodGet, Context: base + "/tokens/{uuid}/keys"},
		{Name: "getKey", Method: http.MethodGet, Context: base + "/tokens/{uuid}/keys/{keyUuid}"},
		{Name: "destroyKey", Method: http.MethodDelete, Context: base + "/tokens/{uuid}/keys/{keyUuid}"},
		{Name: "createSecretKey", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/secret"},
		{Name: "createKeyPair", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/pair"},
		{Name: "randomData", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/random"},

		// Per-key-type attribute endpoints.
		{Name: "listCreateSecretKeyAttributes", Method: http.MethodGet, Context: base + "/tokens/{uuid}/keys/secret/attributes"},
		{Name: "validateCreateSecretKeyAttributes", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/secret/attributes/validate"},
		{Name: "listCreateKeyPairAttributes", Method: http.MethodGet, Context: base + "/tokens/{uuid}/keys/pair/attributes"},
		{Name: "validateCreateKeyPairAttributes", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/pair/attributes/validate"},
		{Name: "listRandomAttributes", Method: http.MethodGet, Context: base + "/tokens/{uuid}/keys/random/attributes"},
		{Name: "validateRandomAttributes", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/random/attributes/validate"},

		// Crypto operations.
		{Name: "signData", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/{keyUuid}/sign"},
		{Name: "verifyData", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/{keyUuid}/verify"},
		{Name: "encryptData", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/{keyUuid}/encrypt"},
		{Name: "decryptData", Method: http.MethodPost, Context: base + "/tokens/{uuid}/keys/{keyUuid}/decrypt"},
	}

	return shared.V1FunctionGroup{
		FunctionGroupCode: FunctionGroupCode,
		Kinds:             shared.EnsureSlice(h.Kinds),
		EndPoints:         endpoints,
	}
}

// Mount attaches every Cryptography Provider route onto r.
//
// The generic kind-attribute endpoints are mounted once per declared kind
// with the kind name as a literal segment, avoiding the stdlib ServeMux
// conflict between
//
//	GET /v1/cryptographyProvider/{kind}/attributes
//	GET /v1/cryptographyProvider/tokens/{uuid}
//
// where both have one literal and one wildcard at swapped positions and
// neither is more specific (same trick as authority/v2). Other routes
// distinguish themselves by literal tails and do not collide.
func (h *Handler) Mount(r shared.Router) {
	base := h.BasePath

	// Per-literal-kind generic attributes.
	handlerbase.MountPerKindAttributes(r, base, h.Kinds, h.listKindAttributesFor, h.validateKindAttributesFor)

	// Token instance management.
	r.Handle(http.MethodGet, base+"/tokens", h.listTokenInstances)
	r.Handle(http.MethodPost, base+"/tokens", h.createTokenInstance)
	r.Handle(http.MethodGet, base+"/tokens/{uuid}", h.getTokenInstance)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}", h.updateTokenInstance)
	r.Handle(http.MethodDelete, base+"/tokens/{uuid}", h.removeTokenInstance)
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/status", h.getTokenInstanceStatus)
	r.Handle(http.MethodPatch, base+"/tokens/{uuid}/activate", h.activateTokenInstance)
	r.Handle(http.MethodPatch, base+"/tokens/{uuid}/deactivate", h.deactivateTokenInstance)

	// Token profile attributes.
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/tokenProfile/attributes", h.listTokenProfileAttributes)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/tokenProfile/attributes/validate", h.validateTokenProfileAttributes)

	// Token activation attributes.
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/activate/attributes", h.listTokenActivationAttributes)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/activate/attributes/validate", h.validateTokenActivationAttributes)

	// Key management.
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/keys", h.listKeys)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/secret", h.createSecretKey)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/pair", h.createKeyPair)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/random", h.randomData)
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/keys/secret/attributes", h.listCreateSecretKeyAttributes)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/secret/attributes/validate", h.validateCreateSecretKeyAttributes)
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/keys/pair/attributes", h.listCreateKeyPairAttributes)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/pair/attributes/validate", h.validateCreateKeyPairAttributes)
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/keys/random/attributes", h.listRandomDataAttributes)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/random/attributes/validate", h.validateRandomDataAttributes)

	// Keys with {keyUuid} — must come after the literal /secret /pair /random
	// sub-paths so the literal segments win specificity. Go's mux compares
	// patterns by specificity rather than order, so this ordering is for
	// clarity only.
	r.Handle(http.MethodGet, base+"/tokens/{uuid}/keys/{keyUuid}", h.getKey)
	r.Handle(http.MethodDelete, base+"/tokens/{uuid}/keys/{keyUuid}", h.destroyKey)

	// Crypto operations.
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/{keyUuid}/sign", h.signData)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/{keyUuid}/verify", h.verifyData)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/{keyUuid}/encrypt", h.encryptData)
	r.Handle(http.MethodPost, base+"/tokens/{uuid}/keys/{keyUuid}/decrypt", h.decryptData)
}
