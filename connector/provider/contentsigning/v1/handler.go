package contentsigning

import (
	"errors"
	"fmt"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// DefaultBasePath is the prefix for every Content Signing Formatting v1 route.
const DefaultBasePath = "/v1/signatureProvider/contentSigning"

// InterfaceVersion is reported via /v2/info as the implemented version of the
// "contentSigningFormatting" connector interface.
const InterfaceVersion = shared.VersionV1

// Handler mounts the Content Signing Formatting v1 routes. Shared info, health
// and metrics come from shared.Connector.
type Handler struct {
	handlerbase.Config
	provider Provider
	decl     *declaration

	// Set only when the family declares the level they serve.
	validator ProfileValidator
	sigStamp  SignatureTimestamper
	arcStamp  ArchiveTimestamper
	extender  Extender
}

// NewHandler builds a Handler for the given Provider. It reads the family and
// the attributes of every operation once, and refuses a declaration that is
// malformed or that needs an optional capability the provider lacks.
func NewHandler(p Provider, opts ...Option) (*Handler, error) {
	if p == nil {
		return nil, errors.New("contentsigning v1: provider must not be nil")
	}
	decl, err := newDeclaration(p)
	if err != nil {
		return nil, fmt.Errorf("contentsigning v1: %w", err)
	}
	h := &Handler{Config: handlerbase.NewConfig(DefaultBasePath), provider: p, decl: decl}
	h.validator, _ = p.(ProfileValidator)
	if h.sigStamp, err = capability[SignatureTimestamper](p, decl, mdl.SIGNATURELEVEL_TIMESTAMPED, "SignatureTimestamper"); err != nil {
		return nil, fmt.Errorf("contentsigning v1: %w", err)
	}
	if h.extender, err = capability[Extender](p, decl, mdl.SIGNATURELEVEL_LONG_TERM, "Extender"); err != nil {
		return nil, fmt.Errorf("contentsigning v1: %w", err)
	}
	if h.arcStamp, err = capability[ArchiveTimestamper](p, decl, mdl.SIGNATURELEVEL_ARCHIVAL, "ArchiveTimestamper"); err != nil {
		return nil, fmt.Errorf("contentsigning v1: %w", err)
	}
	if err := handlerbase.ApplyOptions(h, opts, "contentsigning v1"); err != nil {
		return nil, err
	}
	return h, nil
}

// Interface satisfies shared.Registrable. Reports the "contentSigningFormatting"
// interface at version v1.
func (h *Handler) Interface() shared.InterfaceInfo {
	return h.InterfaceInfo(shared.InterfaceCodeContentSigningFormatting, InterfaceVersion)
}

// Mount attaches every Content Signing Formatting v1 route onto r.
func (h *Handler) Mount(r shared.Router) {
	r.Handle(http.MethodGet, h.BasePath+"/declaration", h.declaration)
	r.Handle(http.MethodGet, h.BasePath+"/{operation}/attributes", h.attributes)

	r.Handle(http.MethodPost, h.BasePath+"/validateProfile", h.validateProfile)
	r.Handle(http.MethodPost, h.BasePath+"/computeDtbs", h.computeDtbs)
	r.Handle(http.MethodPost, h.BasePath+"/embedSignatureValue", h.embedSignatureValue)
	r.Handle(http.MethodPost, h.BasePath+"/computeSignatureTimestampImprint", h.computeSignatureTimestampImprint)
	r.Handle(http.MethodPost, h.BasePath+"/embedSignatureTimestamp", h.embedSignatureTimestamp)
	r.Handle(http.MethodPost, h.BasePath+"/computeArchiveTimestampImprint", h.computeArchiveTimestampImprint)
	r.Handle(http.MethodPost, h.BasePath+"/embedArchiveTimestamp", h.embedArchiveTimestamp)
	r.Handle(http.MethodPost, h.BasePath+"/extendToLevel", h.extendToLevel)
	r.Handle(http.MethodPost, h.BasePath+"/extendToLevel/status", h.extendStatus)
	r.Handle(http.MethodPost, h.BasePath+"/extendToLevel/cancel", h.extendCancel)
}
