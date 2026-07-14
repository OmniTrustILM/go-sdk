// Package attributes provides connector-agnostic scaffolding for the
// Attributes v2 API — the connector-global attribute-definition registry plus
// the dynamic-attribute callback surface that NG (next-generation) connectors
// serve at GET/POST /v2/attributes*.
//
// # Version axes — read carefully
//
// Three independent "vN" numbers appear in this feature; do not conflate them:
//
//   - Common-interface / NG generation — the "v2" in this package's import path
//     and in the /v2/attributes route prefix. It means "version 2 of the common
//     connector interface" (the NG generation, alongside Info/Health/Metrics).
//     This is what "Attributes v2 API" refers to. It is NOT attribute schema v2.
//   - Attribute schema version — the v2/v3 on the payload types
//     (BaseAttributeDto -> BaseAttributeDtoV2/V3, RequestAttribute, content
//     types). The registry is polymorphic over schema v2/v3; the callback
//     response content arm is pinned to schema v3 by design.
//   - Functional provider interface version — e.g. authority "v3", carried as
//     AttributeCallbackRequestDto.InterfaceVersion.
//
// So an Attributes v2 message legitimately carries attribute schema v3 content.
// That is correct, not a bug. The wire contract mirrors the Java definition in
// OmniTrustILM/interfaces (cross-language parity).
//
// # Usage
//
// A connector builds a static registry of Definitions once at startup and
// constructs a Handler from it. The Handler is a shared.Registrable, mounted
// alongside the connector's functional interface:
//
//	h, err := attributes.NewHandler("1.0.0", []attributes.Definition{
//		{Attribute: caNameDef},                       // no callback
//		{Attribute: regionDef, Callback: a.region},   // dynamic dropdown
//	})
//	// ...
//	c, _ := shared.New(shared.Register(authorityHandler), shared.Register(h))
//
// NewHandler self-validates the registry (see Validate) and fails fast on any
// inconsistency, so a misconfigured connector never starts.
package attributes

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
)

// InterfaceVersion is the common-interface (NG) generation this package serves,
// reported by Handler.Interface for the /v2/info interfaces list.
const InterfaceVersion = "v2"

// CallbackFunc resolves one attribute's dynamic (Attributes v2 / NG) callback:
// given the callback envelope Core dispatched, it returns the resolved content
// (DATA-attribute dropdown options) or runtime-injected attributes (GROUP
// children). Exactly one arm of the response must be set — see the response
// helpers ContentResponse and AttributesResponse.
type CallbackFunc func(ctx context.Context, req *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error)

// Definition is one attribute definition plus its optional callback resolver.
//
// Callback is required if and only if Attribute declares a dependsOn trigger
// (i.e. it is an NG callback attribute): the registry self-check rejects a
// dependsOn-declaring attribute with no Callback, and a Callback on an
// attribute that declares no trigger. Attributes with neither (static
// attributes) carry a nil Callback.
type Definition struct {
	// Attribute is the polymorphic attribute definition (schema v2 or v3).
	Attribute mdl.BaseAttributeDto
	// Callback resolves this attribute's dynamic callback, dispatched by the
	// attribute's connector-global UUID. Nil for static attributes.
	Callback CallbackFunc
}
