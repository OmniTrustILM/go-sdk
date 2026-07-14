package attributes

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
)

// ContentResponse builds a callback response with the content arm set — the
// resolved DATA-attribute dropdown options (attribute schema v3) — and the
// attributes arm left unset, honoring the exactly-one-arm contract.
//
// content may be empty: a present, empty content arm means "resolved to zero
// options". A nil content is normalized to a non-nil empty slice so it
// serializes as [] (a present arm) rather than being omitted, which would
// leave neither arm set. totalItems is optional (nil to omit).
func ContentResponse(content []mdl.BaseAttributeContentDtoV3, totalItems *int64) *mdl.AttributeCallbackResponseDto {
	if content == nil {
		content = []mdl.BaseAttributeContentDtoV3{}
	}
	return &mdl.AttributeCallbackResponseDto{Content: content, TotalItems: totalItems}
}

// AttributesResponse builds a callback response with the attributes arm set —
// runtime-injected GROUP children — and the content arm left unset, honoring
// the exactly-one-arm contract. A nil attrs is normalized to a non-nil empty
// slice so the attributes arm is present.
func AttributesResponse(attrs []mdl.BaseAttributeDto) *mdl.AttributeCallbackResponseDto {
	if attrs == nil {
		attrs = []mdl.BaseAttributeDto{}
	}
	return &mdl.AttributeCallbackResponseDto{Attributes: attrs}
}
