// Package contentsigning implements the Content Signing Formatting Provider
// v1 connector interface: a connector that turns a document into the bytes a
// signer signs, and the signature back into a signed document.
//
// A connector serves one signature family. The handler checks what is common
// to every family (body fields, family, transfer mode, signature algorithm,
// declared levels) and leaves the format to the Provider. Operations beyond
// the signed level are optional: the provider implements ProfileValidator,
// SignatureTimestamper, ArchiveTimestamper and Extender as its family needs,
// and NewHandler checks that every declared level has its capability.
package contentsigning

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
)

// Family is the declaration of the signature family a provider serves.
type Family = mdl.SignatureFamilyDeclaration

// Operation names an operation that can carry attribute definitions.
type Operation = mdl.ContentSigningFormattingOperation

// Attributes are the attribute definitions of one operation. Profile
// attributes are set by the operator on the signing profile, request
// attributes by the signing request.
type Attributes struct {
	Profile []mdl.BaseAttributeDto
	Request []mdl.BaseAttributeDto
}

// Provider is the surface every content-signing formatting connector
// implements: its family, the attributes of each operation, and the two
// operations of the signed level.
//
// Family and Attributes are read once by NewHandler. Request attributes must
// be data attributes, and a name must have one definition across operations.
// The handler has already checked the body fields, the family, the transfer
// mode and the signature algorithm when a method runs.
type Provider interface {
	Family() Family
	Attributes(op Operation) Attributes
	ComputeDtbs(ctx context.Context, req *mdl.ComputeDtbsRequest) (*mdl.ComputeDtbsResponse, error)
	EmbedSignatureValue(ctx context.Context, req *mdl.EmbedSignatureValueRequest) (*mdl.SignedDocumentResponse, error)
}

// ProfileValidator judges the formatting attributes of a signing profile. A
// provider without it accepts every profile.
type ProfileValidator interface {
	ValidateProfile(ctx context.Context, req *mdl.ValidateProfileRequest) (*mdl.ValidateProfileResponse, error)
}

// SignatureTimestamper serves the timestamped level.
type SignatureTimestamper interface {
	ComputeSignatureTimestampImprint(ctx context.Context, req *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error)
	EmbedSignatureTimestamp(ctx context.Context, req *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error)
}

// ArchiveTimestamper serves the archival level.
type ArchiveTimestamper interface {
	ComputeArchiveTimestampImprint(ctx context.Context, req *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error)
	EmbedArchiveTimestamp(ctx context.Context, req *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error)
}

// Extender serves the long_term level.
type Extender interface {
	ExtendToLevel(ctx context.Context, req *mdl.ExtendToLevelRequest) (*mdl.ExtendToLevelResponse, error)
	ExtendStatus(ctx context.Context, req *mdl.ExtendOperationScopedRequest) (*mdl.ExtendOperationStatusResponse, error)
	ExtendCancel(ctx context.Context, req *mdl.ExtendOperationScopedRequest) error
}
