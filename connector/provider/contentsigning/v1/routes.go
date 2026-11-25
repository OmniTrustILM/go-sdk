package contentsigning

import (
	"context"
	"net/http"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// handle decodes the body into In, runs check, then call, and writes the
// answer. A call that returns neither a response nor an error is a 500, except
// where the route answers 204.
func handle[In, Out any](h *Handler, w http.ResponseWriter, r *http.Request, event string, status int,
	check func(*In) error, call func(context.Context, *In) (*Out, error)) {
	var in In
	err := h.decode(w, r, &in)
	if err == nil {
		err = check(&in)
	}
	if err != nil {
		h.reply(w, r, event, status, nil, err)
		return
	}
	out, err := call(r.Context(), &in)
	if out == nil && err == nil && status != http.StatusNoContent {
		err = errNilResponse
	}
	h.reply(w, r, event, status, out, err)
}

func (h *Handler) declaration(w http.ResponseWriter, r *http.Request) {
	h.reply(w, r, "content_signing_declaration", 200, mdl.NewContentSigningDeclaration([]Family{h.decl.family}), nil)
}

func (h *Handler) attributes(w http.ResponseWriter, r *http.Request) {
	op, err := mdl.NewContentSigningFormattingOperationFromValue(r.PathValue("operation"))
	if err != nil {
		h.reply(w, r, "content_signing_attributes", 200, nil, shared.BadRequest("BAD_REQUEST", "unknown operation %q", r.PathValue("operation")))
		return
	}
	a := h.decl.attributesOf(*op)
	h.reply(w, r, "content_signing_attributes", 200, mdl.NewContentSigningFormattingAttributes(
		shared.EnsureSlice(a.Profile), shared.EnsureSlice(a.Request)), nil)
}

func (h *Handler) validateProfile(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_validate_profile", 200,
		func(in *mdl.ValidateProfileRequest) error { return h.checkFamilyOnly(in.Family) },
		func(ctx context.Context, in *mdl.ValidateProfileRequest) (*mdl.ValidateProfileResponse, error) {
			if h.validator == nil {
				return mdl.NewValidateProfileResponse([]mdl.ProfileAttributeError{}, h.decl.family.TransferModes), nil
			}
			out, err := h.validator.ValidateProfile(ctx, in)
			if out != nil {
				copyOut := *out
				copyOut.Errors = shared.EnsureSlice(copyOut.Errors)
				out = &copyOut
			}
			return out, err
		})
}

func (h *Handler) computeDtbs(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_compute_dtbs", 200, h.checkComputeDtbs, h.provider.ComputeDtbs)
}

func (h *Handler) embedSignatureValue(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_embed_signature_value", 200, h.checkEmbedSignatureValue, h.provider.EmbedSignatureValue)
}

func (h *Handler) checkSignedDocument(in *mdl.SignedDocumentRequest) error {
	return h.checkSigned(in.Family, in.SignedDocument, in.DetachedContent)
}

func (h *Handler) checkEmbedTimestamp(in *mdl.EmbedTimestampRequest) error {
	return h.checkSigned(in.Family, in.SignedDocument, in.DetachedContent, text("timestampToken", in.TimestampToken))
}

func (h *Handler) computeSignatureTimestampImprint(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_compute_signature_timestamp_imprint", 200, h.checkSignedDocument,
		func(ctx context.Context, in *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error) {
			if h.sigStamp == nil {
				return nil, h.unsupportedLevel(mdl.SIGNATURELEVEL_TIMESTAMPED)
			}
			return h.sigStamp.ComputeSignatureTimestampImprint(ctx, in)
		})
}

func (h *Handler) embedSignatureTimestamp(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_embed_signature_timestamp", 200, h.checkEmbedTimestamp,
		func(ctx context.Context, in *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error) {
			if h.sigStamp == nil {
				return nil, h.unsupportedLevel(mdl.SIGNATURELEVEL_TIMESTAMPED)
			}
			return h.sigStamp.EmbedSignatureTimestamp(ctx, in)
		})
}

func (h *Handler) computeArchiveTimestampImprint(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_compute_archive_timestamp_imprint", 200, h.checkSignedDocument,
		func(ctx context.Context, in *mdl.SignedDocumentRequest) (*mdl.TimestampImprintResponse, error) {
			if h.arcStamp == nil {
				return nil, h.unsupportedLevel(mdl.SIGNATURELEVEL_ARCHIVAL)
			}
			return h.arcStamp.ComputeArchiveTimestampImprint(ctx, in)
		})
}

func (h *Handler) embedArchiveTimestamp(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_embed_archive_timestamp", 200, h.checkEmbedTimestamp,
		func(ctx context.Context, in *mdl.EmbedTimestampRequest) (*mdl.SignedDocumentResponse, error) {
			if h.arcStamp == nil {
				return nil, h.unsupportedLevel(mdl.SIGNATURELEVEL_ARCHIVAL)
			}
			return h.arcStamp.EmbedArchiveTimestamp(ctx, in)
		})
}

func (h *Handler) extendToLevel(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_extend_to_level", 200,
		func(in *mdl.ExtendToLevelRequest) error {
			return h.checkSigned(in.Family, in.SignedDocument, in.DetachedContent)
		},
		func(ctx context.Context, in *mdl.ExtendToLevelRequest) (*mdl.ExtendToLevelResponse, error) {
			if h.extender == nil {
				return nil, h.unsupportedLevel(mdl.SIGNATURELEVEL_LONG_TERM)
			}
			return h.extender.ExtendToLevel(ctx, in)
		})
}

func (h *Handler) checkOperation(in *mdl.ExtendOperationScopedRequest) error {
	return h.validate(request{
		family: in.Family,
		fields: []field{text("family", in.Family), {"operationMeta", len(in.OperationMeta) > 0}},
	})
}

func (h *Handler) extendStatus(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_extend_status", 200, h.checkOperation,
		func(ctx context.Context, in *mdl.ExtendOperationScopedRequest) (*mdl.ExtendOperationStatusResponse, error) {
			if h.extender == nil {
				return nil, errNotTracked
			}
			return h.extender.ExtendStatus(ctx, in)
		})
}

func (h *Handler) extendCancel(w http.ResponseWriter, r *http.Request) {
	handle(h, w, r, "content_signing_extend_cancel", 204, h.checkOperation,
		func(ctx context.Context, in *mdl.ExtendOperationScopedRequest) (*struct{}, error) {
			if h.extender == nil {
				return nil, errNotTracked
			}
			return nil, h.extender.ExtendCancel(ctx, in)
		})
}

func (h *Handler) reply(w http.ResponseWriter, r *http.Request, event string, status int, out any, err error) {
	shared.EmitEvent(r.Context(), event, err)
	if err != nil {
		shared.RenderError(w, r, err)
		return
	}
	if status == http.StatusNoContent {
		w.WriteHeader(status)
		return
	}
	if werr := shared.WriteJSON(w, status, out); werr != nil {
		h.LoggerFor(r).Error("write content signing response", "err", werr, "event", event)
	}
}
