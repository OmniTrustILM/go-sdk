package contentsigning

import (
	"encoding/json"
	"errors"
	"io"
	"net/http"
	"slices"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// field is a required request field and whether the request carries it.
type field struct {
	name string
	ok   bool
}

func text(name, value string) field { return field{name, value != ""} }

// request gathers what the handler checks of every request: required fields
// first, then the family, the transfer mode and the signature algorithm
// against the declaration. An empty mode or algorithm means the request
// carries none.
type request struct {
	family    string
	fields    []field
	mode      mdl.DocumentTransferMode
	algorithm mdl.SignatureAlgorithm
}

func (h *Handler) validate(q request) error {
	for _, f := range q.fields {
		if !f.ok {
			return ValidationFailed("%s must not be empty", f.name)
		}
	}
	if !familyCode.MatchString(q.family) {
		return ValidationFailed("family %q must match %s", q.family, familyCode)
	}
	fam := h.decl.family
	if q.family != fam.Code {
		return ParameterUnsupported("family %q is not supported; supported: %s", q.family, fam.Code)
	}
	if q.mode != "" && !slices.Contains(fam.TransferModes, q.mode) {
		return ParameterUnsupported("transfer mode %q is not supported; supported: %v", q.mode, fam.TransferModes)
	}
	if q.algorithm != "" && len(fam.SignatureAlgorithms) > 0 && !slices.Contains(fam.SignatureAlgorithms, q.algorithm) {
		return ParameterUnsupported("signature algorithm %q is not supported; supported: %v", q.algorithm, fam.SignatureAlgorithms)
	}
	return nil
}

func (h *Handler) checkComputeDtbs(in *mdl.ComputeDtbsRequest) error {
	mode, err := documentMode("document", &in.Document)
	if err != nil {
		return err
	}
	return h.validate(request{
		family: in.Family,
		fields: []field{
			text("family", in.Family),
			{"signerCertificateChain", len(in.SignerCertificateChain) > 0},
			{"signingTime", !in.SigningTime.IsZero()},
		},
		mode:      mode,
		algorithm: in.SignatureAlgorithm,
	})
}

func (h *Handler) checkEmbedSignatureValue(in *mdl.EmbedSignatureValueRequest) error {
	return h.validate(request{
		family: in.Family,
		fields: []field{
			text("family", in.Family),
			text("signatureValue", in.SignatureValue),
		},
		algorithm: in.SignatureAlgorithm,
	})
}

// checkSigned checks a request on a signed document, which may carry the
// detached content it signs.
func (h *Handler) checkSigned(family, signedDocument string, detached *mdl.DocumentTransfer, more ...field) error {
	var mode mdl.DocumentTransferMode
	if detached != nil {
		var err error
		if mode, err = documentMode("detachedContent", detached); err != nil {
			return err
		}
	}
	return h.validate(request{
		family: family,
		fields: append([]field{text("family", family), text("signedDocument", signedDocument)}, more...),
		mode:   mode,
	})
}

// checkFamilyOnly checks a request that carries nothing but the family.
func (h *Handler) checkFamilyOnly(family string) error {
	return h.validate(request{family: family, fields: []field{text("family", family)}})
}

// documentMode reads the transfer mode of a document and checks that the
// document carries what the mode needs.
func documentMode(name string, d *mdl.DocumentTransfer) (mdl.DocumentTransferMode, error) {
	switch {
	case d.InlineDocumentTransfer != nil:
		if d.InlineDocumentTransfer.Document == "" {
			return "", ValidationFailed("%s.document must not be empty", name)
		}
		return mdl.DOCUMENTTRANSFERMODE_INLINE, nil
	case d.DigestOnlyDocumentTransfer != nil:
		if d.DigestOnlyDocumentTransfer.DocumentDigest == "" {
			return "", ValidationFailed("%s.documentDigest must not be empty", name)
		}
		return mdl.DOCUMENTTRANSFERMODE_DIGEST_ONLY, nil
	default:
		return "", shared.BadRequest("BAD_REQUEST", "%s must carry a transferMode of inline or digestOnly", name)
	}
}

// decode reads a request body. A body that is not JSON is 400 BAD_REQUEST; a
// body that is JSON but not a valid request is 422 VALIDATION_FAILED.
func (h *Handler) decode(w http.ResponseWriter, r *http.Request, v any) error {
	err := shared.DecodeJSON(w, r, v, h.MaxBytes, h.Strict)
	var se *shared.Error
	if !errors.As(err, &se) {
		return err
	}
	if se.Status == http.StatusBadRequest && se.Cause != nil && isTransferModeError(se.Cause) {
		return shared.BadRequest("BAD_REQUEST", "a document must carry a transferMode of inline or digestOnly").WithCause(err)
	}
	if se.Status == http.StatusBadRequest && (se.ErrorCode != "INVALID_JSON" || se.Cause == nil || isSyntaxError(se.Cause)) {
		return shared.BadRequest("BAD_REQUEST", "%s", se.Detail).WithCause(err)
	}
	if name, ok := se.Properties["field"]; ok {
		return ValidationFailed("%s: %v", se.Detail, name).WithCause(err)
	}
	return ValidationFailed("%s", se.Detail).WithCause(err)
}

// isSyntaxError reports whether a decode failed on the JSON itself rather than
// on a generated decoder rejecting a well-formed value.
func isSyntaxError(err error) bool {
	var syntaxErr *json.SyntaxError
	return errors.As(err, &syntaxErr) || errors.Is(err, io.ErrUnexpectedEOF)
}

// isTransferModeError reports whether a decode failed on a document transfer
// whose transferMode is absent or unknown, which the contract treats as an
// unreadable body.
func isTransferModeError(err error) bool {
	return strings.Contains(err.Error(), "DocumentTransfer: unknown transferMode")
}

func (h *Handler) unsupportedLevel(level mdl.SignatureLevel) error {
	return ParameterUnsupported("the %s level is not supported: family %q does not declare it", level, h.decl.family.Code)
}
