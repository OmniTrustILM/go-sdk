package contentsigning

import "github.com/OmniTrustILM/go-sdk/connector/shared"

// ParameterUnsupported is a request for a family, transfer mode, signature
// algorithm or level the connector does not serve. Name what it serves.
func ParameterUnsupported(format string, a ...any) *shared.Error {
	return shared.Invalid("PARAMETER_UNSUPPORTED", format, a...)
}

// AttributesRejected is attribute values the connector cannot accept.
func AttributesRejected(format string, a ...any) *shared.Error {
	return shared.Invalid("ATTRIBUTES_REJECTED", format, a...)
}

// DocumentMalformed is a document or formatting context the connector cannot read.
func DocumentMalformed(format string, a ...any) *shared.Error {
	return shared.Invalid("DOCUMENT_MALFORMED", format, a...)
}

// ContextMismatch is a signature algorithm that disagrees with the formatting context.
func ContextMismatch(format string, a ...any) *shared.Error {
	return shared.Invalid("CONTEXT_MISMATCH", format, a...)
}

// ValidationFailed is a request with a missing or invalid field.
func ValidationFailed(format string, a ...any) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", format, a...)
}

var (
	errNotTracked  = shared.NotFound("OPERATION_NOT_TRACKED", "no extend operation is tracked for this family")
	errNilResponse = shared.Internal("INTERNAL_SERVER_ERROR", "provider returned no response")
)
