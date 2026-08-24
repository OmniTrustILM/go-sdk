package cryptography

import (
	"encoding/base64"
	"strings"
	"unicode/utf8"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// The Cryptography Provider v2 contract carries Jakarta Bean Validation
// constraints that the OpenAPI spec cannot express, and the generated DTOs
// enforce only required-property presence. This file closes that gap.
//
// The remaining constraints need crypto knowledge or the connector's own
// attribute-equality rules, so they are delegated and documented on the
// affected Provider method: publicKeySpki's DER shape and its agreement with
// the declared algorithm and length, MetadataAttribute validation, and
// keyCreationId request-equivalence.

// maxKeyCreationIdLen mirrors the contract's @Size(max = 256) on
// CreateKeyRequestV2Dto.keyCreationId. The spec and Java's @Size count
// characters, so the check counts runes — a multi-byte id must pass on its
// rune count rather than its UTF-8 byte length.
const maxKeyCreationIdLen = 256

// maxRandomDataLength mirrors RandomDataRequestV2Dto.length's documented 1 MiB
// cap. openapi-generator emits no numeric range validation, so an unbounded
// length would otherwise reach a connector's RNG as a resource-exhaustion
// vector.
const maxRandomDataLength = 1048576

// errValidationFailed renders 422 with the contract's VALIDATION_FAILED code,
// built per call so WithProperty context stays request-local.
//
// msg must be a %-free literal describing the violated rule: shared.Invalid is
// printf-style, and echoing request content into an error body discloses
// information.
func errValidationFailed(msg string) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", "%s", msg)
}

// errResponseShape renders 500, treating a response-shape violation as a
// provider bug — the connector returned a body the contract forbids, and
// letting it through would break Core's validation of a supposedly well-formed
// 200/202. msg carries errValidationFailed's %-free-literal requirement.
func errResponseShape(msg string) *shared.Error {
	return shared.Internal("INTERNAL_SERVER_ERROR", "provider response violates the contract: %s", msg)
}

// validateExecutionMode enforces that the caller-selected mode is present
// and known. The connector must not switch modes implicitly, so an unknown
// value is a client error rather than something to default.
//
// In practice shared.DecodeJSON rejects every malformed executionMode before
// the handler runs: an absent property or a non-string value yields 422
// VALIDATION_FAILED, while null (which unmarshals into the empty string) and
// any unknown string are rejected by the generated
// OperationExecutionMode.UnmarshalJSON as 400 INVALID_JSON. This guard is
// therefore a documented invariant and a backstop against that decode behavior
// ever loosening, not a reachable path; validate_test.go exercises it directly.
func validateExecutionMode(m mdl.OperationExecutionMode) error {
	switch m {
	case mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS:
		return nil
	case "":
		return errValidationFailed("executionMode is required")
	default:
		return errValidationFailed("executionMode must be synchronous or asynchronous")
	}
}

// validateModeNotSwitched enforces the contract rule that a connector must not
// switch the caller-selected execution mode: a synchronous request renders 200
// and an asynchronous one renders 202.
//
// Core enforces both directions — OperationResponseValidator requires HTTP 200
// for synchronous and HTTP 202 for asynchronous — so a downgraded 200 is
// rejected there rather than reaching the caller as a usable result. A
// connector that cannot execute asynchronously must decline the feature
// instead, by leaving FEATUREFLAG_ASYNCHRONOUS unadvertised so Core never
// selects the mode.
func validateModeNotSwitched(mode mdl.OperationExecutionMode, accepted bool, what string) error {
	if accepted && mode == mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS {
		return errResponseShape(what + " requested synchronously must not be accepted for asynchronous execution")
	}
	if !accepted && mode == mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS {
		return errResponseShape(what + " requested asynchronously must be accepted for asynchronous execution")
	}
	return nil
}

// validateKeyCreationId enforces the contract's @NotBlank and
// @Size(max = 256) on CreateKeyRequestV2Dto.keyCreationId.
func validateKeyCreationId(id string) error {
	if strings.TrimSpace(id) == "" {
		return errValidationFailed("keyCreationId is required and must not be blank")
	}
	if utf8.RuneCountInString(id) > maxKeyCreationIdLen {
		return errValidationFailed("keyCreationId must not exceed 256 characters")
	}
	return nil
}

// validateUniqueIdentifiers enforces the contract's @UniqueIdentifiers on a
// batch list. field names the offending list in the error message, not any
// request value.
func validateUniqueIdentifiers(ids []string, field string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if _, dup := seen[id]; dup {
			return errValidationFailed(field + " identifiers must be unique within a batch")
		}
		seen[id] = struct{}{}
	}
	return nil
}

// validateNonEmptyBatch enforces the contract's minItems: 1 on a request batch
// list. The generated DTOs verify only that a required property is present, so
// an empty batch decodes cleanly and reaches the provider. field names the
// offending list in the error message, never a request value.
func validateNonEmptyBatch(n int, field string) error {
	if n == 0 {
		return errValidationFailed(field + " must not be empty")
	}
	return nil
}

// validateKeyUsages enforces both constraints every request DTO puts on
// keyUsages: minItems: 1 and uniqueItems: true.
func validateKeyUsages(usages []mdl.KeyUsage) error {
	if err := validateNonEmptyBatch(len(usages), "keyUsages"); err != nil {
		return err
	}
	seen := make(map[mdl.KeyUsage]struct{}, len(usages))
	for _, u := range usages {
		if _, dup := seen[u]; dup {
			return errValidationFailed("keyUsages must not contain duplicates")
		}
		seen[u] = struct{}{}
	}
	return nil
}

// firstError returns the first non-nil error in errs, letting a handler state
// its whole request-guard set as one ordered list.
//
// Every argument is evaluated before the selection, which is safe because the
// guards are pure and cheap. Argument order decides which violation is
// reported, so a guard whose correctness depends on an earlier one must be
// listed after it (see verifyData).
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// validateIdentifiersMatch enforces that two batch lists cover exactly the
// same identifier set — verify's signature identifiers against its
// signed-data identifiers, same set and same size.
func validateIdentifiersMatch(want, got []string, field string) error {
	if len(want) != len(got) {
		return errValidationFailed(field + " identifiers must match the request data identifiers")
	}
	set := make(map[string]struct{}, len(want))
	for _, id := range want {
		set[id] = struct{}{}
	}
	for _, id := range got {
		if _, ok := set[id]; !ok {
			return errValidationFailed(field + " identifiers must match the request data identifiers")
		}
	}
	return nil
}

// validateBatchItems enforces the contract's @NotBlank on each batch item's
// identifier and @NotEmpty on its data, which the generated DTOs leave
// unchecked because both fields decode cleanly when present but empty.
func validateBatchItems(ids []string, data []string, field string) error {
	for i, id := range ids {
		if strings.TrimSpace(id) == "" {
			return errValidationFailed(field + " identifiers must not be blank")
		}
		if data[i] == "" {
			return errValidationFailed(field + " entries must not carry empty data")
		}
	}
	return nil
}

// validateResponseIdentifiers enforces that a batch response covers exactly the
// request's identifier set, with no duplicates. Core applies the same rule and
// rejects the response otherwise, so a mismatch is reported here as a provider
// bug rather than passed on.
func validateResponseIdentifiers(want, got []string, what string) error {
	seen := make(map[string]struct{}, len(got))
	for _, id := range got {
		if _, dup := seen[id]; dup {
			return errResponseShape(what + " response identifiers must be unique")
		}
		seen[id] = struct{}{}
	}
	if len(want) != len(got) {
		return errResponseShape(what + " response identifiers must match the request identifiers")
	}
	for _, id := range want {
		if _, ok := seen[id]; !ok {
			return errResponseShape(what + " response identifiers must match the request identifiers")
		}
	}
	return nil
}

// validateResponseBatch adds the contract's @NotEmpty on each item's data to
// validateResponseIdentifiers. Core rejects an empty payload even when every
// identifier lines up.
func validateResponseBatch(want, got, data []string, what string) error {
	if err := validateResponseIdentifiers(want, got, what); err != nil {
		return err
	}
	for _, d := range data {
		if d == "" {
			return errResponseShape(what + " response entries must not carry empty data")
		}
	}
	return nil
}

// validateResponseItemIdentifiers enforces @NotBlank and @UniqueIdentifiers on
// the sign-status response, whose request carries only an operationMeta handle
// to correlate against.
func validateResponseItemIdentifiers(ids []string, what string) error {
	seen := make(map[string]struct{}, len(ids))
	for _, id := range ids {
		if strings.TrimSpace(id) == "" {
			return errResponseShape(what + " response identifiers must not be blank")
		}
		if _, dup := seen[id]; dup {
			return errResponseShape(what + " response identifiers must be unique")
		}
		seen[id] = struct{}{}
	}
	return nil
}

// validateRandomDataPayload enforces that a random-data response decodes to
// exactly the requested number of bytes. Core compares the decoded length
// against the request, so a short or long payload is a provider bug.
func validateRandomDataPayload(data string, want int32) error {
	raw, err := base64.StdEncoding.DecodeString(data)
	if err != nil {
		return errResponseShape("random data must be valid base64")
	}
	if int64(len(raw)) != int64(want) {
		return errResponseShape("random data length must match the requested length")
	}
	return nil
}

// validateRequestedKeyRequestType enforces that a key-creation response names
// the same key request type the caller asked for. Core rejects a response whose
// type differs from the request's, so answering a secret request with a key
// pair is a provider bug.
func validateRequestedKeyRequestType(got, want mdl.KeyRequestType) error {
	if got != want {
		return errResponseShape("keyRequestType must match the requested key request type")
	}
	return nil
}

// keyCreationRequestType reports the key request type the populated arm of a
// key-creation response represents, independently of the discriminator the arm
// carries. Empty when no arm is populated, which the shape guards report first.
func keyCreationRequestType(out *mdl.KeyCreationResponse) mdl.KeyRequestType {
	if out.SecretKeyDataResponseV2Dto != nil {
		return mdl.KEYREQUESTTYPE_SECRET
	}
	if out.KeyPairDataResponseV2Dto != nil {
		return mdl.KEYREQUESTTYPE_KEY_PAIR
	}
	return ""
}

// validateRandomDataLength enforces that RandomDataRequestV2Dto.length is
// positive and does not exceed the spec's documented 1 MiB cap.
func validateRandomDataLength(length int32) error {
	if length <= 0 {
		return errValidationFailed("length must be positive")
	}
	if length > maxRandomDataLength {
		return errValidationFailed("length must not exceed 1048576 bytes")
	}
	return nil
}

// validateExecutionShape enforces the mode-dependent response shape the
// contract expresses as Jakarta validation groups: an accepted (202) response
// carries a non-empty tracking handle and no payload; a synchronous (200)
// response carries the payload and no handle.
//
// hasPayload answers a different question per branch — "any payload fragment
// present" for accepted, "complete payload present" for synchronous. One
// boolean serves both only where the response type has a single payload field,
// as SignDataResponseV2Dto does; see validateKeyCreationShape for the
// multi-field case.
func validateExecutionShape(accepted, hasMeta, hasPayload bool, what string) error {
	if accepted {
		if !hasMeta {
			return errResponseShape(what + " accepted for asynchronous execution must carry operationMeta")
		}
		if hasPayload {
			return errResponseShape(what + " accepted for asynchronous execution must not carry a result payload")
		}
		return nil
	}
	if hasMeta {
		return errResponseShape(what + " completed synchronously must not carry operationMeta")
	}
	if !hasPayload {
		return errResponseShape(what + " completed synchronously must carry a result payload")
	}
	return nil
}

// validateStatusReason enforces the contract's reason-presence rule: a
// non-blank reason accompanies failed and cancelled, and is absent for
// inProgress and completed. reason is a pointer because the rule turns on
// presence — an empty string still serializes as "reason":"".
//
// Use validateStatusShape for DTOs that also carry a result field.
func validateStatusReason(status mdl.OperationStatus, reason *string) error {
	switch status {
	case mdl.OPERATIONSTATUS_FAILED, mdl.OPERATIONSTATUS_CANCELLED:
		if reason == nil || strings.TrimSpace(*reason) == "" {
			return errResponseShape("reason is required when status is failed or cancelled")
		}
	case mdl.OPERATIONSTATUS_IN_PROGRESS, mdl.OPERATIONSTATUS_COMPLETED:
		if reason != nil {
			return errResponseShape("reason must be absent unless status is failed or cancelled")
		}
	default:
		return errResponseShape("unknown operation status")
	}
	return nil
}

// validateStatusShape layers the result-presence rule on validateStatusReason:
// a result is present exactly when the status is completed. Requires a DTO
// that carries a result field.
func validateStatusShape(status mdl.OperationStatus, reason *string, hasResult bool) error {
	if err := validateStatusReason(status, reason); err != nil {
		return err
	}
	switch status {
	case mdl.OPERATIONSTATUS_FAILED, mdl.OPERATIONSTATUS_CANCELLED, mdl.OPERATIONSTATUS_IN_PROGRESS:
		if hasResult {
			return errResponseShape("result must be absent unless status is completed")
		}
	case mdl.OPERATIONSTATUS_COMPLETED:
		if !hasResult {
			return errResponseShape("result is required when status is completed")
		}
	}
	return nil
}

// validateDestroyShape is the destroy-key counterpart to
// validateExecutionShape, covering the operationMeta rule alone:
// KeyOperationResponseV2Dto carries operationMeta and no payload field. The
// spec states both directions — operationMeta is required and non-empty when
// accepting asynchronous execution, and absent from a synchronous response.
func validateDestroyShape(accepted, hasMeta bool) error {
	if accepted && !hasMeta {
		return errResponseShape("key destruction accepted for asynchronous execution must carry operationMeta")
	}
	if !accepted && hasMeta {
		return errResponseShape("key destruction completed synchronously must not carry operationMeta")
	}
	return nil
}

// validateKeyCreationShape is createKey's mode-dependent response-shape guard.
// KeyCreationResponse spreads its payload over several fields, so each branch
// needs its own predicate: the accepted branch rejects any fragment
// (keyCreationHasPayload), while the synchronous branch requires a complete
// and usable payload (validateKeyCreationPayload).
//
// Both branches first require exactly one populated arm carrying a matching
// keyRequestType discriminator.
func validateKeyCreationShape(accepted bool, out *mdl.KeyCreationResponse) error {
	if err := validateSingleKeyCreationArm(out); err != nil {
		return err
	}
	if err := validateKeyRequestType(keyCreationDiscriminator(out)); err != nil {
		return err
	}
	hasMeta := keyCreationHasMeta(out)
	if accepted {
		if !hasMeta {
			return errResponseShape("key creation accepted for asynchronous execution must carry operationMeta")
		}
		if keyCreationHasPayload(out) {
			return errResponseShape("key creation accepted for asynchronous execution must not carry a result payload")
		}
		return nil
	}
	if hasMeta {
		return errResponseShape("key creation completed synchronously must not carry operationMeta")
	}
	return validateKeyCreationPayload(out)
}

// keyCreationHasPayload reports whether the populated oneOf variant carries any
// fragment of a created-key result. This is the accepted (202) branch's test,
// where a single leftover fragment is already a violation.
func keyCreationHasPayload(out *mdl.KeyCreationResponse) bool {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		return v.KeyData != nil || len(v.KeyMeta) > 0
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		return v.PublicKeyData != nil || v.PrivateKeyData != nil || len(v.KeyPairMeta) > 0
	}
	return false
}

// validateKeyCreationPayload is the synchronous (200) branch's payload guard:
// every fragment the contract requires, with a usable descriptor behind it.
// Core rejects an empty nested DTO.
func validateKeyCreationPayload(out *mdl.KeyCreationResponse) error {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		if v.KeyData == nil || len(v.KeyMeta) == 0 {
			return errIncompleteKeyPayload()
		}
		return validateKeyDescriptor(v.KeyData.Type, v.KeyData.Algorithm, v.KeyData.Length, "keyData")
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		if v.PublicKeyData == nil || v.PrivateKeyData == nil || len(v.KeyPairMeta) == 0 {
			return errIncompleteKeyPayload()
		}
		return validateKeyPairPayload(v)
	}
	return errIncompleteKeyPayload()
}

func errIncompleteKeyPayload() error {
	return errResponseShape("key creation completed synchronously must carry a result payload")
}

// validateKeyPairPayload covers the key-pair arm's own rules: each side's
// keyMeta and descriptor, the public SPKI, and the contract's assertion that
// both halves describe the same algorithm and length.
//
// The SPKI is checked for presence only; parsing it is the connector's job.
func validateKeyPairPayload(v *mdl.KeyPairDataResponseV2Dto) error {
	if len(v.PublicKeyData.KeyMeta) == 0 || len(v.PrivateKeyData.KeyMeta) == 0 {
		return errIncompleteKeyPayload()
	}
	pub, priv := &v.PublicKeyData.KeyData, &v.PrivateKeyData.KeyData
	if err := firstError(
		validateKeyDescriptor(pub.Type, pub.Algorithm, pub.Length, "publicKeyData.keyData"),
		validateKeyDescriptor(priv.Type, priv.Algorithm, priv.Length, "privateKeyData.keyData"),
	); err != nil {
		return err
	}
	if pub.PublicKeySpki == "" {
		return errResponseShape("publicKeyData.keyData must carry publicKeySpki")
	}
	if pub.Algorithm != priv.Algorithm {
		return errResponseShape("public and private key algorithms must match")
	}
	if pub.Length != priv.Length {
		return errResponseShape("public and private key lengths must match")
	}
	return nil
}

// validateKeyDescriptor enforces the key descriptor's required fields. The
// generated struct leaves type as a bare string, so an unset one decodes to ""
// and reaches Core as an unresolvable discriminator.
func validateKeyDescriptor(keyType string, algorithm mdl.KeyAlgorithm, length int32, field string) error {
	if keyType == "" {
		return errResponseShape(field + " must carry a key type")
	}
	if !algorithm.IsValid() {
		return errResponseShape(field + " must carry a known key algorithm")
	}
	if length <= 0 {
		return errResponseShape(field + " must carry a positive key length")
	}
	return nil
}

// keyCreationHasMeta reports whether the populated oneOf variant carries an
// operationMeta tracking handle. KeyCreationResponse is a oneOf wrapper, so
// this reaches into whichever variant is set.
func keyCreationHasMeta(out *mdl.KeyCreationResponse) bool {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		return len(v.OperationMeta) > 0
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		return len(v.OperationMeta) > 0
	}
	return false
}

// validateKeyRequestType enforces the wire discriminator both key-creation
// oneOf wrappers are resolved by. The generated structs tag keyRequestType
// without omitempty, so an unset one emits "keyRequestType":"" — not a member
// of the enum, leaving Core unable to pick a variant and rejecting an
// otherwise well-formed 200/202. A value disagreeing with the populated arm is
// equally unresolvable, so both halves are checked.
//
// got is the discriminator the populated arm carries; want is the value that
// arm must carry, or "" when no arm was populated, which the payload and
// status guards report in their own terms.
func validateKeyRequestType(got, want mdl.KeyRequestType) error {
	if want == "" {
		return nil
	}
	if got == "" {
		return errResponseShape("keyRequestType is required on the populated key data variant")
	}
	if got != want {
		return errResponseShape("keyRequestType must match the populated key data variant")
	}
	return nil
}

// validateSingleKeyCreationArm rejects a key-creation response wrapper with
// more than one oneOf arm populated. Such a wrapper is unvalidatable: the
// generated MarshalJSON serializes the key-pair arm first while every helper
// here inspects the secret arm first, so validation would approve one arm
// while the wire carried the other, unchecked.
//
// The payload guards report a wrapper with zero arms in their own terms.
func validateSingleKeyCreationArm(out *mdl.KeyCreationResponse) error {
	if out.SecretKeyDataResponseV2Dto != nil && out.KeyPairDataResponseV2Dto != nil {
		return errResponseShape("exactly one key data variant may be populated")
	}
	return nil
}

// validateSingleKeyCreationStatusArm is validateSingleKeyCreationArm's
// counterpart for the status wrapper, whose generated MarshalJSON has the same
// key-pair-first ordering.
func validateSingleKeyCreationStatusArm(out *mdl.KeyCreationStatusResponse) error {
	if out.SecretKeyOperationStatusResponseV2Dto != nil && out.KeyPairOperationStatusResponseV2Dto != nil {
		return errResponseShape("exactly one key status variant may be populated")
	}
	return nil
}

// keyCreationDiscriminator reports the keyRequestType the populated arm of a
// key-creation response carries, together with the value that arm is
// required to carry. Both are "" when neither arm is set.
func keyCreationDiscriminator(out *mdl.KeyCreationResponse) (got, want mdl.KeyRequestType) {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		return v.KeyRequestType, mdl.KEYREQUESTTYPE_SECRET
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		return v.KeyRequestType, mdl.KEYREQUESTTYPE_KEY_PAIR
	}
	return "", ""
}

// keyCreationStatusDiscriminator is keyCreationDiscriminator's counterpart
// for the status wrapper, whose two arms carry the same required
// discriminator.
func keyCreationStatusDiscriminator(out *mdl.KeyCreationStatusResponse) (got, want mdl.KeyRequestType) {
	if v := out.SecretKeyOperationStatusResponseV2Dto; v != nil {
		return v.KeyRequestType, mdl.KEYREQUESTTYPE_SECRET
	}
	if v := out.KeyPairOperationStatusResponseV2Dto; v != nil {
		return v.KeyRequestType, mdl.KEYREQUESTTYPE_KEY_PAIR
	}
	return "", ""
}

func signHasPayload(out *mdl.SignDataResponseV2Dto) bool {
	return len(out.Signatures) > 0
}

// validateSignatureResultItem enforces SignatureResultItemV2Dto's per-item
// consistency rule, which pairs the status/result shape with a non-empty
// signature on a completed item.
func validateSignatureResultItem(item mdl.SignatureResultItemV2Dto) error {
	if err := validateStatusShape(item.Status, item.Reason, item.Signature != nil); err != nil {
		return err
	}
	if item.Status == mdl.OPERATIONSTATUS_COMPLETED && *item.Signature == "" {
		return errResponseShape("signature must not be empty when status is completed")
	}
	return nil
}

// keyCreationStatusShape extracts the status, reason and result-presence used
// by validateStatusShape from whichever oneOf variant of
// KeyCreationStatusResponse is populated. An empty status reports a malformed
// response with neither variant set, which validateStatusShape rejects.
func keyCreationStatusShape(out *mdl.KeyCreationStatusResponse) (status mdl.OperationStatus, reason *string, hasResult bool) {
	if v := out.SecretKeyOperationStatusResponseV2Dto; v != nil {
		return v.Status, v.Reason, v.Result != nil
	}
	if v := out.KeyPairOperationStatusResponseV2Dto; v != nil {
		return v.Status, v.Reason, v.Result != nil
	}
	return "", nil, false
}

// validateKeyCreationStatusShape is createKeyStatus's full response-shape
// guard: exactly one populated arm, its keyRequestType discriminator, the
// status/reason/result rules, and finally the completed result's own shape.
//
// A completed result is a full created-key payload of the same type a
// synchronous creation returns, so it is held to the same rules. Presence
// alone would admit a result whose discriminator is unset or mismatched, whose
// key payload is incomplete, or which carries a forbidden operationMeta —
// Core can consume none of these.
func validateKeyCreationStatusShape(out *mdl.KeyCreationStatusResponse) error {
	if err := validateSingleKeyCreationStatusArm(out); err != nil {
		return err
	}
	if err := validateKeyRequestType(keyCreationStatusDiscriminator(out)); err != nil {
		return err
	}
	status, reason, hasResult := keyCreationStatusShape(out)
	if err := validateStatusShape(status, reason, hasResult); err != nil {
		return err
	}
	if result := keyCreationStatusResult(out); result != nil {
		return validateKeyCreationShape(false, result)
	}
	return nil
}

// keyCreationStatusResult wraps a status response's completed result in the
// initial-response oneOf wrapper, so the synchronous-creation rules apply to
// it verbatim. Returns nil for every non-completed status.
func keyCreationStatusResult(out *mdl.KeyCreationStatusResponse) *mdl.KeyCreationResponse {
	if v := out.SecretKeyOperationStatusResponseV2Dto; v != nil && v.Result != nil {
		return &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: v.Result}
	}
	if v := out.KeyPairOperationStatusResponseV2Dto; v != nil && v.Result != nil {
		return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: v.Result}
	}
	return nil
}

// signatureDataIdentifiers extracts the identifier field of each batch
// element, for validateUniqueIdentifiers and validateIdentifiersMatch.
func signatureDataIdentifiers(data []mdl.SignatureDataV2Dto) []string {
	ids := make([]string, len(data))
	for i, d := range data {
		ids[i] = d.Identifier
	}
	return ids
}

// cipherDataIdentifiers is signatureDataIdentifiers' counterpart for the
// encrypt/decrypt batch element type.
func cipherDataIdentifiers(data []mdl.CipherDataV2Dto) []string {
	ids := make([]string, len(data))
	for i, d := range data {
		ids[i] = d.Identifier
	}
	return ids
}

// verificationIdentifiers is signatureDataIdentifiers' counterpart for the
// verify response element type.
func verificationIdentifiers(items []mdl.VerificationResponseItemV2Dto) []string {
	ids := make([]string, len(items))
	for i, v := range items {
		ids[i] = v.Identifier
	}
	return ids
}

// signatureDataPayloads extracts the data field of each batch element, for
// validateBatchItems.
func signatureDataPayloads(data []mdl.SignatureDataV2Dto) []string {
	out := make([]string, len(data))
	for i, d := range data {
		out[i] = d.Data
	}
	return out
}

// cipherDataPayloads is signatureDataPayloads' counterpart for the
// encrypt/decrypt batch element type.
func cipherDataPayloads(data []mdl.CipherDataV2Dto) []string {
	out := make([]string, len(data))
	for i, d := range data {
		out[i] = d.Data
	}
	return out
}

// signatureResultIdentifiers extracts the identifier field of each sign-status
// item, for validateResponseItemIdentifiers.
func signatureResultIdentifiers(items []mdl.SignatureResultItemV2Dto) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.Identifier
	}
	return out
}
