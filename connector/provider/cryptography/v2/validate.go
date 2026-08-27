package cryptography

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"unicode/utf8"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// The spec declares minItems, uniqueItems, minLength, maxLength, minimum and
// maximum on its schemas, and the Java DTOs add cross-field @AssertTrue rules.
// The openapi-generator Go template drops all of them, so this file hand-writes
// the checks; a generator-level pass like the one tools/fixoneof does for pins
// is where they eventually belong.
//
// Checks that need crypto knowledge or connector-specific attribute equality
// are delegated to the Provider methods and documented there.

// maxKeyCreationIdLen mirrors the spec's maxLength: 256 on keyCreationId. JSON
// Schema maxLength counts code points, so the check counts runes; Java's @Size
// counts UTF-16 code units, so Core may still reject supplementary-plane ids.
const maxKeyCreationIdLen = 256

// maxRandomDataLength mirrors RandomDataRequestV2Dto.length's documented 1 MiB
// cap, which the generated DTO does not enforce.
const maxRandomDataLength = 1048576

// errValidationFailed renders 422 VALIDATION_FAILED. msg must be a %-free
// literal naming the violated rule: shared.Invalid is printf-style, and echoing
// request content into an error body discloses information.
func errValidationFailed(msg string) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", "%s", msg)
}

// errResponseShape renders 500 for a response body the contract forbids and
// Core would reject. msg follows errValidationFailed's literal rule.
func errResponseShape(msg string) *shared.Error {
	return shared.Internal("INTERNAL_SERVER_ERROR", "provider response violates the contract: %s", msg)
}

// validateExecutionMode rejects a missing mode with 422 VALIDATION_FAILED and an
// unknown one with 400 BAD_REQUEST, the codes the contract documents.
//
// shared.DecodeJSON already rejects both cases before the handler runs (the
// generated OperationExecutionMode.UnmarshalJSON answers unknown values with
// 400 INVALID_JSON), so this guard is a backstop; validate_test.go exercises
// it directly.
func validateExecutionMode(m mdl.OperationExecutionMode) error {
	switch m {
	case mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS:
		return nil
	case "":
		return errValidationFailed("executionMode is required")
	default:
		return shared.BadRequest("BAD_REQUEST", "executionMode must be synchronous or asynchronous")
	}
}

// validateModeNotSwitched enforces that a synchronous request renders 200 and
// an asynchronous one 202. Core's OperationResponseValidator requires both
// directions, so a switched mode is a provider bug; a connector that cannot
// execute asynchronously must leave FEATUREFLAG_ASYNCHRONOUS unadvertised.
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
// batch list. field names the list in the error message.
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

// validateNonEmptyBatch enforces the contract's minItems: 1, which the generated
// DTOs do not. field names the list in the error message.
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

// firstError returns the first non-nil error in errs, so a handler states its
// request guards as one ordered list. All arguments are evaluated eagerly; the
// guards are pure and cheap, and none depends on an earlier one.
func firstError(errs ...error) error {
	for _, err := range errs {
		if err != nil {
			return err
		}
	}
	return nil
}

// sameMultiset reports whether got is a permutation of want, so duplicates on
// either side are detected without a preceding uniqueness guard.
func sameMultiset(want, got []string) bool {
	if len(want) != len(got) {
		return false
	}
	counts := make(map[string]int, len(want))
	for _, id := range want {
		counts[id]++
	}
	for _, id := range got {
		counts[id]--
		if counts[id] < 0 {
			return false
		}
	}
	return true
}

// validateIdentifiersMatch enforces that two batch lists carry the same
// identifiers, such as verify's signatures against its signed data.
func validateIdentifiersMatch(want, got []string, field string) error {
	if !sameMultiset(want, got) {
		return errValidationFailed(field + " identifiers must match the request data identifiers")
	}
	return nil
}

// validateBatchItems enforces @NotBlank on each item's identifier and @NotEmpty
// on its data. ids and data are paired projections of one list, so unequal
// lengths are rejected instead of indexed.
func validateBatchItems(ids []string, data []string, field string) error {
	if len(ids) != len(data) {
		return errValidationFailed(field + " entries are malformed")
	}
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
// request's identifiers, with no duplicates, as Core requires.
func validateResponseIdentifiers(want, got []string, what string) error {
	seen := make(map[string]struct{}, len(got))
	for _, id := range got {
		if _, dup := seen[id]; dup {
			return errResponseShape(what + " response identifiers must be unique")
		}
		seen[id] = struct{}{}
	}
	if !sameMultiset(want, got) {
		return errResponseShape(what + " response identifiers must match the request identifiers")
	}
	return nil
}

// validateResponse rejects a nil response, which would serialize as a 200 with
// a null body, runs check against it, and finally probes that the response
// encodes at all.
func validateResponse[T any](out *T, check func(*T) error) error {
	if out == nil {
		return ErrNilResponse
	}
	if err := check(out); err != nil {
		return err
	}
	return validateEncodable(out)
}

// validateEncodable marshals v and rejects anything encoding/json refuses: an
// unset oneOf wrapper at any depth (the generated MarshalJSON returns
// (nil, nil)), or a NaN or func in an AdditionalProperties map.
// shared.WriteJSON commits the status before encoding, so without this probe
// such a response reaches Core as a 2xx with an empty body.
func validateEncodable(v any) error {
	if _, err := json.Marshal(v); err != nil {
		return errResponseShape("response cannot be encoded as JSON").WithCause(err)
	}
	return nil
}

// validateKnownEnums enforces that every element of a response enum list is a
// member of its enum; the generated types are bare strings.
func validateKnownEnums[T interface{ IsValid() bool }](values []T, what string) error {
	for _, v := range values {
		if !v.IsValid() {
			return errResponseShape(what + " must contain only known values")
		}
	}
	return nil
}

// validateTokenStatus enforces that the response carries a known status; the
// field is tagged without omitempty, so a zero value would ship as "".
func validateTokenStatus(out *mdl.TokenStatusResponseV2Dto) error {
	if !out.Status.IsValid() {
		return errResponseShape("token status must be a known token status")
	}
	return nil
}

// validateMetadataElements enforces that every MetadataAttribute populates
// exactly one oneOf arm, naming the offending list. validateEncodable catches
// the same defect anywhere else in the tree with a generic message.
func validateMetadataElements(as []mdl.MetadataAttribute, field string) error {
	for _, a := range as {
		if (a.MetadataAttributeV2 == nil) == (a.MetadataAttributeV3 == nil) {
			return errResponseShape(field + " entries must populate exactly one metadata attribute variant")
		}
	}
	return nil
}

// validateResponseBatch adds @NotEmpty on each item's data to
// validateResponseIdentifiers.
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
// the sign-status response, which has no request identifiers to correlate with.
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

// validateRandomDataPayload enforces that the response decodes to exactly the
// requested number of bytes, as Core checks. The decode is what makes the byte
// count knowable; it requires standard padded base64, the encoding Java emits.
// Sign, encrypt and decrypt payloads are not decoded here; Core decodes them.
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
// the key request type the caller asked for, as Core requires.
func validateRequestedKeyRequestType(got, want mdl.KeyRequestType) error {
	if got != want {
		return errResponseShape("keyRequestType must match the requested key request type")
	}
	return nil
}

// keyCreationRequestType reports the key request type of the populated arm,
// independently of its discriminator. Empty when no arm is populated.
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

// validateExecutionShape enforces the mode-dependent shape the contract
// expresses as Jakarta validation groups: a 202 carries a non-empty tracking
// handle and no payload, a 200 the payload and no handle.
//
// hasPayload means "any fragment" for accepted and "complete payload" for
// synchronous, which coincide only for a single payload field as in
// SignDataResponseV2Dto; see validateKeyCreationShape for the multi-field case.
//
// The spec text for SignDataResponseV2Dto states only the accepted direction,
// but the Java DTO carries @Null on operationMeta for the synchronous group, so
// Core rejects a synchronous signing response with a handle too.
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

// validateStatusReason enforces that a non-blank reason accompanies failed and
// cancelled and is absent otherwise. reason is a pointer because the rule turns
// on presence. Use validateStatusShape for DTOs that also carry a result.
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

// validateStatusShape adds to validateStatusReason that a result is present
// exactly when the status is completed.
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

// validateDestroyShape enforces the operationMeta rule alone, as
// KeyOperationResponseV2Dto has no payload field: required and non-empty on
// 202, absent on 200.
func validateDestroyShape(accepted, hasMeta bool) error {
	if accepted && !hasMeta {
		return errResponseShape("key destruction accepted for asynchronous execution must carry operationMeta")
	}
	if !accepted && hasMeta {
		return errResponseShape("key destruction completed synchronously must not carry operationMeta")
	}
	return nil
}

// validateKeyCreationShape is createKey's mode-dependent response guard. The
// payload spans several fields, so the accepted branch rejects any fragment
// (keyCreationHasPayload) while the synchronous branch requires a complete
// payload (validateKeyCreationPayload). A completed result nested in a status
// response is held to the synchronous rules by validateKeyCreationStatusShape.
func validateKeyCreationShape(accepted bool, out *mdl.KeyCreationResponse) error {
	if err := validateKeyCreationCommon(out); err != nil {
		return err
	}
	if accepted {
		if !keyCreationHasMeta(out) {
			return errResponseShape("key creation accepted for asynchronous execution must carry operationMeta")
		}
		if keyCreationHasPayload(out) {
			return errResponseShape("key creation accepted for asynchronous execution must not carry a result payload")
		}
		return nil
	}
	return validateSynchronousKeyCreation(out, "key creation completed synchronously")
}

// validateKeyCreationCommon holds the mode-independent rules: exactly one
// populated arm, a matching discriminator, and marshallable metadata elements.
func validateKeyCreationCommon(out *mdl.KeyCreationResponse) error {
	if err := validateSingleKeyCreationArm(out); err != nil {
		return err
	}
	if err := validateKeyRequestType(keyCreationDiscriminator(out)); err != nil {
		return err
	}
	return validateKeyCreationMetadata(out)
}

// validateSynchronousKeyCreation enforces the 200 branch: no tracking handle
// and a complete payload. subject names the payload in the messages.
func validateSynchronousKeyCreation(out *mdl.KeyCreationResponse, subject string) error {
	if keyCreationHasMeta(out) {
		return errResponseShape(subject + " must not carry operationMeta")
	}
	return validateKeyCreationPayload(out, subject)
}

// validateKeyCreationMetadata applies validateMetadataElements to every
// metadata list the populated arm carries, the key descriptors' included.
func validateKeyCreationMetadata(out *mdl.KeyCreationResponse) error {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		if err := firstError(
			validateMetadataElements(v.OperationMeta, "operationMeta"),
			validateMetadataElements(v.KeyMeta, "keyMeta"),
		); err != nil {
			return err
		}
		if v.KeyData != nil {
			return validateMetadataElements(v.KeyData.Metadata, "keyData.metadata")
		}
		return nil
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		if err := firstError(
			validateMetadataElements(v.OperationMeta, "operationMeta"),
			validateMetadataElements(v.KeyPairMeta, "keyPairMeta"),
		); err != nil {
			return err
		}
		if v.PublicKeyData != nil {
			if err := firstError(
				validateMetadataElements(v.PublicKeyData.KeyMeta, "publicKeyData.keyMeta"),
				validateMetadataElements(v.PublicKeyData.KeyData.Metadata, "publicKeyData.keyData.metadata"),
			); err != nil {
				return err
			}
		}
		if v.PrivateKeyData != nil {
			return firstError(
				validateMetadataElements(v.PrivateKeyData.KeyMeta, "privateKeyData.keyMeta"),
				validateMetadataElements(v.PrivateKeyData.KeyData.Metadata, "privateKeyData.keyData.metadata"),
			)
		}
	}
	return nil
}

// keyCreationHasPayload reports whether the populated arm carries any fragment
// of a created-key result, which a 202 must not.
func keyCreationHasPayload(out *mdl.KeyCreationResponse) bool {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		return v.KeyData != nil || len(v.KeyMeta) > 0
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		return v.PublicKeyData != nil || v.PrivateKeyData != nil || len(v.KeyPairMeta) > 0
	}
	return false
}

// validateKeyCreationPayload enforces the 200 branch's payload: every required
// fragment with a usable descriptor behind it. Core rejects an empty nested DTO.
func validateKeyCreationPayload(out *mdl.KeyCreationResponse, subject string) error {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		if v.KeyData == nil || len(v.KeyMeta) == 0 {
			return errIncompleteKeyPayload(subject)
		}
		return validateKeyDescriptor(v.KeyData.Type, keyTypeSecret, v.KeyData.Algorithm, v.KeyData.Length, "keyData")
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		if v.PublicKeyData == nil || v.PrivateKeyData == nil || len(v.KeyPairMeta) == 0 {
			return errIncompleteKeyPayload(subject)
		}
		return validateKeyPairPayload(v, subject)
	}
	return errIncompleteKeyPayload(subject)
}

func errIncompleteKeyPayload(subject string) error {
	return errResponseShape(subject + " must carry a result payload")
}

// The spec pins each key descriptor's type, and tools/fixoneof enforces the pin
// in the generated MarshalJSON, which fails after the 2xx status is on the wire.
const (
	keyTypeSecret  = "Secret"
	keyTypePublic  = "Public"
	keyTypePrivate = "Private"
)

// validateKeyPairPayload enforces each side's keyMeta and descriptor, the
// public SPKI's presence, and equal algorithm and length across both halves.
// The SPKI is not parsed; that is the connector's job. Core applies the length
// equality (KeyPairDataResponseV2Dto.isKeyLengthsMatching) to every algorithm;
// for post-quantum entries length identifies the parameter set, so it matches.
func validateKeyPairPayload(v *mdl.KeyPairDataResponseV2Dto, subject string) error {
	if len(v.PublicKeyData.KeyMeta) == 0 || len(v.PrivateKeyData.KeyMeta) == 0 {
		return errIncompleteKeyPayload(subject)
	}
	pub, priv := &v.PublicKeyData.KeyData, &v.PrivateKeyData.KeyData
	if err := firstError(
		validateKeyDescriptor(pub.Type, keyTypePublic, pub.Algorithm, pub.Length, "publicKeyData.keyData"),
		validateKeyDescriptor(priv.Type, keyTypePrivate, priv.Algorithm, priv.Length, "privateKeyData.keyData"),
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

// validateKeyDescriptor enforces the descriptor's required fields. An unset
// type reaches Core as an unresolvable discriminator; a wrong one fails the
// pinned MarshalJSON (see keyTypeSecret).
func validateKeyDescriptor(keyType, wantType string, algorithm mdl.KeyAlgorithm, length int32, field string) error {
	if keyType != wantType {
		return errResponseShape(field + " must carry key type " + wantType)
	}
	if !algorithm.IsValid() {
		return errResponseShape(field + " must carry a known key algorithm")
	}
	if length <= 0 {
		return errResponseShape(field + " must carry a positive key length")
	}
	return nil
}

// keyCreationHasMeta reports whether the populated arm carries an operationMeta
// tracking handle.
func keyCreationHasMeta(out *mdl.KeyCreationResponse) bool {
	if v := out.SecretKeyDataResponseV2Dto; v != nil {
		return len(v.OperationMeta) > 0
	}
	if v := out.KeyPairDataResponseV2Dto; v != nil {
		return len(v.OperationMeta) > 0
	}
	return false
}

// validateKeyRequestType enforces the discriminator both key-creation oneOf
// wrappers are resolved by. The field is tagged without omitempty, so an unset
// or mismatched value leaves Core unable to pick a variant. want is "" when no
// arm is populated, which the payload and status guards report themselves.
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

// validateSingleKeyCreationArm rejects a wrapper with more than one arm
// populated: the generated MarshalJSON serializes the key-pair arm first while
// the helpers here inspect the secret arm first, so the wire would carry an
// unchecked arm. Zero arms are reported by the payload guards.
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

// keyCreationDiscriminator reports the keyRequestType the populated arm carries
// and the value it must carry. Both are "" when neither arm is set.
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

// validateSignatureResultItem enforces the status/reason rule per item and a
// non-empty signature on a completed one.
func validateSignatureResultItem(item mdl.SignatureResultItemV2Dto) error {
	if err := validateStatusShape(item.Status, item.Reason, item.Signature != nil); err != nil {
		return err
	}
	if item.Status == mdl.OPERATIONSTATUS_COMPLETED && *item.Signature == "" {
		return errResponseShape("signature must not be empty when status is completed")
	}
	return nil
}

// validateSignStatusShape is signDataStatus's response guard. minItems: 1 is
// checked first because an empty array would skip the per-item loop; there is
// no top-level status, so each item is checked on its own.
func validateSignStatusShape(out *mdl.SignOperationStatusResponseV2Dto) error {
	if len(out.Items) == 0 {
		return errResponseShape("items must not be empty")
	}
	if err := validateResponseItemIdentifiers(signatureResultIdentifiers(out.Items), "sign status"); err != nil {
		return err
	}
	for _, item := range out.Items {
		if err := validateSignatureResultItem(item); err != nil {
			return err
		}
	}
	return nil
}

// keyCreationStatusShape extracts status, reason and result presence from the
// populated arm. The caller has already rejected a wrapper with neither arm.
func keyCreationStatusShape(out *mdl.KeyCreationStatusResponse) (status mdl.OperationStatus, reason *string, hasResult bool) {
	if v := out.SecretKeyOperationStatusResponseV2Dto; v != nil {
		return v.Status, v.Reason, v.Result != nil
	}
	if v := out.KeyPairOperationStatusResponseV2Dto; v != nil {
		return v.Status, v.Reason, v.Result != nil
	}
	return "", nil, false
}

// validateKeyCreationStatusShape is createKeyStatus's response guard: exactly
// one populated arm, its discriminator, the status/reason/result rules, and the
// completed result's shape. The result is a full created-key payload, so it is
// held to the synchronous-creation rules; presence alone would admit an
// incomplete payload or a forbidden operationMeta.
func validateKeyCreationStatusShape(out *mdl.KeyCreationStatusResponse) error {
	if err := validateSingleKeyCreationStatusArm(out); err != nil {
		return err
	}
	if err := validateKeyRequestType(keyCreationStatusDiscriminator(out)); err != nil {
		return err
	}
	if out.SecretKeyOperationStatusResponseV2Dto == nil && out.KeyPairOperationStatusResponseV2Dto == nil {
		return errResponseShape("exactly one key status variant must be populated")
	}
	status, reason, hasResult := keyCreationStatusShape(out)
	if err := validateStatusShape(status, reason, hasResult); err != nil {
		return err
	}
	if result := keyCreationStatusResult(out); result != nil {
		if err := validateKeyCreationCommon(result); err != nil {
			return err
		}
		return validateSynchronousKeyCreation(result, "completed key creation result")
	}
	return nil
}

// keyCreationStatusResult wraps a completed result in the initial-response
// wrapper so the synchronous-creation rules apply verbatim. Nil unless
// completed.
func keyCreationStatusResult(out *mdl.KeyCreationStatusResponse) *mdl.KeyCreationResponse {
	if v := out.SecretKeyOperationStatusResponseV2Dto; v != nil && v.Result != nil {
		return &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: v.Result}
	}
	if v := out.KeyPairOperationStatusResponseV2Dto; v != nil && v.Result != nil {
		return &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: v.Result}
	}
	return nil
}

// signatureDataIdentifiers extracts each batch element's identifier.
func signatureDataIdentifiers(data []mdl.SignatureDataV2Dto) []string {
	ids := make([]string, len(data))
	for i, d := range data {
		ids[i] = d.Identifier
	}
	return ids
}

// cipherDataIdentifiers extracts each cipher batch element's identifier.
func cipherDataIdentifiers(data []mdl.CipherDataV2Dto) []string {
	ids := make([]string, len(data))
	for i, d := range data {
		ids[i] = d.Identifier
	}
	return ids
}

// verificationIdentifiers extracts each verify response element's identifier.
func verificationIdentifiers(items []mdl.VerificationResponseItemV2Dto) []string {
	ids := make([]string, len(items))
	for i, v := range items {
		ids[i] = v.Identifier
	}
	return ids
}

// signatureDataPayloads extracts each batch element's data.
func signatureDataPayloads(data []mdl.SignatureDataV2Dto) []string {
	out := make([]string, len(data))
	for i, d := range data {
		out[i] = d.Data
	}
	return out
}

// cipherDataPayloads extracts each cipher batch element's data.
func cipherDataPayloads(data []mdl.CipherDataV2Dto) []string {
	out := make([]string, len(data))
	for i, d := range data {
		out[i] = d.Data
	}
	return out
}

// signatureResultIdentifiers extracts each sign-status item's identifier.
func signatureResultIdentifiers(items []mdl.SignatureResultItemV2Dto) []string {
	out := make([]string, len(items))
	for i, item := range items {
		out[i] = item.Identifier
	}
	return out
}
