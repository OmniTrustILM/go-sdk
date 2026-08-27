package cryptography

// White-box unit tests for validate.go's guard functions. Unlike every other
// _test.go file in this package, this one declares `package cryptography`
// (not cryptography_test) on purpose: validateExecutionMode's non-nil
// branches are not reachable through the HTTP surface at all — shared.DecodeJSON
// rejects every malformed executionMode before a route handler runs (see
// validateExecutionMode's doc comment for which failure maps to which status).
// Calling the unexported function directly is the only way to exercise
// (and hold coverage on) those branches. The remaining guards here are
// black-box-reachable too (see validate_routes_test.go), but testing the
// pure functions directly keeps each case small and exhaustive.
//
// Every case below asserts the specific ErrorCode and Detail message a
// guard produces, not just "an error happened": asserting only err != nil
// would stay green if two branches' messages were swapped, which defeats
// the point of having unexported access in the first place.

import (
	"math"
	"net/http"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// strPtr returns a pointer to s, so a table case can distinguish an absent
// optional field from one present but empty.
func strPtr(s string) *string { return &s }

// metaAttr is a MetadataAttribute with exactly one arm populated, so a fixture
// passes validateMetadataElements; see TestValidateMetadataElements for the
// zero-value element the guard rejects.
func metaAttr() mdl.MetadataAttribute {
	return mdl.MetadataAttribute{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}
}

// wantNoError fails t if err is non-nil.
func wantNoError(t *testing.T, err error) {
	t.Helper()
	if err != nil {
		t.Errorf("err = %v, want nil", err)
	}
}

// wantValidationFailed fails t unless err is a *shared.Error carrying
// errorCode VALIDATION_FAILED and the exact detail message wantDetail.
func wantValidationFailed(t *testing.T, err error, wantDetail string) {
	t.Helper()
	se, ok := err.(*shared.Error)
	if !ok || se == nil {
		t.Fatalf("err = %v (%T), want a *shared.Error", err, err)
	}
	if se.ErrorCode != "VALIDATION_FAILED" {
		t.Errorf("ErrorCode = %q, want VALIDATION_FAILED", se.ErrorCode)
	}
	if se.Detail != wantDetail {
		t.Errorf("Detail = %q, want %q", se.Detail, wantDetail)
	}
}

// wantResponseShapeError fails t unless err is a *shared.Error carrying
// errorCode INTERNAL_SERVER_ERROR whose detail contains wantSubstring (the
// guard message, without the "provider response violates the contract: "
// prefix errResponseShape adds).
func wantResponseShapeError(t *testing.T, err error, wantSubstring string) {
	t.Helper()
	se, ok := err.(*shared.Error)
	if !ok || se == nil {
		t.Fatalf("err = %v (%T), want a *shared.Error", err, err)
	}
	if se.ErrorCode != "INTERNAL_SERVER_ERROR" {
		t.Errorf("ErrorCode = %q, want INTERNAL_SERVER_ERROR", se.ErrorCode)
	}
	if !strings.Contains(se.Detail, wantSubstring) {
		t.Errorf("Detail = %q, want it to contain %q", se.Detail, wantSubstring)
	}
}

func TestValidateExecutionMode(t *testing.T) {
	cases := []struct {
		name       string
		mode       mdl.OperationExecutionMode
		wantDetail string // "" means no error
	}{
		{"synchronous", mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, ""},
		{"asynchronous", mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, ""},
		{"empty", "", "executionMode is required"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExecutionMode(tc.mode)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantValidationFailed(t, err, tc.wantDetail)
		})
	}
	se, ok := validateExecutionMode(mdl.OperationExecutionMode("eventually")).(*shared.Error)
	if !ok || se.Status != http.StatusBadRequest || se.ErrorCode != "BAD_REQUEST" ||
		se.Detail != "executionMode must be synchronous or asynchronous" {
		t.Errorf("unknown mode: got %+v, want 400 BAD_REQUEST", se)
	}
}

func TestValidateKeyCreationId(t *testing.T) {
	cases := []struct {
		name       string
		id         string
		wantDetail string // "" means no error
	}{
		{"non-blank", "k1", ""},
		{"empty", "", "keyCreationId is required and must not be blank"},
		{"whitespace-only", "   ", "keyCreationId is required and must not be blank"},
		{"exactly-256", strings.Repeat("a", 256), ""},
		{"over-256", strings.Repeat("a", 257), "keyCreationId must not exceed 256 characters"},
		// The contract's @Size(max = 256) counts characters, not UTF-8
		// bytes: 256 multi-byte runes (512 bytes here) must be accepted,
		// and 257 must not.
		{"non-ascii-exactly-256-runes", strings.Repeat("é", 256), ""},
		{"non-ascii-over-256-runes", strings.Repeat("é", 257), "keyCreationId must not exceed 256 characters"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyCreationId(tc.id)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantValidationFailed(t, err, tc.wantDetail)
		})
	}
}

func TestValidateUniqueIdentifiers(t *testing.T) {
	wantNoError(t, validateUniqueIdentifiers(nil, "data"))
	wantNoError(t, validateUniqueIdentifiers([]string{"a", "b"}, "data"))
	wantValidationFailed(t, validateUniqueIdentifiers([]string{"a", "a"}, "data"),
		"data identifiers must be unique within a batch")
	wantValidationFailed(t, validateUniqueIdentifiers([]string{"x", "x"}, "signatures"),
		"signatures identifiers must be unique within a batch")
}

func TestValidateNonEmptyBatch(t *testing.T) {
	wantNoError(t, validateNonEmptyBatch(1, "data"))
	wantNoError(t, validateNonEmptyBatch(3, "operationMeta"))
	// The message names the field so a caller can tell which of a request's
	// several batch lists was empty, and carries no request-supplied value.
	wantValidationFailed(t, validateNonEmptyBatch(0, "data"), "data must not be empty")
	wantValidationFailed(t, validateNonEmptyBatch(0, "keyMeta"), "keyMeta must not be empty")
	wantValidationFailed(t, validateNonEmptyBatch(0, "operationMeta"), "operationMeta must not be empty")
}

func TestValidateKeyUsages(t *testing.T) {
	cases := []struct {
		name       string
		usages     []mdl.KeyUsage
		wantDetail string // "" means no error
	}{
		{"one usage", []mdl.KeyUsage{mdl.KEYUSAGE_SIGN}, ""},
		{"distinct usages", []mdl.KeyUsage{mdl.KEYUSAGE_SIGN, mdl.KEYUSAGE_VERIFY}, ""},
		{"empty", []mdl.KeyUsage{}, "keyUsages must not be empty"},
		{"nil", nil, "keyUsages must not be empty"},
		{"duplicate", []mdl.KeyUsage{mdl.KEYUSAGE_SIGN, mdl.KEYUSAGE_SIGN}, "keyUsages must not contain duplicates"},
		{"duplicate after a distinct one", []mdl.KeyUsage{mdl.KEYUSAGE_SIGN, mdl.KEYUSAGE_VERIFY, mdl.KEYUSAGE_SIGN}, "keyUsages must not contain duplicates"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyUsages(tc.usages)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantValidationFailed(t, err, tc.wantDetail)
		})
	}
}

// TestFirstError pins the property every handler's guard list depends on:
// the reported violation is the first one in argument order, not whichever
// guard happens to be cheapest or last.
func TestFirstError(t *testing.T) {
	wantNoError(t, firstError())
	wantNoError(t, firstError(nil, nil))

	first := errValidationFailed("first rule")
	second := errValidationFailed("second rule")
	if got := firstError(nil, first, second); got != error(first) {
		t.Errorf("firstError(nil, first, second) = %v, want the first non-nil error", got)
	}
	if got := firstError(second, first); got != error(second) {
		t.Errorf("firstError(second, first) = %v, want argument order to decide", got)
	}
}

func TestValidateIdentifiersMatch(t *testing.T) {
	cases := []struct {
		name string
		want []string
		got  []string
		err  bool
	}{
		{"same set", []string{"a", "b"}, []string{"b", "a"}, false},
		{"both empty", nil, nil, false},
		{"different size", []string{"a"}, []string{"a", "b"}, true},
		{"same size different members", []string{"a", "b"}, []string{"a", "c"}, true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateIdentifiersMatch(tc.want, tc.got, "signatures")
			if !tc.err {
				wantNoError(t, err)
				return
			}
			wantValidationFailed(t, err, "signatures identifiers must match the request data identifiers")
		})
	}
	// Same size and every got element present in want, yet not the same set:
	// exact on its own, without relying on a preceding uniqueness guard.
	wantValidationFailed(t, validateIdentifiersMatch([]string{"a", "b"}, []string{"a", "a"}, "signatures"),
		"signatures identifiers must match the request data identifiers")
	wantValidationFailed(t, validateIdentifiersMatch([]string{"a", "a"}, []string{"a", "b"}, "signatures"),
		"signatures identifiers must match the request data identifiers")
}

// The cap is the contract's documented 1 MiB; the boundary rows below would
// pass for any value, so the value itself is pinned here.
func TestMaxRandomDataLengthIsOneMiB(t *testing.T) {
	if maxRandomDataLength != 1<<20 {
		t.Errorf("maxRandomDataLength = %d, want %d", maxRandomDataLength, 1<<20)
	}
}

func TestValidateRandomDataLength(t *testing.T) {
	cases := []struct {
		length     int32
		wantDetail string
	}{
		{1, ""},
		{0, "length must be positive"},
		{-1, "length must be positive"},
		{maxRandomDataLength, ""}, // boundary: accepted
		{maxRandomDataLength + 1, "length must not exceed 1048576 bytes"}, // boundary: rejected
	}
	for _, tc := range cases {
		err := validateRandomDataLength(tc.length)
		if tc.wantDetail == "" {
			wantNoError(t, err)
			continue
		}
		wantValidationFailed(t, err, tc.wantDetail)
	}
}

func TestValidateExecutionShape(t *testing.T) {
	cases := []struct {
		name       string
		accepted   bool
		hasMeta    bool
		hasPayload bool
		wantDetail string
	}{
		{"accepted with meta, no payload", true, true, false, ""},
		{"accepted without meta", true, false, false, "sign data accepted for asynchronous execution must carry operationMeta"},
		{"accepted with payload", true, true, true, "sign data accepted for asynchronous execution must not carry a result payload"},
		{"sync with payload, no meta", false, false, true, ""},
		{"sync with meta", false, true, true, "sign data completed synchronously must not carry operationMeta"},
		{"sync without payload", false, false, false, "sign data completed synchronously must carry a result payload"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateExecutionShape(tc.accepted, tc.hasMeta, tc.hasPayload, "sign data")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

func TestValidateDestroyShape(t *testing.T) {
	wantResponseShapeError(t, validateDestroyShape(true, false),
		"key destruction accepted for asynchronous execution must carry operationMeta")
	wantNoError(t, validateDestroyShape(true, true))
	wantNoError(t, validateDestroyShape(false, false))
	// The spec states outright that operationMeta is "Absent from a
	// synchronous creation response" — a synchronous result carrying one is
	// a violation, symmetric with the accepted-without-meta case above.
	wantResponseShapeError(t, validateDestroyShape(false, true),
		"key destruction completed synchronously must not carry operationMeta")
}

func TestValidateKeyCreationShape(t *testing.T) {
	secretComplete := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
			KeyMeta:        []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}
	secretPartial := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), // KeyMeta missing
		},
	}
	secretAccepted := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			OperationMeta:  []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}
	secretAcceptedWithLeftoverPayload := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			OperationMeta:  []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
			KeyMeta:        []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}

	// Synchronous branch: AND across the arm's payload fields — a partial
	// payload (KeyData without KeyMeta) is a violation, not merely "some
	// payload present".
	wantNoError(t, validateKeyCreationShape(false, secretComplete))
	wantResponseShapeError(t, validateKeyCreationShape(false, secretPartial),
		"key creation completed synchronously must carry a result payload")
	wantResponseShapeError(t, validateKeyCreationShape(false, secretAccepted),
		"key creation completed synchronously must not carry operationMeta")

	// Accepted branch: OR across the arm's payload fields — any leftover
	// fragment, even just one, is a violation.
	wantNoError(t, validateKeyCreationShape(true, secretAccepted))
	wantResponseShapeError(t, validateKeyCreationShape(true, secretComplete),
		"key creation accepted for asynchronous execution must carry operationMeta")
	wantResponseShapeError(t, validateKeyCreationShape(true, secretAcceptedWithLeftoverPayload),
		"key creation accepted for asynchronous execution must not carry a result payload")

	// Key-pair arm, synchronous branch: same AND requirement across its
	// three fragments.
	pairComplete := &mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: keyPair(func(*mdl.KeyPairDataResponseV2Dto) {}),
	}
	pairPartial := &mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
			PublicKeyData:  &mdl.PublicKeyDataResponseV2Dto{}, // PrivateKeyData, KeyPairMeta missing
		},
	}
	wantNoError(t, validateKeyCreationShape(false, pairComplete))
	wantResponseShapeError(t, validateKeyCreationShape(false, pairPartial),
		"key creation completed synchronously must carry a result payload")

	// Neither oneOf arm set: a malformed response, caught the same way in
	// both directions. The discriminator guard passes it through (there is no
	// arm whose discriminator could be wrong) so the payload rules report it.
	empty := &mdl.KeyCreationResponse{}
	wantResponseShapeError(t, validateKeyCreationShape(false, empty),
		"key creation completed synchronously must carry a result payload")
	wantResponseShapeError(t, validateKeyCreationShape(true, empty),
		"key creation accepted for asynchronous execution must carry operationMeta")

	// The discriminator runs ahead of the payload rules in both directions:
	// an otherwise perfectly shaped response Core cannot resolve is still a
	// contract violation.
	noDiscriminator := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
			KeyMeta: []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}
	wantResponseShapeError(t, validateKeyCreationShape(false, noDiscriminator),
		"keyRequestType is required on the populated key data variant")
	wrongDiscriminator := &mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, // names the other arm
			PublicKeyData:  &mdl.PublicKeyDataResponseV2Dto{},
			PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{},
			KeyPairMeta:    []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}
	wantResponseShapeError(t, validateKeyCreationShape(false, wrongDiscriminator),
		"keyRequestType must match the populated key data variant")
	wantResponseShapeError(t, validateKeyCreationShape(true, wrongDiscriminator),
		"keyRequestType must match the populated key data variant")
}

func TestValidateKeyRequestType(t *testing.T) {
	cases := []struct {
		name       string
		got        mdl.KeyRequestType
		want       mdl.KeyRequestType
		wantDetail string // "" means no error
	}{
		{"secret arm carrying secret", mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_SECRET, ""},
		{"key-pair arm carrying keyPair", mdl.KEYREQUESTTYPE_KEY_PAIR, mdl.KEYREQUESTTYPE_KEY_PAIR, ""},
		// No arm populated: the payload and status guards report that in
		// their own terms, so this one stays out of the way.
		{"no arm populated", "", "", ""},
		{"secret arm with no discriminator", "", mdl.KEYREQUESTTYPE_SECRET, "keyRequestType is required on the populated key data variant"},
		{"key-pair arm with no discriminator", "", mdl.KEYREQUESTTYPE_KEY_PAIR, "keyRequestType is required on the populated key data variant"},
		{"secret arm naming keyPair", mdl.KEYREQUESTTYPE_KEY_PAIR, mdl.KEYREQUESTTYPE_SECRET, "keyRequestType must match the populated key data variant"},
		{"key-pair arm naming secret", mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_KEY_PAIR, "keyRequestType must match the populated key data variant"},
		{"arm carrying a value outside the enum", mdl.KeyRequestType("bogus"), mdl.KEYREQUESTTYPE_SECRET, "keyRequestType must match the populated key data variant"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyRequestType(tc.got, tc.want)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

func TestKeyCreationDiscriminator(t *testing.T) {
	got, want := keyCreationDiscriminator(&mdl.KeyCreationResponse{})
	if got != "" || want != "" {
		t.Errorf("neither arm set: got (%q, %q), want two empty values", got, want)
	}
	got, want = keyCreationDiscriminator(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET},
	})
	if got != mdl.KEYREQUESTTYPE_SECRET || want != mdl.KEYREQUESTTYPE_SECRET {
		t.Errorf("secret arm: got (%q, %q), want (secret, secret)", got, want)
	}
	got, want = keyCreationDiscriminator(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{}, // discriminator unset
	})
	if got != "" || want != mdl.KEYREQUESTTYPE_KEY_PAIR {
		t.Errorf("key-pair arm with no discriminator: got (%q, %q), want (\"\", keyPair)", got, want)
	}
}

func TestKeyCreationStatusDiscriminator(t *testing.T) {
	got, want := keyCreationStatusDiscriminator(&mdl.KeyCreationStatusResponse{})
	if got != "" || want != "" {
		t.Errorf("neither arm set: got (%q, %q), want two empty values", got, want)
	}
	got, want = keyCreationStatusDiscriminator(&mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET},
	})
	if got != mdl.KEYREQUESTTYPE_SECRET || want != mdl.KEYREQUESTTYPE_SECRET {
		t.Errorf("secret arm: got (%q, %q), want (secret, secret)", got, want)
	}
	got, want = keyCreationStatusDiscriminator(&mdl.KeyCreationStatusResponse{
		KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR},
	})
	if got != mdl.KEYREQUESTTYPE_KEY_PAIR || want != mdl.KEYREQUESTTYPE_KEY_PAIR {
		t.Errorf("key-pair arm: got (%q, %q), want (keyPair, keyPair)", got, want)
	}
}

// TestValidateKeyCreationStatusShape covers the composition createKeyStatus
// relies on: the discriminator first, then the status/reason/result rules over
// whichever arm is populated.
func TestValidateKeyCreationStatusShape(t *testing.T) {
	wantNoError(t, validateKeyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
		},
	}))
	wantResponseShapeError(t, validateKeyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_IN_PROGRESS, // discriminator unset
		},
	}), "keyRequestType is required on the populated key data variant")
	wantResponseShapeError(t, validateKeyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, // names the other arm
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
		},
	}), "keyRequestType must match the populated key data variant")
	// The status rules still apply once the discriminator is right.
	wantResponseShapeError(t, validateKeyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			Status:         mdl.OPERATIONSTATUS_FAILED, // no reason
		},
	}), "reason is required when status is failed or cancelled")
	wantResponseShapeError(t, validateKeyCreationStatusShape(&mdl.KeyCreationStatusResponse{}),
		"exactly one key status variant must be populated")
}

func TestValidateStatusShape(t *testing.T) {
	cases := []struct {
		name       string
		status     mdl.OperationStatus
		reason     *string
		hasResult  bool
		wantDetail string
	}{
		{"failed with reason", mdl.OPERATIONSTATUS_FAILED, strPtr("boom"), false, ""},
		{"failed without reason", mdl.OPERATIONSTATUS_FAILED, nil, false, "reason is required when status is failed or cancelled"},
		{"failed with blank reason", mdl.OPERATIONSTATUS_FAILED, strPtr("   "), false, "reason is required when status is failed or cancelled"},
		{"failed with reason and result", mdl.OPERATIONSTATUS_FAILED, strPtr("boom"), true, "result must be absent unless status is completed"},
		{"cancelled with reason", mdl.OPERATIONSTATUS_CANCELLED, strPtr("aborted"), false, ""},
		{"cancelled without reason", mdl.OPERATIONSTATUS_CANCELLED, nil, false, "reason is required when status is failed or cancelled"},
		{"cancelled with reason and result", mdl.OPERATIONSTATUS_CANCELLED, strPtr("aborted"), true, "result must be absent unless status is completed"},
		{"inProgress bare", mdl.OPERATIONSTATUS_IN_PROGRESS, nil, false, ""},
		{"inProgress with reason", mdl.OPERATIONSTATUS_IN_PROGRESS, strPtr("why"), false, "reason must be absent unless status is failed or cancelled"},
		{"inProgress with empty reason", mdl.OPERATIONSTATUS_IN_PROGRESS, strPtr(""), false, "reason must be absent unless status is failed or cancelled"},
		{"inProgress with result", mdl.OPERATIONSTATUS_IN_PROGRESS, nil, true, "result must be absent unless status is completed"},
		{"completed with result", mdl.OPERATIONSTATUS_COMPLETED, nil, true, ""},
		{"completed without result", mdl.OPERATIONSTATUS_COMPLETED, nil, false, "result is required when status is completed"},
		{"completed with reason", mdl.OPERATIONSTATUS_COMPLETED, strPtr("why"), true, "reason must be absent unless status is failed or cancelled"},
		{"unknown status", mdl.OperationStatus("bogus"), nil, false, "unknown operation status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStatusShape(tc.status, tc.reason, tc.hasResult)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

// TestValidateStatusReason exercises validateStatusReason directly —
// the rule set that applies to every status DTO, including
// KeyDestructionStatusResponseV2Dto, which has no result field at all and
// therefore cannot go through validateStatusShape (see destroyKeyStatus in
// routes.go).
func TestValidateStatusReason(t *testing.T) {
	cases := []struct {
		name       string
		status     mdl.OperationStatus
		reason     *string
		wantDetail string
	}{
		{"failed with reason", mdl.OPERATIONSTATUS_FAILED, strPtr("boom"), ""},
		{"failed without reason", mdl.OPERATIONSTATUS_FAILED, nil, "reason is required when status is failed or cancelled"},
		{"failed with empty reason", mdl.OPERATIONSTATUS_FAILED, strPtr(""), "reason is required when status is failed or cancelled"},
		{"failed with blank reason", mdl.OPERATIONSTATUS_FAILED, strPtr("   "), "reason is required when status is failed or cancelled"},
		{"cancelled with reason", mdl.OPERATIONSTATUS_CANCELLED, strPtr("aborted"), ""},
		{"cancelled without reason", mdl.OPERATIONSTATUS_CANCELLED, nil, "reason is required when status is failed or cancelled"},
		{"inProgress bare", mdl.OPERATIONSTATUS_IN_PROGRESS, nil, ""},
		{"inProgress with reason", mdl.OPERATIONSTATUS_IN_PROGRESS, strPtr("why"), "reason must be absent unless status is failed or cancelled"},
		{"inProgress with empty reason", mdl.OPERATIONSTATUS_IN_PROGRESS, strPtr(""), "reason must be absent unless status is failed or cancelled"},
		{"completed bare", mdl.OPERATIONSTATUS_COMPLETED, nil, ""},
		{"completed with reason", mdl.OPERATIONSTATUS_COMPLETED, strPtr("why"), "reason must be absent unless status is failed or cancelled"},
		{"completed with empty reason", mdl.OPERATIONSTATUS_COMPLETED, strPtr(""), "reason must be absent unless status is failed or cancelled"},
		{"unknown status", mdl.OperationStatus("bogus"), nil, "unknown operation status"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateStatusReason(tc.status, tc.reason)
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

func TestKeyCreationHasPayload(t *testing.T) {
	if keyCreationHasPayload(&mdl.KeyCreationResponse{}) {
		t.Error("neither variant set: want false")
	}
	if !keyCreationHasPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048)},
	}) {
		t.Error("secret arm with KeyData only: want true (OR)")
	}
	if !keyCreationHasPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyMeta: []mdl.MetadataAttribute{metaAttr()}},
	}) {
		t.Error("secret arm with KeyMeta only: want true (OR)")
	}
	if keyCreationHasPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{},
	}) {
		t.Error("secret arm with neither field: want false")
	}
	if !keyCreationHasPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{PublicKeyData: &mdl.PublicKeyDataResponseV2Dto{}},
	}) {
		t.Error("key-pair arm with PublicKeyData only: want true (OR)")
	}
	if !keyCreationHasPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{}},
	}) {
		t.Error("key-pair arm with PrivateKeyData only: want true (OR)")
	}
	if !keyCreationHasPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{KeyPairMeta: []mdl.MetadataAttribute{metaAttr()}},
	}) {
		t.Error("key-pair arm with KeyPairMeta only: want true (OR)")
	}
	if keyCreationHasPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{},
	}) {
		t.Error("key-pair arm with no fields: want false")
	}
}

func TestValidateKeyCreationPayload(t *testing.T) {
	const incomplete = "key creation completed synchronously must carry a result payload"
	secretKey := func() *mdl.SecretKeyDataV2Dto { return mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048) }

	wantResponseShapeError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{}, "key creation completed synchronously"), incomplete)
	wantResponseShapeError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyData: secretKey()},
	}, "key creation completed synchronously"), incomplete)
	wantResponseShapeError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{KeyMeta: []mdl.MetadataAttribute{metaAttr()}},
	}, "key creation completed synchronously"), incomplete)
	wantNoError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyData: secretKey(),
			KeyMeta: []mdl.MetadataAttribute{metaAttr()},
		},
	}, "key creation completed synchronously"))
	wantResponseShapeError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyData: &mdl.SecretKeyDataV2Dto{},
			KeyMeta: []mdl.MetadataAttribute{metaAttr()},
		},
	}, "key creation completed synchronously"), "keyData must carry key type Secret")

	wantResponseShapeError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			PublicKeyData:  &mdl.PublicKeyDataResponseV2Dto{},
			PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{},
		},
	}, "key creation completed synchronously"), incomplete)
	wantNoError(t, validateKeyCreationPayload(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: keyPair(func(*mdl.KeyPairDataResponseV2Dto) {}),
	}, "key creation completed synchronously"))
}

// keyPair builds a complete, valid key-pair response and applies mutate, so a
// case states only the fragment it breaks.
func keyPair(mutate func(*mdl.KeyPairDataResponseV2Dto)) *mdl.KeyPairDataResponseV2Dto {
	v := &mdl.KeyPairDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		KeyPairMeta:    []mdl.MetadataAttribute{metaAttr()},
		PublicKeyData: &mdl.PublicKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metaAttr()},
			KeyData: *mdl.NewPublicKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048, "AA=="),
		},
		PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{
			KeyMeta: []mdl.MetadataAttribute{metaAttr()},
			KeyData: *mdl.NewPrivateKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
		},
	}
	mutate(v)
	return v
}

func TestValidateKeyPairPayload(t *testing.T) {
	cases := []struct {
		name       string
		mutate     func(*mdl.KeyPairDataResponseV2Dto)
		wantDetail string
	}{
		{"complete", func(*mdl.KeyPairDataResponseV2Dto) {}, ""},
		{"public keyMeta missing", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PublicKeyData.KeyMeta = nil
		}, "key creation completed synchronously must carry a result payload"},
		{"private keyMeta missing", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PrivateKeyData.KeyMeta = nil
		}, "key creation completed synchronously must carry a result payload"},
		{"public length not positive", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PublicKeyData.KeyData.Length = 0
		}, "publicKeyData.keyData must carry a positive key length"},
		{"private algorithm unknown", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PrivateKeyData.KeyData.Algorithm = mdl.KeyAlgorithm("bogus")
		}, "privateKeyData.keyData must carry a known key algorithm"},
		{"publicKeySpki missing", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PublicKeyData.KeyData.PublicKeySpki = ""
		}, "publicKeyData.keyData must carry publicKeySpki"},
		{"algorithms disagree", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PrivateKeyData.KeyData.Algorithm = mdl.KEYALGORITHM_ECDSA
		}, "public and private key algorithms must match"},
		{"lengths disagree", func(v *mdl.KeyPairDataResponseV2Dto) {
			v.PrivateKeyData.KeyData.Length = 4096
		}, "public and private key lengths must match"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyPairPayload(keyPair(tc.mutate), "key creation completed synchronously")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
	wantResponseShapeError(t, validateKeyPairPayload(keyPair(func(v *mdl.KeyPairDataResponseV2Dto) {
		v.PrivateKeyData.KeyData.Type = "Public"
	}), "key creation completed synchronously"), "privateKeyData.keyData must carry key type Private")
}

func TestKeyCreationHasMeta(t *testing.T) {
	if keyCreationHasMeta(&mdl.KeyCreationResponse{}) {
		t.Error("neither variant set: want false")
	}
	if !keyCreationHasMeta(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metaAttr()}},
	}) {
		t.Error("secret arm with OperationMeta: want true")
	}
	if !keyCreationHasMeta(&mdl.KeyCreationResponse{
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metaAttr()}},
	}) {
		t.Error("key-pair arm with OperationMeta: want true")
	}
	if keyCreationHasMeta(&mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{},
	}) {
		t.Error("secret arm with no OperationMeta: want false")
	}
}

func TestSignHasPayload(t *testing.T) {
	if signHasPayload(&mdl.SignDataResponseV2Dto{}) {
		t.Error("empty response: want false")
	}
	if !signHasPayload(&mdl.SignDataResponseV2Dto{Signatures: []mdl.SignatureDataV2Dto{{}}}) {
		t.Error("response with a signature: want true")
	}
}

func TestKeyCreationStatusShape(t *testing.T) {
	status, reason, hasResult := keyCreationStatusShape(&mdl.KeyCreationStatusResponse{})
	if status != "" || reason != nil || hasResult {
		t.Errorf("neither variant set: got (%q, %v, %v), want (\"\", nil, false)", status, reason, hasResult)
	}

	why := "boom"
	status, reason, hasResult = keyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_FAILED,
			Reason: &why,
		},
	})
	if status != mdl.OPERATIONSTATUS_FAILED || reason == nil || *reason != why || hasResult {
		t.Errorf("secret arm: got (%q, %v, %v), want (%q, %q, false)", status, reason, hasResult, mdl.OPERATIONSTATUS_FAILED, why)
	}

	status, reason, hasResult = keyCreationStatusShape(&mdl.KeyCreationStatusResponse{
		KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
			Status: mdl.OPERATIONSTATUS_COMPLETED,
			Result: &mdl.KeyPairDataResponseV2Dto{},
		},
	})
	if status != mdl.OPERATIONSTATUS_COMPLETED || reason != nil || !hasResult {
		t.Errorf("key-pair arm: got (%q, %v, %v), want (%q, nil, true)", status, reason, hasResult, mdl.OPERATIONSTATUS_COMPLETED)
	}
}

func TestSignatureDataIdentifiers(t *testing.T) {
	got := signatureDataIdentifiers([]mdl.SignatureDataV2Dto{{Identifier: "a"}, {Identifier: "b"}})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("signatureDataIdentifiers(...) = %v, want [a b]", got)
	}
	if got := signatureDataIdentifiers(nil); len(got) != 0 {
		t.Errorf("signatureDataIdentifiers(nil) = %v, want empty", got)
	}
}

func TestCipherDataIdentifiers(t *testing.T) {
	got := cipherDataIdentifiers([]mdl.CipherDataV2Dto{{Identifier: "x"}})
	if len(got) != 1 || got[0] != "x" {
		t.Errorf("cipherDataIdentifiers(...) = %v, want [x]", got)
	}
}

func TestErrValidationFailedRendersVALIDATION_FAILED(t *testing.T) {
	err := errValidationFailed("some rule was violated")
	if err.ErrorCode != "VALIDATION_FAILED" {
		t.Errorf("ErrorCode = %q, want VALIDATION_FAILED", err.ErrorCode)
	}
	if err.Status != 422 {
		t.Errorf("Status = %d, want 422", err.Status)
	}
	if err.Detail != "some rule was violated" {
		t.Errorf("Detail = %q, want the message verbatim (no prefix)", err.Detail)
	}
}

func TestErrResponseShapeRendersInternalServerError(t *testing.T) {
	err := errResponseShape("some invariant was violated")
	if err.ErrorCode != "INTERNAL_SERVER_ERROR" {
		t.Errorf("ErrorCode = %q, want INTERNAL_SERVER_ERROR", err.ErrorCode)
	}
	if err.Status != 500 {
		t.Errorf("Status = %d, want 500", err.Status)
	}
	if !strings.Contains(err.Detail, "some invariant was violated") {
		t.Errorf("Detail = %q, want it to include the guard message", err.Detail)
	}
}

// --- Response side: the provider must not switch the caller-selected mode ----

// TestValidateModeNotSwitched pins both halves of the asymmetry: a
// synchronously requested operation reported as accepted is a violation, while
// an asynchronously requested one reported as completed inline is not. The
// permitted direction is what lets a synchronous-only connector serve an
// asynchronous request at all, so it is asserted rather than left implicit.
func TestValidateModeNotSwitched(t *testing.T) {
	cases := []struct {
		name       string
		mode       mdl.OperationExecutionMode
		accepted   bool
		wantDetail string // "" means no error
	}{
		{
			name:       "synchronous request accepted asynchronously",
			mode:       mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
			accepted:   true,
			wantDetail: "requested synchronously must not be accepted for asynchronous execution",
		},
		{name: "synchronous request completed synchronously", mode: mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS},
		{name: "asynchronous request accepted asynchronously", mode: mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, accepted: true},
		{
			name:       "asynchronous request completed inline",
			mode:       mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS,
			wantDetail: "requested asynchronously must be accepted for asynchronous execution",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateModeNotSwitched(tc.mode, tc.accepted, "key creation")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

// --- Response side: exactly one oneOf arm --------------------------------------

// TestValidateKeyCreationShapeRejectsBothArms covers the ambiguity that makes a
// two-armed wrapper unvalidatable rather than merely redundant: the generated
// MarshalJSON serializes the key-pair arm first while every helper here
// inspects the secret arm first, so without this guard validation would approve
// one arm while the wire carried the other, unchecked.
func TestValidateKeyCreationShapeRejectsBothArms(t *testing.T) {
	both := &mdl.KeyCreationResponse{
		SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
			KeyMeta:        []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
		KeyPairDataResponseV2Dto: &mdl.KeyPairDataResponseV2Dto{
			KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
			PublicKeyData:  &mdl.PublicKeyDataResponseV2Dto{},
			PrivateKeyData: &mdl.PrivateKeyDataResponseV2Dto{},
			KeyPairMeta:    []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}},
		},
	}

	// Rejected in both directions: neither arm is inspectable as "the" arm.
	wantResponseShapeError(t, validateKeyCreationShape(false, both), "exactly one key data variant may be populated")
	wantResponseShapeError(t, validateKeyCreationShape(true, both), "exactly one key data variant may be populated")
}

// TestValidateKeyCreationStatusShapeRejectsBothArms is the status counterpart:
// that wrapper's generated MarshalJSON has the same key-pair-first ordering.
func TestValidateKeyCreationStatusShapeRejectsBothArms(t *testing.T) {
	both := &mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		},
		KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
			KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		},
	}

	wantResponseShapeError(t, validateKeyCreationStatusShape(both), "exactly one key status variant may be populated")
}

// --- Response side: a completed status result is a full created-key payload ---

// TestValidateKeyCreationStatusShapeChecksCompletedResult proves the completed
// result is held to the synchronous-creation rules rather than merely being
// non-nil. A result whose discriminator is unset, whose payload is incomplete,
// or which carries a forbidden operationMeta is one Core cannot consume, and a
// presence-only check would report the operation completed regardless.
func TestValidateKeyCreationStatusShapeChecksCompletedResult(t *testing.T) {
	oneMeta := []mdl.MetadataAttribute{{MetadataAttributeV2: &mdl.MetadataAttributeV2{}}}
	completedWith := func(result *mdl.SecretKeyDataResponseV2Dto) *mdl.KeyCreationStatusResponse {
		return &mdl.KeyCreationStatusResponse{
			SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
				Status:         mdl.OPERATIONSTATUS_COMPLETED,
				KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
				Result:         result,
			},
		}
	}

	cases := []struct {
		name       string
		result     *mdl.SecretKeyDataResponseV2Dto
		wantDetail string // "" means no error
	}{
		{
			name:   "complete result",
			result: &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), KeyMeta: oneMeta},
		},
		{
			name:       "partial payload: keyData without keyMeta",
			result:     &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048)},
			wantDetail: "completed key creation result must carry a result payload",
		},
		{
			name:       "absent discriminator",
			result:     &mdl.SecretKeyDataResponseV2Dto{KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), KeyMeta: oneMeta},
			wantDetail: "keyRequestType is required on the populated key data variant",
		},
		{
			name:       "mismatched discriminator",
			result:     &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), KeyMeta: oneMeta},
			wantDetail: "keyRequestType must match the populated key data variant",
		},
		{
			name:       "forbidden operationMeta on the result",
			result:     &mdl.SecretKeyDataResponseV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_SECRET, KeyData: mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048), KeyMeta: oneMeta, OperationMeta: oneMeta},
			wantDetail: "completed key creation result must not carry operationMeta",
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			err := validateKeyCreationStatusShape(completedWith(tc.result))
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

// TestValidateKeyCreationStatusShapeIgnoresAbsentResult pins the other side of
// the rule the completed-result check must not disturb: a non-completed status
// carries no result, and reaching into one that is not there must not fail.
func TestValidateKeyCreationStatusShapeIgnoresAbsentResult(t *testing.T) {
	inProgress := &mdl.KeyCreationStatusResponse{
		SecretKeyOperationStatusResponseV2Dto: &mdl.SecretKeyOperationStatusResponseV2Dto{
			Status:         mdl.OPERATIONSTATUS_IN_PROGRESS,
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		},
	}

	wantNoError(t, validateKeyCreationStatusShape(inProgress))
}

// TestValidateKeyCreationStatusShapeChecksCompletedKeyPairResult covers the
// key-pair arm of the completed-result rule, whose payload is complete only
// with all three fragments present.
func TestValidateKeyCreationStatusShapeChecksCompletedKeyPairResult(t *testing.T) {
	completedWith := func(result *mdl.KeyPairDataResponseV2Dto) *mdl.KeyCreationStatusResponse {
		return &mdl.KeyCreationStatusResponse{
			KeyPairOperationStatusResponseV2Dto: &mdl.KeyPairOperationStatusResponseV2Dto{
				Status:         mdl.OPERATIONSTATUS_COMPLETED,
				KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
				Result:         result,
			},
		}
	}

	complete := keyPair(func(*mdl.KeyPairDataResponseV2Dto) {})
	wantNoError(t, validateKeyCreationStatusShape(completedWith(complete)))

	// Only the public half: a partial key pair, not a completed creation.
	partial := &mdl.KeyPairDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		PublicKeyData:  &mdl.PublicKeyDataResponseV2Dto{},
	}
	wantResponseShapeError(t, validateKeyCreationStatusShape(completedWith(partial)),
		"completed key creation result must carry a result payload")
}

func TestValidateModeNotSwitchedRejectsBothDirections(t *testing.T) {
	wantNoError(t, validateModeNotSwitched(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, false, "key creation"))
	wantNoError(t, validateModeNotSwitched(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, true, "key creation"))

	wantResponseShapeError(t,
		validateModeNotSwitched(mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, true, "key creation"),
		"key creation requested synchronously must not be accepted for asynchronous execution")
	wantResponseShapeError(t,
		validateModeNotSwitched(mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, false, "key creation"),
		"key creation requested asynchronously must be accepted for asynchronous execution")
}

func TestValidateBatchItems(t *testing.T) {
	wantNoError(t, validateBatchItems([]string{"a", "b"}, []string{"AA==", "BB=="}, "data"))

	wantValidationFailed(t,
		validateBatchItems([]string{"a", "  "}, []string{"AA==", "BB=="}, "data"),
		"data identifiers must not be blank")
	wantValidationFailed(t,
		validateBatchItems([]string{"a", "b"}, []string{"AA==", ""}, "data"),
		"data entries must not carry empty data")
	wantValidationFailed(t, validateBatchItems([]string{"a", "b"}, []string{"AA=="}, "data"), "data entries are malformed")
}

func TestValidateResponseIdentifiers(t *testing.T) {
	wantNoError(t, validateResponseIdentifiers([]string{"a", "b"}, []string{"b", "a"}, "encrypt data"))

	wantResponseShapeError(t,
		validateResponseIdentifiers([]string{"a", "b"}, []string{"a", "a"}, "encrypt data"),
		"encrypt data response identifiers must be unique")
	wantResponseShapeError(t,
		validateResponseIdentifiers([]string{"a", "b"}, []string{"a"}, "encrypt data"),
		"encrypt data response identifiers must match the request identifiers")
	wantResponseShapeError(t,
		validateResponseIdentifiers([]string{"a", "b"}, []string{"a", "c"}, "encrypt data"),
		"encrypt data response identifiers must match the request identifiers")
	// A duplicated request identifier must not admit an identifier nobody asked for.
	wantResponseShapeError(t, validateResponseIdentifiers([]string{"a", "a"}, []string{"a", "b"}, "verify data"),
		"verify data response identifiers must match the request identifiers")
}

func TestValidateRandomDataPayload(t *testing.T) {
	wantNoError(t, validateRandomDataPayload("AAAA", 3))

	wantResponseShapeError(t, validateRandomDataPayload("AAAA", 4),
		"random data length must match the requested length")
	wantResponseShapeError(t, validateRandomDataPayload("!!!!", 3),
		"random data must be valid base64")
}

func TestValidateRequestedKeyRequestType(t *testing.T) {
	wantNoError(t, validateRequestedKeyRequestType(mdl.KEYREQUESTTYPE_SECRET, mdl.KEYREQUESTTYPE_SECRET))

	wantResponseShapeError(t,
		validateRequestedKeyRequestType(mdl.KEYREQUESTTYPE_KEY_PAIR, mdl.KEYREQUESTTYPE_SECRET),
		"keyRequestType must match the requested key request type")
}

func TestValidateResponseBatchRejectsEmptyData(t *testing.T) {
	ids := []string{"a", "b"}
	wantNoError(t, validateResponseBatch(ids, []string{"b", "a"}, []string{"AA==", "BB=="}, "encrypt data"))
	// The identifier set still matches; only the payload is missing.
	wantResponseShapeError(t,
		validateResponseBatch(ids, ids, []string{"AA==", ""}, "encrypt data"),
		"encrypt data response entries must not carry empty data")
	wantResponseShapeError(t,
		validateResponseBatch(ids, []string{"a"}, []string{"AA=="}, "encrypt data"),
		"encrypt data response identifiers must match the request identifiers")
}

func TestValidateResponseItemIdentifiers(t *testing.T) {
	wantNoError(t, validateResponseItemIdentifiers([]string{"a", "b"}, "sign status"))
	wantResponseShapeError(t,
		validateResponseItemIdentifiers([]string{"a", "a"}, "sign status"),
		"sign status response identifiers must be unique")
	wantResponseShapeError(t,
		validateResponseItemIdentifiers([]string{"a", "  "}, "sign status"),
		"sign status response identifiers must not be blank")
}

func TestValidateSignatureResultItem(t *testing.T) {
	item := func(status mdl.OperationStatus, signature, reason *string) mdl.SignatureResultItemV2Dto {
		return mdl.SignatureResultItemV2Dto{Identifier: "a", Status: status, Signature: signature, Reason: reason}
	}
	wantNoError(t, validateSignatureResultItem(item(mdl.OPERATIONSTATUS_COMPLETED, strPtr("AA=="), nil)))
	wantNoError(t, validateSignatureResultItem(item(mdl.OPERATIONSTATUS_IN_PROGRESS, nil, nil)))
	wantNoError(t, validateSignatureResultItem(item(mdl.OPERATIONSTATUS_FAILED, nil, strPtr("boom"))))

	wantResponseShapeError(t,
		validateSignatureResultItem(item(mdl.OPERATIONSTATUS_COMPLETED, strPtr(""), nil)),
		"signature must not be empty when status is completed")
	wantResponseShapeError(t,
		validateSignatureResultItem(item(mdl.OPERATIONSTATUS_IN_PROGRESS, strPtr(""), nil)),
		"result must be absent unless status is completed")
	wantResponseShapeError(t,
		validateSignatureResultItem(item(mdl.OPERATIONSTATUS_COMPLETED, strPtr("AA=="), strPtr(""))),
		"reason must be absent unless status is failed or cancelled")
	// completed with no signature at all: validateStatusShape must report it
	// before the signature dereference below it runs.
	wantResponseShapeError(t,
		validateSignatureResultItem(item(mdl.OPERATIONSTATUS_COMPLETED, nil, nil)),
		"result is required when status is completed")
}

func TestValidateSignStatusShape(t *testing.T) {
	sig := strPtr("AA==")
	wantResponseShapeError(t, validateSignStatusShape(&mdl.SignOperationStatusResponseV2Dto{}), "items must not be empty")
	wantResponseShapeError(t, validateSignStatusShape(&mdl.SignOperationStatusResponseV2Dto{Items: []mdl.SignatureResultItemV2Dto{
		{Identifier: "a", Status: mdl.OPERATIONSTATUS_COMPLETED, Signature: sig},
		{Identifier: "a", Status: mdl.OPERATIONSTATUS_COMPLETED, Signature: sig},
	}}), "sign status response identifiers must be unique")
	wantResponseShapeError(t, validateSignStatusShape(&mdl.SignOperationStatusResponseV2Dto{Items: []mdl.SignatureResultItemV2Dto{
		{Identifier: "a", Status: mdl.OPERATIONSTATUS_COMPLETED},
	}}), "result is required when status is completed")
	wantNoError(t, validateSignStatusShape(&mdl.SignOperationStatusResponseV2Dto{Items: []mdl.SignatureResultItemV2Dto{
		{Identifier: "a", Status: mdl.OPERATIONSTATUS_COMPLETED, Signature: sig},
		{Identifier: "b", Status: mdl.OPERATIONSTATUS_IN_PROGRESS},
	}}))
}

func TestValidateResponseRejectsNil(t *testing.T) {
	called := false
	check := func(*mdl.TokenStatusResponseV2Dto) error { called = true; return nil }
	if err := validateResponse[mdl.TokenStatusResponseV2Dto](nil, check); err != ErrNilResponse {
		t.Errorf("nil response: err = %v, want ErrNilResponse", err)
	}
	if called {
		t.Error("check must not run on a nil response")
	}
	wantNoError(t, validateResponse(&mdl.TokenStatusResponseV2Dto{Status: mdl.TOKENSTATUSV2_CONNECTED}, validateTokenStatus))
}

func TestValidateTokenStatus(t *testing.T) {
	wantNoError(t, validateTokenStatus(&mdl.TokenStatusResponseV2Dto{Status: mdl.TOKENSTATUSV2_CONNECTED}))
	wantResponseShapeError(t, validateTokenStatus(&mdl.TokenStatusResponseV2Dto{}), "token status must be a known token status")
	wantResponseShapeError(t, validateTokenStatus(&mdl.TokenStatusResponseV2Dto{Status: "bogus"}), "token status must be a known token status")
}

func TestValidateKnownEnums(t *testing.T) {
	wantNoError(t, validateKnownEnums([]mdl.KeyUsage{mdl.KEYUSAGE_SIGN, mdl.KEYUSAGE_VERIFY}, "key usages"))
	wantNoError(t, validateKnownEnums[mdl.KeyUsage](nil, "key usages"))
	wantResponseShapeError(t, validateKnownEnums([]mdl.KeyUsage{mdl.KEYUSAGE_SIGN, "bogus"}, "key usages"),
		"key usages must contain only known values")
	wantResponseShapeError(t, validateKnownEnums([]mdl.KeyRequestType{""}, "key request types"),
		"key request types must contain only known values")
}

func TestValidateMetadataElements(t *testing.T) {
	wantNoError(t, validateMetadataElements(nil, "operationMeta"))
	wantNoError(t, validateMetadataElements([]mdl.MetadataAttribute{metaAttr()}, "operationMeta"))
	wantNoError(t, validateMetadataElements([]mdl.MetadataAttribute{{MetadataAttributeV3: &mdl.MetadataAttributeV3{}}}, "operationMeta"))
	const msg = "operationMeta entries must populate exactly one metadata attribute variant"
	wantResponseShapeError(t, validateMetadataElements([]mdl.MetadataAttribute{metaAttr(), {}}, "operationMeta"), msg)
	wantResponseShapeError(t, validateMetadataElements([]mdl.MetadataAttribute{
		{MetadataAttributeV2: &mdl.MetadataAttributeV2{}, MetadataAttributeV3: &mdl.MetadataAttributeV3{}},
	}, "operationMeta"), msg)
}

// A zero-value element anywhere in the populated arm is caught before the
// mode-dependent rules, whichever list it sits in.
func TestValidateKeyCreationShapeRejectsZeroValueMetadataElements(t *testing.T) {
	secret := &mdl.KeyCreationResponse{SecretKeyDataResponseV2Dto: &mdl.SecretKeyDataResponseV2Dto{
		KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
		KeyData:        mdl.NewSecretKeyDataV2Dto(mdl.KEYALGORITHM_RSA, 2048),
		KeyMeta:        []mdl.MetadataAttribute{{}},
	}}
	wantResponseShapeError(t, validateKeyCreationShape(false, secret), "keyMeta entries must populate exactly one metadata attribute variant")

	secret.SecretKeyDataResponseV2Dto.KeyMeta = []mdl.MetadataAttribute{metaAttr()}
	secret.SecretKeyDataResponseV2Dto.KeyData.Metadata = []mdl.MetadataAttribute{{}}
	wantResponseShapeError(t, validateKeyCreationShape(false, secret), "keyData.metadata entries must populate exactly one metadata attribute variant")

	pairCases := []struct {
		mutate func(*mdl.KeyPairDataResponseV2Dto)
		field  string
	}{
		{func(v *mdl.KeyPairDataResponseV2Dto) { v.KeyPairMeta = []mdl.MetadataAttribute{{}} }, "keyPairMeta"},
		{func(v *mdl.KeyPairDataResponseV2Dto) { v.PublicKeyData.KeyMeta = []mdl.MetadataAttribute{{}} }, "publicKeyData.keyMeta"},
		{func(v *mdl.KeyPairDataResponseV2Dto) { v.PublicKeyData.KeyData.Metadata = []mdl.MetadataAttribute{{}} }, "publicKeyData.keyData.metadata"},
		{func(v *mdl.KeyPairDataResponseV2Dto) { v.PrivateKeyData.KeyMeta = []mdl.MetadataAttribute{{}} }, "privateKeyData.keyMeta"},
		{func(v *mdl.KeyPairDataResponseV2Dto) { v.PrivateKeyData.KeyData.Metadata = []mdl.MetadataAttribute{{}} }, "privateKeyData.keyData.metadata"},
	}
	for _, tc := range pairCases {
		pair := keyPair(tc.mutate)
		wantResponseShapeError(t, validateKeyCreationShape(false, &mdl.KeyCreationResponse{KeyPairDataResponseV2Dto: pair}),
			tc.field+" entries must populate exactly one metadata attribute variant")
	}
}

// validateResponse's marshal probe: a response that passes every field-level
// guard but that encoding/json refuses is rejected with the generic message,
// and a well-formed one passes.
func TestValidateResponseRejectsUnencodableResponse(t *testing.T) {
	ok := func(*mdl.KeyOperationResponseV2Dto) error { return nil }
	wantNoError(t, validateResponse(&mdl.KeyOperationResponseV2Dto{}, ok))

	unset := &mdl.KeyOperationResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{{
		MetadataAttributeV2: &mdl.MetadataAttributeV2{Content: []mdl.BaseAttributeContentDtoV2{{}}},
	}}}
	wantResponseShapeError(t, validateResponse(unset, ok), "response cannot be encoded as JSON")

	nan := &mdl.KeyOperationResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{{
		MetadataAttributeV2: &mdl.MetadataAttributeV2{AdditionalProperties: map[string]interface{}{"bad": math.NaN()}},
	}}}
	wantResponseShapeError(t, validateResponse(nan, ok), "response cannot be encoded as JSON")

	// The probe runs after check, so check's own message wins.
	boom := errResponseShape("boom")
	if err := validateResponse(unset, func(*mdl.KeyOperationResponseV2Dto) error { return boom }); err != boom {
		t.Errorf("err = %v, want check's error", err)
	}
}

func TestSignatureResultIdentifiers(t *testing.T) {
	got := signatureResultIdentifiers([]mdl.SignatureResultItemV2Dto{{Identifier: "a"}, {Identifier: "b"}})
	if len(got) != 2 || got[0] != "a" || got[1] != "b" {
		t.Errorf("signatureResultIdentifiers(...) = %v, want [a b]", got)
	}
	if got := signatureResultIdentifiers(nil); len(got) != 0 {
		t.Errorf("signatureResultIdentifiers(nil) = %v, want empty", got)
	}
}
