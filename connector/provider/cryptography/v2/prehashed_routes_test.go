package cryptography_test

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"net/http"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

const signPath = "/v2/cryptographyProvider/operations/sign"

func signedBatch() *mdl.SignDataResponseV2Dto {
	return &mdl.SignDataResponseV2Dto{Signatures: []mdl.SignatureDataV2Dto{{Identifier: "d-1", Data: "AA=="}}}
}

// prehashedSignBody is a prehashed sign request selecting algorithm, whose one
// item is digest.
func prehashedSignBody(t *testing.T, executionMode string, algorithm cryptography.SignatureAlgorithm, digest []byte) string {
	t.Helper()
	selection, err := json.Marshal([]mdl.RequestAttribute{cryptography.SignatureAlgorithmSelection(algorithm)})
	if err != nil {
		t.Fatalf("marshal selection: %v", err)
	}
	body := strings.Replace(signDataBodyWithMode(executionMode, "prehashedDigest"),
		`"signatureAttributes":[]`, `"signatureAttributes":`+string(selection), 1)
	return strings.Replace(body, `"data":"AA=="`, `"data":"`+base64.StdEncoding.EncodeToString(digest)+`"`, 1)
}

// validPrehashedSignBody selects SHA256withECDSA and carries a 32-byte digest.
func validPrehashedSignBody(t *testing.T, executionMode string) string {
	return prehashedSignBody(t, executionMode, cryptography.SignatureAlgorithmSHA256WithECDSA, make([]byte, 32))
}

// countingProvider counts the SignData calls that reach the base provider.
type countingProvider struct {
	stubProvider
	signCalls int
}

func (c *countingProvider) SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	c.signCalls++
	return c.stubProvider.SignData(ctx, req)
}

func TestPrehashedSignAnswers422WithoutItsProvider(t *testing.T) {
	p := &countingProvider{}

	rec := post(t, newTestServer(t, p), signPath, signDataBodyWithMode("synchronous", "prehashedDigest"))

	assertProblem(t, rec, http.StatusUnprocessableEntity, "PARAMETER_UNSUPPORTED")
	if p.signCalls != 0 {
		t.Fatalf("SignData called %d times for a prehashed request", p.signCalls)
	}
}

func TestPrehashedSignReachesThePrehashedProvider(t *testing.T) {
	p := &countingProvider{}
	stub := &stubPrehashed{resp: signedBatch()}
	srv := newTestServer(t, p, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, validPrehashedSignBody(t, "synchronous"))

	if rec.Code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
	}
	if stub.got == nil {
		t.Fatal("prehashed provider was not called")
	}
	if p.signCalls != 0 {
		t.Fatalf("SignData called %d times for a prehashed request", p.signCalls)
	}
}

func TestPrehashedSignRendersAcceptedAs202(t *testing.T) {
	stub := &stubPrehashed{accepted: true, resp: &mdl.SignDataResponseV2Dto{OperationMeta: []mdl.MetadataAttribute{metadataAttributeFixture()}}}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, validPrehashedSignBody(t, "asynchronous"))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
}

func TestPrehashedSignIsHeldToTheCallersExecutionMode(t *testing.T) {
	stub := &stubPrehashed{accepted: true, resp: signedBatch()}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, validPrehashedSignBody(t, "synchronous"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data requested synchronously must not be accepted for asynchronous execution")
}

func TestPrehashedSignMapsProviderErrorToProblem(t *testing.T) {
	stub := &stubPrehashed{err: cryptography.ErrSignatureAlgorithmUnsupported}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, validPrehashedSignBody(t, "synchronous"))

	assertProblem(t, rec, http.StatusUnprocessableEntity, "PARAMETER_UNSUPPORTED")
}

func TestPrehashedSignRefusesAnAlgorithmItIsNotDefinedFor(t *testing.T) {
	for _, algorithm := range []cryptography.SignatureAlgorithm{
		cryptography.SignatureAlgorithmEd25519, cryptography.SignatureAlgorithmMLDSA65, cryptography.SignatureAlgorithmSLHDSASHA2128S,
	} {
		t.Run(string(algorithm), func(t *testing.T) {
			stub := &stubPrehashed{resp: signedBatch()}
			srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

			rec := post(t, srv, signPath, prehashedSignBody(t, "synchronous", algorithm, make([]byte, 64)))

			problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "PARAMETER_UNSUPPORTED")
			assertDetail(t, problem, "prehashed signing is not defined for the selected signature algorithm")
			if stub.got != nil {
				t.Fatal("prehashed provider was called for an algorithm prehashed signing does not cover")
			}
		})
	}
}

func TestPrehashedSignRefusesAnItemOfTheWrongLength(t *testing.T) {
	cases := map[string]struct {
		algorithm cryptography.SignatureAlgorithm
		digest    []byte
	}{
		"longer than SHA-256":  {cryptography.SignatureAlgorithmSHA256WithECDSA, make([]byte, 64)},
		"shorter than SHA-384": {cryptography.SignatureAlgorithmSHA384WithRSAPSS, make([]byte, 32)},
		"shorter than SHA-512": {cryptography.SignatureAlgorithmSHA512WithRSA, make([]byte, 48)},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			stub := &stubPrehashed{resp: signedBatch()}
			srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

			rec := post(t, srv, signPath, prehashedSignBody(t, "synchronous", c.algorithm, c.digest))

			assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			if stub.got != nil {
				t.Fatal("prehashed provider was called for an item of the wrong length")
			}
		})
	}
}

func TestPrehashedSignAcceptsEachDigestLength(t *testing.T) {
	cases := map[cryptography.SignatureAlgorithm]int{
		cryptography.SignatureAlgorithmSHA256WithRSA:    32,
		cryptography.SignatureAlgorithmSHA384WithECDSA:  48,
		cryptography.SignatureAlgorithmSHA512WithRSAPSS: 64,
	}
	for algorithm, size := range cases {
		t.Run(string(algorithm), func(t *testing.T) {
			stub := &stubPrehashed{resp: signedBatch()}
			srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

			rec := post(t, srv, signPath, prehashedSignBody(t, "synchronous", algorithm, make([]byte, size)))

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
			}
		})
	}
}

func TestDataAndAbsentModeReachSignData(t *testing.T) {
	bodies := map[string]string{
		"data":   signDataBodyWithMode("synchronous", "data"),
		"absent": signDataBody("synchronous"),
		"null":   strings.Replace(signDataBody("synchronous"), `"signatureAttributes"`, `"signatureInputMode":null,"signatureAttributes"`, 1),
	}
	for name, body := range bodies {
		t.Run(name, func(t *testing.T) {
			p := &countingProvider{stubProvider: stubProvider{signDataResp: signedBatch()}}
			stub := &stubPrehashed{resp: signedBatch()}
			srv := newTestServer(t, p, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

			rec := post(t, srv, signPath, body)

			if rec.Code != http.StatusOK {
				t.Fatalf("status = %d, want 200; body %s", rec.Code, rec.Body)
			}
			if p.signCalls != 1 {
				t.Fatalf("SignData called %d times, want 1", p.signCalls)
			}
			if stub.got != nil {
				t.Fatal("prehashed provider received a data request")
			}
		})
	}
}

func TestPrehashedSigningFeatureRequiresTheProvider(t *testing.T) {
	_, err := cryptography.NewHandler(&stubProvider{},
		cryptography.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_PREHASHED_SIGNING))))

	if err == nil || !strings.Contains(err.Error(), "WithPrehashedSigning") {
		t.Fatalf("NewHandler error = %v, want one naming WithPrehashedSigning", err)
	}
}

func TestWithPrehashedSigningRejectsNil(t *testing.T) {
	_, err := cryptography.NewHandler(&stubProvider{}, cryptography.WithPrehashedSigning(nil))

	if err == nil || !strings.Contains(err.Error(), "prehashed sign provider must not be nil") {
		t.Fatalf("NewHandler error = %v, want the nil refusal", err)
	}
}

func TestUnknownInputModeIsRejectedWhileDecoding(t *testing.T) {
	p := &countingProvider{}
	stub := &stubPrehashed{}
	srv := newTestServer(t, p, cryptography.WithPrehashedSigning(stub))

	rec := post(t, srv, signPath, signDataBodyWithMode("synchronous", "prehashed"))

	assertProblem(t, rec, http.StatusBadRequest, "INVALID_JSON")
	if p.signCalls != 0 || stub.got != nil {
		t.Fatal("a provider was called for an unknown input mode")
	}
}

func TestPrehashedRequestIsGuardedBeforeRouting(t *testing.T) {
	valid := validPrehashedSignBody(t, "synchronous")
	item := `"data":[{"identifier":"d-1","data":"` + base64.StdEncoding.EncodeToString(make([]byte, 32)) + `"}]`
	cases := map[string]struct{ body, detail string }{
		"empty payload": {strings.Replace(valid, item, `"data":[{"identifier":"d-1","data":""}]`, 1), "data entries must not carry empty data"},
		"empty batch":   {strings.Replace(valid, item, `"data":[]`, 1), "data must not be empty"},
	}
	for name, c := range cases {
		t.Run(name, func(t *testing.T) {
			p := &countingProvider{}
			stub := &stubPrehashed{}
			srv := newTestServer(t, p, cryptography.WithPrehashedSigning(stub))

			rec := post(t, srv, signPath, c.body)

			problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			assertDetail(t, problem, c.detail)
			if p.signCalls != 0 || stub.got != nil {
				t.Fatal("a provider was called for an invalid request")
			}
		})
	}
}

func TestPrehashedSignChecksEveryItem(t *testing.T) {
	digest := base64.StdEncoding.EncodeToString(make([]byte, 48))
	short := base64.StdEncoding.EncodeToString(make([]byte, 32))
	body := strings.Replace(
		prehashedSignBody(t, "synchronous", cryptography.SignatureAlgorithmSHA384WithECDSA, make([]byte, 48)),
		`"data":"`+digest+`"}]`, `"data":"`+digest+`"},{"identifier":"d-2","data":"`+short+`"}]`, 1)

	assertPrehashedItemRefused(t, body, "data entries must be 48-byte digests for SHA384withECDSA")
}

func TestPrehashedSignRefusesAnItemThatIsNotBase64(t *testing.T) {
	digest := base64.StdEncoding.EncodeToString(make([]byte, 48))
	// The 48 bytes before the invalid character still decode, so only the
	// decoding error tells this item apart from a valid SHA-384 digest.
	body := strings.Replace(
		prehashedSignBody(t, "synchronous", cryptography.SignatureAlgorithmSHA384WithECDSA, make([]byte, 48)),
		`"data":"`+digest+`"`, `"data":"`+digest+`!"`, 1)

	assertPrehashedItemRefused(t, body, "data entries must be 48-byte digests for SHA384withECDSA")
}

func assertPrehashedItemRefused(t *testing.T, body, detail string) {
	t.Helper()
	stub := &stubPrehashed{resp: signedBatch()}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, body)

	problem := assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	assertDetail(t, problem, detail)
	if stub.got != nil {
		t.Fatal("prehashed provider was called for an invalid item")
	}
}

func TestInputModeTreatsAbsentAsData(t *testing.T) {
	absent := &mdl.SignDataRequestV2Dto{}
	if got := cryptography.InputMode(absent); got != mdl.SIGNATUREINPUTMODE_DATA {
		t.Errorf("InputMode(absent) = %q, want data", got)
	}
	prehashed := &mdl.SignDataRequestV2Dto{}
	prehashed.SetSignatureInputMode(mdl.SIGNATUREINPUTMODE_PREHASHED_DIGEST)
	if got := cryptography.InputMode(prehashed); got != mdl.SIGNATUREINPUTMODE_PREHASHED_DIGEST {
		t.Errorf("InputMode(prehashed) = %q, want prehashedDigest", got)
	}
}
