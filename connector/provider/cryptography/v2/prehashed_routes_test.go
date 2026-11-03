package cryptography_test

import (
	"context"
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

	rec := post(t, srv, signPath, signDataBodyWithMode("synchronous", "prehashedDigest"))

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

	rec := post(t, srv, signPath, signDataBodyWithMode("asynchronous", "prehashedDigest"))

	if rec.Code != http.StatusAccepted {
		t.Fatalf("status = %d, want 202; body %s", rec.Code, rec.Body)
	}
}

func TestPrehashedSignIsHeldToTheCallersExecutionMode(t *testing.T) {
	stub := &stubPrehashed{accepted: true, resp: signedBatch()}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, signDataBodyWithMode("synchronous", "prehashedDigest"))

	problem := assertProblem(t, rec, http.StatusInternalServerError, "INTERNAL_SERVER_ERROR")
	assertDetail(t, problem, "provider response violates the contract: sign data requested synchronously must not be accepted for asynchronous execution")
}

func TestPrehashedSignMapsProviderErrorToProblem(t *testing.T) {
	stub := &stubPrehashed{err: cryptography.ErrSignatureAlgorithmUnsupported}
	srv := newTestServer(t, &countingProvider{}, cryptography.WithPrehashedSigning(stub), features(mdl.FEATUREFLAG_PREHASHED_SIGNING))

	rec := post(t, srv, signPath, signDataBodyWithMode("synchronous", "prehashedDigest"))

	assertProblem(t, rec, http.StatusUnprocessableEntity, "PARAMETER_UNSUPPORTED")
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
	valid := signDataBodyWithMode("synchronous", "prehashedDigest")
	item := `"data":[{"identifier":"d-1","data":"AA=="}]`
	cases := map[string]string{
		"empty payload": strings.Replace(valid, item, `"data":[{"identifier":"d-1","data":""}]`, 1),
		"empty batch":   strings.Replace(valid, item, `"data":[]`, 1),
	}
	for name, body := range cases {
		t.Run(name, func(t *testing.T) {
			p := &countingProvider{}
			stub := &stubPrehashed{}
			srv := newTestServer(t, p, cryptography.WithPrehashedSigning(stub))

			rec := post(t, srv, signPath, body)

			assertProblem(t, rec, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
			if p.signCalls != 0 || stub.got != nil {
				t.Fatal("a provider was called for an invalid request")
			}
		})
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
