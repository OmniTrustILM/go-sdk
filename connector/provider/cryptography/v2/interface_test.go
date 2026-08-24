package cryptography_test

import (
	"context"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// stubProvider implements cryptography.Provider. Every method returns the
// configured response/error pair for its own operation, defaulting to zero
// values when unset. Used to exercise NewHandler / Interface wiring as well
// as the per-route handler tests in routes_test.go and attributes_test.go.
type stubProvider struct {
	tokenStatus    *mdl.TokenStatusResponseV2Dto
	tokenStatusErr error

	tokenProfileKeyUsages    []mdl.KeyUsage
	tokenProfileKeyUsagesErr error

	keyRequestTypes    []mdl.KeyRequestType
	keyRequestTypesErr error

	createKeyResp     *mdl.KeyCreationResponse
	createKeyAccepted bool
	createKeyErr      error

	destroyKeyResp     *mdl.KeyOperationResponseV2Dto
	destroyKeyAccepted bool
	destroyKeyErr      error

	signDataResp     *mdl.SignDataResponseV2Dto
	signDataAccepted bool
	signDataErr      error

	verifyData    *mdl.VerifyDataResponseV2Dto
	verifyDataErr error

	encryptData    *mdl.EncryptDataResponseV2Dto
	encryptDataErr error

	decryptData    *mdl.DecryptDataResponseV2Dto
	decryptDataErr error

	randomData    *mdl.RandomDataResponseV2Dto
	randomDataErr error
}

func (s *stubProvider) TokenStatus(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) (*mdl.TokenStatusResponseV2Dto, error) {
	return s.tokenStatus, s.tokenStatusErr
}

func (s *stubProvider) TokenProfileKeyUsages(ctx context.Context, req *mdl.TokenScopedRequestV2Dto) ([]mdl.KeyUsage, error) {
	return s.tokenProfileKeyUsages, s.tokenProfileKeyUsagesErr
}

func (s *stubProvider) KeyRequestTypes(ctx context.Context, req *mdl.TokenProfileScopedRequestV2Dto) ([]mdl.KeyRequestType, error) {
	return s.keyRequestTypes, s.keyRequestTypesErr
}

func (s *stubProvider) CreateKey(ctx context.Context, req *mdl.CreateKeyRequestV2Dto) (*mdl.KeyCreationResponse, bool, error) {
	return s.createKeyResp, s.createKeyAccepted, s.createKeyErr
}

func (s *stubProvider) DestroyKey(ctx context.Context, req *mdl.DestroyKeyRequestV2Dto) (*mdl.KeyOperationResponseV2Dto, bool, error) {
	return s.destroyKeyResp, s.destroyKeyAccepted, s.destroyKeyErr
}

func (s *stubProvider) SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	return s.signDataResp, s.signDataAccepted, s.signDataErr
}

func (s *stubProvider) VerifyData(ctx context.Context, req *mdl.VerifyDataRequestV2Dto) (*mdl.VerifyDataResponseV2Dto, error) {
	return s.verifyData, s.verifyDataErr
}

func (s *stubProvider) EncryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.EncryptDataResponseV2Dto, error) {
	return s.encryptData, s.encryptDataErr
}

func (s *stubProvider) DecryptData(ctx context.Context, req *mdl.CipherDataRequestV2Dto) (*mdl.DecryptDataResponseV2Dto, error) {
	return s.decryptData, s.decryptDataErr
}

func (s *stubProvider) RandomData(ctx context.Context, req *mdl.RandomDataRequestV2Dto) (*mdl.RandomDataResponseV2Dto, error) {
	return s.randomData, s.randomDataErr
}

func TestInterfaceReportsCryptographyV2(t *testing.T) {
	h, err := cryptography.NewHandler(&stubProvider{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	got := h.Interface()

	if got.Code != shared.InterfaceCodeCryptography {
		t.Errorf("Code = %q, want %q", got.Code, shared.InterfaceCodeCryptography)
	}
	if got.Version != shared.VersionV2 {
		t.Errorf("Version = %q, want %q", got.Version, shared.VersionV2)
	}
	if got.Features != nil {
		t.Errorf("Features = %v, want nil for a handler with no WithFeatures", got.Features)
	}
}

func TestInterfaceAdvertisesAsynchronousWhenConfigured(t *testing.T) {
	h, err := cryptography.NewHandler(&stubProvider{},
		cryptography.Base(handlerbase.WithFeatures(string(mdl.FEATUREFLAG_ASYNCHRONOUS))),
	)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	got := h.Interface().Features

	if len(got) != 1 || got[0] != "asynchronous" {
		t.Errorf("Features = %v, want [asynchronous]", got)
	}
}

func TestNewHandlerRejectsNilProvider(t *testing.T) {
	if _, err := cryptography.NewHandler(nil); err == nil {
		t.Fatal("expected an error for a nil provider")
	}
}
