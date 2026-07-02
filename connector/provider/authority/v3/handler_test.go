package authority_test

import (
	"context"
	"net/http"
	"net/http/httptest"
	"testing"

	mdlv2 "github.com/OmniTrustILM/go-sdk/connector/model/authority/v2"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	mdlsec "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
	authorityv2 "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v2"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// stubProvider implements authority.Provider with inert responses — enough
// to mount routes; route behavior is covered by the example's live tests.
type stubProvider struct{}

func (stubProvider) Issue(context.Context, *mdl.CertificateSignRequestDtoV3) (*mdl.CertificateDataResponseDtoV3, bool, error) {
	return mdl.NewCertificateDataResponseDtoV3(), false, nil
}
func (stubProvider) IssueStatus(context.Context, *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateOperationStatusResponseDtoV3, error) {
	return mdl.NewCertificateOperationStatusResponseDtoV3(mdl.CERTIFICATEOPERATIONSTATUSV3_COMPLETED), nil
}
func (stubProvider) CancelIssue(context.Context, *mdl.CertificateOperationCancelRequestDtoV3) error {
	return nil
}
func (stubProvider) Renew(context.Context, *mdl.CertificateRenewRequestDtoV3) (*mdl.CertificateDataResponseDtoV3, bool, error) {
	return mdl.NewCertificateDataResponseDtoV3(), false, nil
}
func (stubProvider) Register(context.Context, *mdl.CertificateRegistrationRequestDtoV3) (*mdl.CertificateDataResponseDtoV3, bool, error) {
	return mdl.NewCertificateDataResponseDtoV3(), false, nil
}
func (stubProvider) RegisterStatus(context.Context, *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateOperationStatusResponseDtoV3, error) {
	return mdl.NewCertificateOperationStatusResponseDtoV3(mdl.CERTIFICATEOPERATIONSTATUSV3_COMPLETED), nil
}
func (stubProvider) CancelRegister(context.Context, *mdl.CertificateOperationCancelRequestDtoV3) error {
	return nil
}
func (stubProvider) Revoke(context.Context, *mdl.CertificateRevocationRequestDtoV3) (*mdl.CertificateDataResponseDtoV3, bool, error) {
	return nil, false, nil
}
func (stubProvider) RevokeStatus(context.Context, *mdl.CertificateOperationStatusRequestDtoV3) (*mdl.CertificateOperationStatusResponseDtoV3, error) {
	return mdl.NewCertificateOperationStatusResponseDtoV3(mdl.CERTIFICATEOPERATIONSTATUSV3_COMPLETED), nil
}
func (stubProvider) CancelRevoke(context.Context, *mdl.CertificateOperationCancelRequestDtoV3) error {
	return nil
}
func (stubProvider) Identify(context.Context, *mdl.CertificateIdentificationRequestDtoV3) (*mdl.CertificateIdentificationResponseDtoV3, error) {
	return mdl.NewCertificateIdentificationResponseDtoV3(nil), nil
}
func (stubProvider) CheckAuthorityConnection(context.Context, []mdl.RequestAttribute) error {
	return nil
}
func (stubProvider) GetCrl(context.Context, *mdl.CrlRequestDtoV3) (*mdl.CrlResponseDtoV3, error) {
	return mdl.NewCrlResponseDtoV3(""), nil
}
func (stubProvider) GetCaCertificates(context.Context, *mdl.CaCertificatesRequestDtoV3) (*mdl.CaCertificatesResponseDtoV3, error) {
	return mdl.NewCaCertificatesResponseDtoV3(nil), nil
}

// stubSecret implements secret.Provider with inert responses.
type stubSecret struct{}

func (stubSecret) CreateSecret(context.Context, *mdlsec.CreateSecretRequestDto) (*mdlsec.SecretResponseDto, error) {
	return &mdlsec.SecretResponseDto{}, nil
}
func (stubSecret) UpdateSecret(context.Context, *mdlsec.UpdateSecretRequestDto) (*mdlsec.SecretResponseDto, error) {
	return &mdlsec.SecretResponseDto{}, nil
}
func (stubSecret) DeleteSecret(context.Context, *mdlsec.SecretRequestDto) error { return nil }
func (stubSecret) RotateSecret(context.Context, *mdlsec.SecretRequestDto) (*mdlsec.SecretResponseDto, error) {
	return &mdlsec.SecretResponseDto{}, nil
}
func (stubSecret) GetSecretContent(context.Context, *mdlsec.SecretRequestDto, string) (*mdlsec.SecretContentResponseDto, error) {
	return &mdlsec.SecretContentResponseDto{}, nil
}
func (stubSecret) CheckVaultConnection(context.Context, []mdlsec.RequestAttribute) error { return nil }

// stubAuthorityV2 implements authorityv2.Provider with inert responses.
type stubAuthorityV2 struct{}

func (stubAuthorityV2) ListAuthorityInstances(context.Context) ([]mdlv2.AuthorityProviderInstanceDto, error) {
	return nil, nil
}
func (stubAuthorityV2) CreateAuthorityInstance(context.Context, *mdlv2.AuthorityProviderInstanceRequestDto) (*mdlv2.AuthorityProviderInstanceDto, error) {
	return &mdlv2.AuthorityProviderInstanceDto{}, nil
}
func (stubAuthorityV2) GetAuthorityInstance(context.Context, string) (*mdlv2.AuthorityProviderInstanceDto, error) {
	return &mdlv2.AuthorityProviderInstanceDto{}, nil
}
func (stubAuthorityV2) UpdateAuthorityInstance(context.Context, string, *mdlv2.AuthorityProviderInstanceRequestDto) (*mdlv2.AuthorityProviderInstanceDto, error) {
	return &mdlv2.AuthorityProviderInstanceDto{}, nil
}
func (stubAuthorityV2) RemoveAuthorityInstance(context.Context, string) error { return nil }
func (stubAuthorityV2) GetConnection(context.Context, string) error           { return nil }
func (stubAuthorityV2) GetCaCertificates(context.Context, string, *mdlv2.CaCertificatesRequestDto) (*mdlv2.CaCertificatesResponseDto, error) {
	return &mdlv2.CaCertificatesResponseDto{}, nil
}
func (stubAuthorityV2) GetCrl(context.Context, string, *mdlv2.CertificateRevocationListRequestDto) (*mdlv2.CertificateRevocationListResponseDto, error) {
	return &mdlv2.CertificateRevocationListResponseDto{}, nil
}
func (stubAuthorityV2) IssueCertificate(context.Context, string, *mdlv2.CertificateSignRequestDto) (*mdlv2.CertificateDataResponseDto, error) {
	return &mdlv2.CertificateDataResponseDto{}, nil
}
func (stubAuthorityV2) RenewCertificate(context.Context, string, *mdlv2.CertificateRenewRequestDto) (*mdlv2.CertificateDataResponseDto, error) {
	return &mdlv2.CertificateDataResponseDto{}, nil
}
func (stubAuthorityV2) RevokeCertificate(context.Context, string, *mdlv2.CertRevocationDto) error {
	return nil
}
func (stubAuthorityV2) IdentifyCertificate(context.Context, string, *mdlv2.CertificateIdentificationRequestDto) (*mdlv2.CertificateIdentificationResponseDto, error) {
	return &mdlv2.CertificateIdentificationResponseDto{}, nil
}

// TestCombinableWithOtherProviders proves an authority/v3 Handler mounts on
// one shared.Connector alongside authority/v2 and secret/v1 without route
// conflicts (the stdlib ServeMux panics on conflicting patterns at
// registration time, which shared.New surfaces as a panic — so reaching the
// HTTP assertions below proves the composition is conflict-free).
func TestCombinableWithOtherProviders(t *testing.T) {
	v3h, err := authority.NewHandler(stubProvider{})
	if err != nil {
		t.Fatalf("v3 NewHandler: %v", err)
	}
	v2h, err := authorityv2.NewHandler(stubAuthorityV2{}, authorityv2.WithKinds("LegacyCA"))
	if err != nil {
		t.Fatalf("v2 NewHandler: %v", err)
	}
	sech, err := secret.NewHandler(stubSecret{})
	if err != nil {
		t.Fatalf("secret NewHandler: %v", err)
	}

	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "combo", Name: "combo", Version: "0.0.1"}),
		shared.Register(v3h),
		shared.Register(v2h),
		shared.Register(sech),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}

	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	// /v2/info reports all three interfaces.
	resp, err := http.Get(srv.URL + "/v2/info")
	if err != nil {
		t.Fatalf("GET /v2/info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/info = %d, want 200", resp.StatusCode)
	}

	// One representative route per provider answers (not 404).
	for _, probe := range []struct {
		method, path string
		wantNot      int
	}{
		{http.MethodGet, "/v3/authorityProvider/authorities/attributes", http.StatusNotFound},
		{http.MethodGet, "/v1/authorityProvider/authorities", http.StatusNotFound},
		{http.MethodGet, "/v1/secretProvider/vaults/attributes", http.StatusNotFound},
	} {
		req, _ := http.NewRequest(probe.method, srv.URL+probe.path, nil)
		r, err := http.DefaultClient.Do(req)
		if err != nil {
			t.Fatalf("%s %s: %v", probe.method, probe.path, err)
		}
		r.Body.Close()
		if r.StatusCode == probe.wantNot {
			t.Errorf("%s %s = %d; route not mounted", probe.method, probe.path, r.StatusCode)
		}
	}
}
