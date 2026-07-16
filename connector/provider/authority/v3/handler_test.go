package authority_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
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

// defsProvider is an AttributeDefinitionsProvider that returns whatever DTO it
// was given on every ListDefinitions call — modelling a provider that caches a
// single shared instance. A nil dto exercises the (nil, nil) contract-violation
// path.
type defsProvider struct{ dto *mdl.AttributeDefinitionsDto }

func (d defsProvider) ListDefinitions(context.Context) (*mdl.AttributeDefinitionsDto, error) {
	return d.dto, nil
}
func (defsProvider) GetDefinition(context.Context, string) (*mdl.BaseAttributeDto, error) {
	return nil, nil
}
func (defsProvider) Callback(context.Context, *mdl.AttributeCallbackRequestDto) (*mdl.AttributeCallbackResponseDto, error) {
	return nil, nil
}

// dataDef builds a minimal DATA BaseAttributeDto carrying the given UUID.
func dataDef(uuid string) mdl.BaseAttributeDto {
	d := mdl.NewDataAttributeV3(uuid, "n-"+uuid, 3, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewDataAttributeProperties("L", true, true, false, false, false, false), mdl.ATTRIBUTEVERSION_V3)
	w := mdl.DataAttributeV3AsBaseAttributeDtoV3(d)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&w)
}

func attributesServer(t *testing.T, defs authority.AttributeDefinitionsProvider) *httptest.Server {
	t.Helper()
	h, err := authority.NewHandler(stubProvider{}, authority.WithAttributeDefinitions(defs))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "a", Name: "a", Version: "0.0.1"}),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func getDefs(t *testing.T, srv *httptest.Server, query string) (mdl.AttributeDefinitionsDto, string) {
	t.Helper()
	resp, err := http.Get(srv.URL + "/v2/attributes" + query)
	if err != nil {
		t.Fatalf("GET /v2/attributes%s: %v", query, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/attributes%s = %d, want 200", query, resp.StatusCode)
	}
	raw, _ := io.ReadAll(resp.Body)
	var out mdl.AttributeDefinitionsDto
	if err := json.Unmarshal(raw, &out); err != nil {
		t.Fatalf("decode: %v (body %s)", err, raw)
	}
	return out, string(raw)
}

// TestListDefinitionsDoesNotMutateProviderResult proves the ?uuids= filter
// builds a fresh response and never narrows or races on the DTO/slice the
// provider returned (a provider may cache and share one instance).
func TestListDefinitionsDoesNotMutateProviderResult(t *testing.T) {
	cached := &mdl.AttributeDefinitionsDto{
		ConnectorVersion: "1.0.0",
		Definitions:      []mdl.BaseAttributeDto{dataDef("uuid-a"), dataDef("uuid-b")},
	}
	srv := attributesServer(t, defsProvider{dto: cached})

	// A filtered request must not shrink the provider's shared slice.
	filtered, _ := getDefs(t, srv, "?uuids=uuid-a")
	if len(filtered.Definitions) != 1 {
		t.Fatalf("filtered response has %d definitions, want 1", len(filtered.Definitions))
	}
	if len(cached.Definitions) != 2 {
		t.Fatalf("provider's cached slice was mutated to %d definitions, want 2", len(cached.Definitions))
	}

	// A subsequent unfiltered request still sees the full set.
	all, _ := getDefs(t, srv, "")
	if len(all.Definitions) != 2 {
		t.Fatalf("unfiltered response has %d definitions after a filtered call, want 2", len(all.Definitions))
	}
}

// TestListDefinitionsNilResultDegradesToEmpty proves a wired provider that
// returns (nil, nil) yields 200 with an empty (not null) definition set,
// honoring the DTO's required connectorVersion/definitions.
func TestListDefinitionsNilResultDegradesToEmpty(t *testing.T) {
	srv := attributesServer(t, defsProvider{dto: nil})
	out, raw := getDefs(t, srv, "")
	if out.Definitions == nil {
		t.Errorf("definitions is null, want []: %s", raw)
	}
	if strings.Contains(raw, ":null") || strings.TrimSpace(raw) == "null" {
		t.Errorf("response body contains null: %s", raw)
	}
}

// TestGetDefinitionNilResultIs500 proves the single-resource handlers guard
// against a wired provider returning (nil, nil): rather than a 200 with a null
// body, that contract violation surfaces as a 500.
func TestGetDefinitionNilResultIs500(t *testing.T) {
	srv := attributesServer(t, defsProvider{}) // GetDefinition returns (nil, nil)
	resp, err := http.Get(srv.URL + "/v2/attributes/whatever")
	if err != nil {
		t.Fatalf("GET /v2/attributes/whatever: %v", err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusInternalServerError {
		t.Errorf("GetDefinition nil result = %d, want 500", resp.StatusCode)
	}
}
