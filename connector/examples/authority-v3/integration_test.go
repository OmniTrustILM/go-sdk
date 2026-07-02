package main_test

// Integration tests for the authority-v3 example, a real
// in-memory X.509 CA, driven over the public HTTP interface via the shared
// testcontainers harness. Requests/responses use the generated
// connector/model/authority/v3 types; assertions include real crypto checks
// (issued cert chains to the CA root, CRL verifies and lists the revoked
// serial, registered subject is honored). Skips with no Docker or -short.

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/base64"
	"maps"
	"math/big"
	"net/http"
	"testing"
	"time"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
)

const (
	caName    = "demo-ca"  // APP_CA_NAME default
	apiKey    = "test-key" // APP_API_KEY for the test container
	badAPIKey = "wrong-key"
)

// Authority/issue attribute UUIDs (connector/examples/authority-v3/attrs.go).
const (
	caNameAttrUUID       = "9c1d6f1a-3f4b-4e26-b9a8-7d2e0c5b8a01"
	apiKeyAttrUUID       = "2f7e4d3c-8b1a-4c59-9e60-31d4f6a7b502"
	validityDaysAttrUUID = "6a8b2c4d-0e9f-4f13-a7d5-58c3b1e2f903"
)

// Route paths.
const (
	pathIssue       = "/v3/authorityProvider/certificates/issue"
	pathIssueStatus = "/v3/authorityProvider/certificates/issue/status"
	pathIssueCancel = "/v3/authorityProvider/certificates/issue/cancel"
	pathRenew       = "/v3/authorityProvider/certificates/renew"
	pathRegister    = "/v3/authorityProvider/certificates/register"
	pathRevoke      = "/v3/authorityProvider/certificates/revoke"
	pathIdentify    = "/v3/authorityProvider/certificates/identify"
	pathAuthorities = "/v3/authorityProvider/authorities"
	pathCrl         = "/v3/authorityProvider/authorities/crl"
	pathCaCerts     = "/v3/authorityProvider/authorities/caCertificates"
)

// --- harness setup ---------------------------------------------------------

func startAuthority(t *testing.T, extraEnv map[string]string) *itest.Harness {
	t.Helper()
	// Set both credential knobs explicitly so the suite is self-contained
	// and robust against changes to the example's defaults.
	env := map[string]string{"APP_CA_NAME": caName, "APP_API_KEY": apiKey}
	maps.Copy(env, extraEnv)
	return itest.Start(t, itest.Example{Path: "connector/examples/authority-v3", Env: env})
}

// --- attribute / request builders ------------------------------------------

func stringAttr(uuid, name, value string) mdl.RequestAttribute {
	c := mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
		Data: value, ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	})
	return mdl.RequestAttributeV3AsRequestAttribute(&mdl.RequestAttributeV3{
		Uuid: uuid, Name: name, ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Version: mdl.ATTRIBUTEVERSION_V3, Content: []mdl.BaseAttributeContentDtoV3{c},
	})
}

func intAttr(uuid, name string, value int32) mdl.RequestAttribute {
	c := mdl.IntegerAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.IntegerAttributeContentV3{
		Data: value, ContentType: mdl.ATTRIBUTECONTENTTYPE_INTEGER,
	})
	return mdl.RequestAttributeV3AsRequestAttribute(&mdl.RequestAttributeV3{
		Uuid: uuid, Name: name, ContentType: mdl.ATTRIBUTECONTENTTYPE_INTEGER,
		Version: mdl.ATTRIBUTEVERSION_V3, Content: []mdl.BaseAttributeContentDtoV3{c},
	})
}

func authAttrs(ca, key string) []mdl.RequestAttribute {
	return []mdl.RequestAttribute{
		stringAttr(caNameAttrUUID, "ca_name", ca),
		stringAttr(apiKeyAttrUUID, "api_key", key),
	}
}

func validAuth() []mdl.RequestAttribute { return authAttrs(caName, apiKey) }

func validityAttrs(days int32) []mdl.RequestAttribute {
	return []mdl.RequestAttribute{intAttr(validityDaysAttrUUID, "validity_days", days)}
}

// --- crypto helpers --------------------------------------------------------

// genCSR returns a base64 DER PKCS#10 CSR for the given common name.
func genCSR(t *testing.T, cn string) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	der, err := x509.CreateCertificateRequest(rand.Reader,
		&x509.CertificateRequest{Subject: pkix.Name{CommonName: cn}}, key)
	if err != nil {
		t.Fatalf("create CSR: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}

// parseCertB64 decodes a base64 DER certificate.
func parseCertB64(t *testing.T, b64 string) *x509.Certificate {
	t.Helper()
	der, err := base64.StdEncoding.DecodeString(b64)
	if err != nil {
		t.Fatalf("cert base64: %v", err)
	}
	cert, err := x509.ParseCertificate(der)
	if err != nil {
		t.Fatalf("parse cert: %v", err)
	}
	return cert
}

// metaString extracts the first string content of the meta attribute with
// the given name from a response's meta. It treats meta as the opaque,
// verbatim-replayed handle it is — used only to assert presence.
func metaValue(t *testing.T, meta []mdl.MetadataAttribute, name string) string {
	t.Helper()
	for _, m := range meta {
		v3 := m.MetadataAttributeV3
		if v3 == nil || v3.Name != name || len(v3.Content) == 0 {
			continue
		}
		if s := v3.Content[0].StringAttributeContentV3; s != nil {
			return s.Data
		}
	}
	return ""
}

// caRoot fetches and parses the CA root certificate via getCaCertificates.
func caRoot(t *testing.T, h *itest.Harness) *x509.Certificate {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCaCerts, Body: mdl.CaCertificatesRequestDtoV3{
		AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var out mdl.CaCertificatesResponseDtoV3
	resp.JSON(t, &out)
	if len(out.Certificates) == 0 || out.Certificates[0].CertificateData == nil {
		t.Fatalf("getCaCertificates returned no chain: %s", resp.Body)
	}
	return parseCertB64(t, *out.Certificates[0].CertificateData)
}

// issueCert issues a certificate for cn and returns the response DTO.
func issueCert(t *testing.T, h *itest.Harness, cn string) mdl.CertificateDataResponseDtoV3 {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssue, Body: mdl.CertificateSignRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		Request:             genCSR(t, cn),
		Attributes:          validityAttrs(90),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var out mdl.CertificateDataResponseDtoV3
	resp.JSON(t, &out)
	// Fatal guard here covers every caller: a non-200 leaves CertificateData
	// nil, and the callers dereference it — a panic would abort the whole
	// package instead of failing one test with a useful message.
	if out.CertificateData == nil {
		t.Fatalf("issueCert(%q): no certificateData\nbody: %s", cn, resp.Body)
	}
	return out
}

// --- health + info ----------------------------------------------------

func TestAuthorityV3HealthAndInfo(t *testing.T) {
	h := startAuthority(t, nil)
	h.AssertHealthy(t, "/v2/health")

	var info map[string]any
	if status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info); status != http.StatusOK {
		t.Fatalf("/v2/info = %d, want 200", status)
	}
	ifaces, _ := info["interfaces"].([]any)
	var ok bool
	for _, raw := range ifaces {
		if m, _ := raw.(map[string]any); m["code"] == "authority" && m["version"] == "v3" {
			ok = true
			break
		}
	}
	if !ok {
		t.Errorf("/v2/info missing {authority, v3} interface: %v", info["interfaces"])
	}
	h.AssertLogsConform(t)
}

// --- mandatory authority attributes (auth) ----------------------------

func TestAuthorityV3Auth(t *testing.T) {
	h := startAuthority(t, nil)

	// Valid -> 204.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: validAuth()})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// Wrong api_key -> 401 UNAUTHORIZED.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: authAttrs(caName, badAPIKey)})
	itest.AssertProblem(t, resp, http.StatusUnauthorized, "UNAUTHORIZED")

	// Missing api_key -> 422 VALIDATION_FAILED.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities,
		Body: []mdl.RequestAttribute{stringAttr(caNameAttrUUID, "ca_name", caName)}})
	itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "VALIDATION_FAILED")

	// Unknown ca_name -> 422 VALIDATION_FAILED.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathAuthorities, Body: authAttrs("other-ca", apiKey)})
	itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

// --- issue + chain verification ---------------------------------------

func TestAuthorityV3IssueVerifiesChain(t *testing.T) {
	h := startAuthority(t, nil)
	root := caRoot(t, h)

	issued := issueCert(t, h, "device-1.example.test")
	if issued.CertificateData == nil {
		t.Fatal("issue returned no certificateData")
	}
	leaf := parseCertB64(t, *issued.CertificateData)
	if leaf.Subject.CommonName != "device-1.example.test" {
		t.Errorf("issued CN = %q, want device-1.example.test", leaf.Subject.CommonName)
	}

	// Real chain verification against the CA root.
	roots := x509.NewCertPool()
	roots.AddCert(root)
	if _, err := leaf.Verify(x509.VerifyOptions{
		Roots:     roots,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageAny},
	}); err != nil {
		t.Errorf("issued cert does not chain to CA root: %v", err)
	}
	if metaValue(t, issued.Meta, "serial") == "" {
		t.Error("issue response carries no serial meta")
	}

	// Missing validity_days -> 422 VALIDATION_FAILED.
	bad := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssue, Body: mdl.CertificateSignRequestDtoV3{
		AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, Request: genCSR(t, "x"),
	}})
	itest.AssertProblem(t, bad, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
}

// --- renew ------------------------------------------------------------

func TestAuthorityV3Renew(t *testing.T) {
	h := startAuthority(t, nil)
	issued := issueCert(t, h, "renew-me.example.test")

	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRenew, Body: mdl.CertificateRenewRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		ExistingCertificate: *issued.CertificateData,
		Request:             ptr(genCSR(t, "renew-me.example.test")),
		Attributes:          validityAttrs(60),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var renewed mdl.CertificateDataResponseDtoV3
	resp.JSON(t, &renewed)
	if renewed.CertificateData == nil {
		t.Fatal("renew returned no certificateData")
	}
	oldSerial := parseCertB64(t, *issued.CertificateData).SerialNumber
	newSerial := parseCertB64(t, *renewed.CertificateData).SerialNumber
	if oldSerial.Cmp(newSerial) == 0 {
		t.Errorf("renewed serial %s equals original; want a fresh serial", newSerial)
	}
}

// --- revoke + CRL -----------------------------------------------------

func TestAuthorityV3RevokeAndCRL(t *testing.T) {
	h := startAuthority(t, nil)
	root := caRoot(t, h)
	issued := issueCert(t, h, "revoke-me.example.test")
	leaf := parseCertB64(t, *issued.CertificateData)

	// Revoke -> 204 (no body).
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRevoke, Body: mdl.CertificateRevocationRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		Certificate:         *issued.CertificateData,
		Reason:              mdl.CERTIFICATEREVOCATIONREASON_KEY_COMPROMISE,
	}})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// CRL -> 200, verifies against root, lists the revoked serial.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathCrl, Body: mdl.CrlRequestDtoV3{
		AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var crlResp mdl.CrlResponseDtoV3
	resp.JSON(t, &crlResp)

	crlDER, err := base64.StdEncoding.DecodeString(crlResp.Crl)
	if err != nil {
		t.Fatalf("crl base64: %v", err)
	}
	crl, err := x509.ParseRevocationList(crlDER)
	if err != nil {
		t.Fatalf("parse CRL: %v", err)
	}
	if err := crl.CheckSignatureFrom(root); err != nil {
		t.Errorf("CRL does not verify against CA root: %v", err)
	}
	var found bool
	for _, e := range crl.RevokedCertificateEntries {
		if e.SerialNumber.Cmp(leaf.SerialNumber) == 0 {
			found = true
			break
		}
	}
	if !found {
		t.Errorf("CRL does not list revoked serial %s", leaf.SerialNumber)
	}
}

// --- register -> issue-against-registration ---------------------------

func TestAuthorityV3RegisterThenIssue(t *testing.T) {
	h := startAuthority(t, nil)
	const registeredCN = "registered-device-7"

	// Register -> 200 with a registration_id meta handle.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathRegister, Body: mdl.CertificateRegistrationRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		SubjectDn:           ptr(registeredCN),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var reg mdl.CertificateDataResponseDtoV3
	resp.JSON(t, &reg)
	if metaValue(t, reg.Meta, "registration_id") == "" {
		t.Fatalf("register response carries no registration_id meta: %s", resp.Body)
	}

	// Issue against the registration (replay its meta verbatim). The
	// registered subject overrides the CSR subject.
	issueReq := mdl.CertificateSignRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		Request:             genCSR(t, "ignored-csr-subject"),
		Attributes:          validityAttrs(90),
		Meta:                reg.Meta,
	}
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssue, Body: issueReq})
	itest.AssertStatus(t, resp, http.StatusOK)
	var issued mdl.CertificateDataResponseDtoV3
	resp.JSON(t, &issued)
	leaf := parseCertB64(t, *issued.CertificateData)
	if leaf.Subject.CommonName != registeredCN {
		t.Errorf("issued CN = %q, want registered subject %q", leaf.Subject.CommonName, registeredCN)
	}

	// One-shot: re-issuing against the consumed registration -> 404.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssue, Body: issueReq})
	itest.AssertProblem(t, resp, http.StatusNotFound, "OPERATION_NOT_FOUND")
}

// --- identify ---------------------------------------------------------

func TestAuthorityV3Identify(t *testing.T) {
	h := startAuthority(t, nil)
	issued := issueCert(t, h, "identify-me.example.test")

	// Known certificate -> 200.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIdentify, Body: mdl.CertificateIdentificationRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		Certificate:         *issued.CertificateData,
	}})
	itest.AssertStatus(t, resp, http.StatusOK)

	// Unknown certificate -> 404 CERTIFICATE_NOT_FOUND.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIdentify, Body: mdl.CertificateIdentificationRequestDtoV3{
		AuthorityAttributes: validAuth(),
		RaProfileAttributes: []mdl.RequestAttribute{},
		Certificate:         foreignCertB64(t),
	}})
	itest.AssertProblem(t, resp, http.StatusNotFound, "CERTIFICATE_NOT_FOUND")
}

// --- getCaCertificates ------------------------------------------------

func TestAuthorityV3GetCaCertificates(t *testing.T) {
	h := startAuthority(t, nil)
	root := caRoot(t, h) // fetches, parses, and asserts non-empty
	if !root.IsCA {
		t.Errorf("CA certificate IsCA = false, want true")
	}
}

// --- connector Attributes API (/v2/attributes) ------------------------

func TestAuthorityV3AttributeDefinitions(t *testing.T) {
	h := startAuthority(t, nil)

	// listDefinitions -> 200 with the connector's definition set.
	resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v2/attributes"})
	itest.AssertStatus(t, resp, http.StatusOK)
	var defs mdl.AttributeDefinitionsDto
	resp.JSON(t, &defs)
	if defs.ConnectorVersion == "" {
		t.Errorf("listDefinitions connectorVersion is empty: %s", resp.Body)
	}
	if len(defs.Definitions) == 0 {
		t.Errorf("listDefinitions returned no definitions: %s", resp.Body)
	}

	// getDefinition for a known attribute UUID -> 200.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v2/attributes/" + caNameAttrUUID})
	itest.AssertStatus(t, resp, http.StatusOK)

	// getDefinition for an unknown UUID -> 404 DEFINITION_NOT_FOUND.
	resp = h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v2/attributes/00000000-0000-0000-0000-000000000000"})
	itest.AssertProblem(t, resp, http.StatusNotFound, "DEFINITION_NOT_FOUND")

	// callback -> 200 with a (possibly empty) resolved response.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: "/v2/attributes/callback", Body: mdl.AttributeCallbackRequestDto{
		ConnectorInterface: mdl.CONNECTORINTERFACE_AUTHORITY,
		InterfaceVersion:   "v3",
		AttributeUuid:      caNameAttrUUID,
		AttributeName:      "ca_name",
		ContextAttributes:  []mdl.ScopedAttributes{},
		CurrentAttributes:  []mdl.RequestAttribute{},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
}

// --- async mode (202 accept -> poll status -> completed; cancel; not-found) ---

func TestAuthorityV3Async(t *testing.T) {
	h := startAuthority(t, map[string]string{
		"APP_ASYNC_ISSUE": "true",
		// Generous delay so the job is reliably still pending on the first
		// status poll even on a slow/loaded CI host (the poll loop below
		// tolerates either outcome regardless).
		"APP_ASYNC_DELAY": "5s",
	})

	accept := func() mdl.CertificateDataResponseDtoV3 {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathIssue, Body: mdl.CertificateSignRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{},
			Request: genCSR(t, "async.example.test"), Attributes: validityAttrs(90),
		}})
		itest.AssertStatus(t, resp, http.StatusAccepted)
		var out mdl.CertificateDataResponseDtoV3
		resp.JSON(t, &out)
		if metaValue(t, out.Meta, "job_id") == "" {
			t.Fatalf("async accept carries no job_id meta: %s", resp.Body)
		}
		return out
	}

	statusReq := func(meta []mdl.MetadataAttribute) itest.Request {
		return itest.Request{Method: http.MethodPost, Path: pathIssueStatus, Body: mdl.CertificateOperationStatusRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, Meta: meta,
		}}
	}
	cancelReq := func(meta []mdl.MetadataAttribute) itest.Request {
		return itest.Request{Method: http.MethodPost, Path: pathIssueCancel, Body: mdl.CertificateOperationCancelRequestDtoV3{
			AuthorityAttributes: validAuth(), RaProfileAttributes: []mdl.RequestAttribute{}, Meta: meta,
		}}
	}

	// Accept -> 202 with a job_id, then poll /status. In v3 the status
	// endpoint always answers 200; the CertificateOperationStatusV3 field
	// carries progress (inProgress -> completed). The loop records that it
	// observed at least one inProgress response before completion, proving
	// the transition without depending on how fast the job lazily completes
	// relative to the round-trips.
	job := accept()
	var (
		completed  bool
		sawPending bool
		doneCert   *string
	)
	deadline := time.Now().Add(20 * time.Second)
	for time.Now().Before(deadline) {
		resp := h.Do(t, statusReq(job.Meta))
		if !itest.AssertStatus(t, resp, http.StatusOK) {
			t.FailNow() // status is always 200 now; a non-200 is a real failure
		}
		var st mdl.CertificateOperationStatusResponseDtoV3
		resp.JSON(t, &st)
		switch st.Status {
		case mdl.CERTIFICATEOPERATIONSTATUSV3_IN_PROGRESS:
			sawPending = true
		case mdl.CERTIFICATEOPERATIONSTATUSV3_COMPLETED:
			completed = true
			doneCert = st.CertificateData
		case mdl.CERTIFICATEOPERATIONSTATUSV3_FAILED:
			t.Fatalf("async issue reported failed status; reason=%v", st.Reason)
		default:
			t.Fatalf("async status = %q, not a known CertificateOperationStatusV3", st.Status)
		}
		if completed {
			break
		}
		time.Sleep(300 * time.Millisecond)
	}
	if !sawPending {
		t.Error("async job never reported inProgress before completing")
	}
	if !completed {
		t.Fatal("async job never reached completed status within the deadline")
	}
	if doneCert == nil {
		t.Fatal("async job completed but returned no certificateData")
	}
	parseCertB64(t, *doneCert) // completed job yields a real certificate

	// Cancel completed -> 422 CANCEL_REFUSED.
	itest.AssertProblem(t, h.Do(t, cancelReq(job.Meta)), http.StatusUnprocessableEntity, "CANCEL_REFUSED")

	// Cancel a fresh pending job -> 204.
	job2 := accept()
	itest.AssertStatus(t, h.Do(t, cancelReq(job2.Meta)), http.StatusNoContent)
	// Status of a cancelled job -> 404 OPERATION_NOT_FOUND.
	itest.AssertProblem(t, h.Do(t, statusReq(job2.Meta)), http.StatusNotFound, "OPERATION_NOT_FOUND")
}

// --- helpers ---------------------------------------------------------------

func ptr[T any](v T) *T { return &v }

// foreignCertB64 returns a base64 DER self-signed certificate not issued by
// the example CA, for negative identify/revoke paths.
func foreignCertB64(t *testing.T) string {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("gen key: %v", err)
	}
	tmpl := &x509.Certificate{
		SerialNumber: big.NewInt(1),
		Subject:      pkix.Name{CommonName: "foreign"},
		NotBefore:    time.Now().Add(-time.Hour),
		NotAfter:     time.Now().Add(time.Hour),
	}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &key.PublicKey, key)
	if err != nil {
		t.Fatalf("create foreign cert: %v", err)
	}
	return base64.StdEncoding.EncodeToString(der)
}
