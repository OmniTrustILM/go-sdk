package main_test

// Integration tests for the secret-v1 example (issue #24), driven over the
// public HTTP interface via the shared testcontainers harness. The example
// is run as a real container; requests use the generated secret/v1 model
// types so the test exercises the spec, the generated models, and the
// shared/provider runtime end to end. Skips with no Docker or under -short.

import (
	"net/http"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// Credentials the example is configured with (APP_USERNAME / APP_PASSWORD).
// Non-default values prove the env wiring rather than relying on admin/admin.
const (
	vaultUser = "vault-user"
	vaultPass = "vault-pass"
)

// Attribute UUIDs the example matches credentials by (connector/examples/secret-v1/attrs.go).
const (
	usernameAttrUUID = "fc70ce69-ca60-4919-bd97-9461fc3cf892"
	passwordAttrUUID = "1050005a-d550-4ba5-9525-0294d2ff8cd9"
)

// Secret route paths.
const (
	pathSecrets        = "/v1/secretProvider/secrets"
	pathSecretContent  = "/v1/secretProvider/secrets/content"
	pathSecretRotate   = "/v1/secretProvider/secrets/rotate"
	pathVaults         = "/v1/secretProvider/vaults"
	pathVaultAttrs     = "/v1/secretProvider/vaults/attributes"
	pathVaultProfile   = "/v1/secretProvider/vaultProfiles/attributes"
	pathRotateAttrs    = "/v1/secretProvider/secrets/rotate/attributes"
	pathSecretTypeAttr = "/v1/secretProvider/secrets/basicAuth/attributes"
)

// startSecret launches the secret-v1 example container with the test
// credentials and returns the harness.
func startSecret(t *testing.T) *itest.Harness {
	t.Helper()
	return itest.Start(t, itest.Example{
		Path: "connector/examples/secret-v1",
		Env: map[string]string{
			"APP_USERNAME": vaultUser,
			"APP_PASSWORD": vaultPass,
		},
	})
}

// stringAttr builds a single-string RequestAttribute (v3) carrying one
// credential field, matched by the example against its configured UUIDs.
func stringAttr(uuid, name, value string) mdl.RequestAttribute {
	content := mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
		Data:        value,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	})
	return mdl.RequestAttributeV3AsRequestAttribute(&mdl.RequestAttributeV3{
		Uuid:        uuid,
		Name:        name,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Version:     mdl.ATTRIBUTEVERSION_V3,
		Content:     []mdl.BaseAttributeContentDtoV3{content},
	})
}

// authAttrs builds the username + password vault attributes for the given
// credentials.
func authAttrs(user, pass string) []mdl.RequestAttribute {
	return []mdl.RequestAttribute{
		stringAttr(usernameAttrUUID, "username", user),
		stringAttr(passwordAttrUUID, "password", pass),
	}
}

// validAuth is the configured (correct) credential set.
func validAuth() []mdl.RequestAttribute { return authAttrs(vaultUser, vaultPass) }

func basicAuthContent(user, pass string) mdl.SecretContent {
	return mdl.BasicAuthSecretContentAsSecretContent(&mdl.BasicAuthSecretContent{
		Type:     mdl.SECRETTYPE_BASIC_AUTH,
		Username: user,
		Password: pass,
	})
}

func jwtContent(token string) mdl.SecretContent {
	return mdl.JwtTokenSecretContentAsSecretContent(&mdl.JwtTokenSecretContent{
		Type:    mdl.SECRETTYPE_JWT_TOKEN,
		Content: token,
	})
}

func apiKeyContent(key string) mdl.SecretContent {
	return mdl.ApiKeySecretContentAsSecretContent(&mdl.ApiKeySecretContent{
		Type:    mdl.SECRETTYPE_API_KEY,
		Content: key,
	})
}

// errorCode extracts the RFC 9457 ProblemDetail errorCode from a response.
func errorCode(t *testing.T, resp itest.Response) string {
	t.Helper()
	var pd struct {
		ErrorCode string `json:"errorCode"`
	}
	resp.JSON(t, &pd)
	return pd.ErrorCode
}

// --- #24: health + info ----------------------------------------------------

func TestSecretV1HealthAndInfo(t *testing.T) {
	h := startSecret(t)

	// Aggregate health: 200 with mandatory liveness/readiness components.
	h.AssertHealthy(t, "/v2/health")
	h.AssertHealthy(t, "/v2/health/liveness")
	h.AssertHealthy(t, "/v2/health/readiness")

	var info map[string]any
	if status := h.GetJSON(t, http.MethodGet, "/v2/info", nil, &info); status != http.StatusOK {
		t.Fatalf("/v2/info = %d, want 200", status)
	}
	ifaces, _ := info["interfaces"].([]any)
	var haveSecret bool
	for _, raw := range ifaces {
		if m, ok := raw.(map[string]any); ok && m["code"] == "secret" {
			haveSecret = true
		}
	}
	if !haveSecret {
		t.Errorf("/v2/info interfaces missing the secret interface: %v", info["interfaces"])
	}

	// Container logs conform to the connector.log v1 contract.
	h.AssertLogsConform(t)
}

// --- #24: credential-form auth --------------------------------------------

func TestSecretV1Auth(t *testing.T) {
	h := startSecret(t)

	// Valid credentials against CheckVaultConnection -> 204.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathVaults, Body: validAuth()})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// Wrong password -> 401 UNAUTHORIZED.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathVaults, Body: authAttrs(vaultUser, "wrong")})
	itest.AssertStatus(t, resp, http.StatusUnauthorized)
	if code := errorCode(t, resp); code != "UNAUTHORIZED" {
		t.Errorf("wrong-credentials errorCode = %q, want UNAUTHORIZED", code)
	}

	// Missing password attribute -> 422 VALIDATION_FAILED.
	resp = h.Do(t, itest.Request{
		Method: http.MethodPost, Path: pathVaults,
		Body: []mdl.RequestAttribute{stringAttr(usernameAttrUUID, "username", vaultUser)},
	})
	itest.AssertStatus(t, resp, http.StatusUnprocessableEntity)
	if code := errorCode(t, resp); code != "VALIDATION_FAILED" {
		t.Errorf("missing-attribute errorCode = %q, want VALIDATION_FAILED", code)
	}
}

// --- #24: full lifecycle create -> read -> update -> rotate -> delete ------

func TestSecretV1Lifecycle(t *testing.T) {
	h := startSecret(t)
	const name = "lifecycle-secret"

	// create (apiKey — a rotatable type)
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: apiKeyContent("key-v1"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusCreated)
	var created mdl.SecretResponseDto
	resp.JSON(t, &created)
	if created.Type != mdl.SECRETTYPE_API_KEY {
		t.Errorf("created type = %q, want apiKey", created.Type)
	}

	// read
	content := readSecret(t, h, name, mdl.SECRETTYPE_API_KEY)
	if content.ApiKeySecretContent == nil || content.ApiKeySecretContent.Content != "key-v1" {
		t.Errorf("read content = %+v, want apiKey key-v1", content)
	}

	// update (same type, new value)
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathSecrets, Body: mdl.UpdateSecretRequestDto{
		Name: name, Secret: apiKeyContent("key-v2"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	content = readSecret(t, h, name, mdl.SECRETTYPE_API_KEY)
	if content.ApiKeySecretContent == nil || content.ApiKeySecretContent.Content != "key-v2" {
		t.Errorf("after update content = %+v, want apiKey key-v2", content)
	}

	// rotate (apiKey regenerates the value)
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretRotate, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_API_KEY, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	content = readSecret(t, h, name, mdl.SECRETTYPE_API_KEY)
	if content.ApiKeySecretContent == nil || content.ApiKeySecretContent.Content == "key-v2" {
		t.Errorf("after rotate content = %+v, want a regenerated apiKey value", content)
	}

	// delete
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathSecrets, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_API_KEY, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// confirm gone
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_API_KEY, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)
	if code := errorCode(t, resp); code != "RESOURCE_NOT_FOUND" {
		t.Errorf("read-after-delete errorCode = %q, want RESOURCE_NOT_FOUND", code)
	}
}

// --- #24: error paths ------------------------------------------------------

func TestSecretV1Errors(t *testing.T) {
	h := startSecret(t)
	const name = "conflict-secret"

	// create once
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: apiKeyContent("k"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusCreated)

	// duplicate create -> 409 RESOURCE_ALREADY_EXISTS
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: apiKeyContent("k"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusConflict)
	if code := errorCode(t, resp); code != "RESOURCE_ALREADY_EXISTS" {
		t.Errorf("duplicate-create errorCode = %q, want RESOURCE_ALREADY_EXISTS", code)
	}

	// read unknown -> 404 RESOURCE_NOT_FOUND
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: mdl.SecretRequestDto{
		Name: "no-such-secret", Type: mdl.SECRETTYPE_API_KEY, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)
	if code := errorCode(t, resp); code != "RESOURCE_NOT_FOUND" {
		t.Errorf("read-unknown errorCode = %q, want RESOURCE_NOT_FOUND", code)
	}

	// rotate unknown -> 404 RESOURCE_NOT_FOUND
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretRotate, Body: mdl.SecretRequestDto{
		Name: "no-such-secret", Type: mdl.SECRETTYPE_API_KEY, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)
	if code := errorCode(t, resp); code != "RESOURCE_NOT_FOUND" {
		t.Errorf("rotate-unknown errorCode = %q, want RESOURCE_NOT_FOUND", code)
	}
}

// --- #24: attribute schema endpoints ---------------------------------------

func TestSecretV1Attributes(t *testing.T) {
	h := startSecret(t)

	// Vault attributes: array including the username + password definitions.
	var vaultAttrs []map[string]any
	if status := h.GetJSON(t, http.MethodGet, pathVaultAttrs, nil, &vaultAttrs); status != http.StatusOK {
		t.Fatalf("%s = %d, want 200", pathVaultAttrs, status)
	}
	if len(vaultAttrs) == 0 {
		t.Errorf("%s returned no attributes", pathVaultAttrs)
	}

	// Per-secret-type attribute schema -> 200 (array, possibly empty).
	if status := h.GetJSON(t, http.MethodGet, pathSecretTypeAttr, nil, nil); status != http.StatusOK {
		t.Errorf("%s = %d, want 200", pathSecretTypeAttr, status)
	}

	// Rotate attribute schema -> 200.
	if status := h.GetJSON(t, http.MethodGet, pathRotateAttrs, nil, nil); status != http.StatusOK {
		t.Errorf("%s = %d, want 200", pathRotateAttrs, status)
	}

	// Vault profile attributes (POST with context attrs) -> 200.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathVaultProfile, Body: validAuth()})
	itest.AssertStatus(t, resp, http.StatusOK)
}

// --- Karol's test case (issue #24) -----------------------------------------

// TestSecretV1KarolsCase walks the exact 10-step scenario from the issue:
// error-before-existence, create, read-back, duplicate, type-changing update,
// read-back, delete, read-after-delete.
func TestSecretV1KarolsCase(t *testing.T) {
	h := startSecret(t)
	const name = "dev-db-password"

	// 1. Read non-existing -> 404 not-found.
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_BASIC_AUTH, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)
	if code := errorCode(t, resp); code != "RESOURCE_NOT_FOUND" {
		t.Errorf("step 1 errorCode = %q, want RESOURCE_NOT_FOUND", code)
	}

	// 2. Update non-existing -> 404 not-found.
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathSecrets, Body: mdl.UpdateSecretRequestDto{
		Name: name, Secret: basicAuthContent("u", "p"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)

	// 3. Delete non-existing -> 404 not-found.
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathSecrets, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_BASIC_AUTH, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)

	// 4. Create, type basicAuth.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: basicAuthContent("dbadmin", "hunter2"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusCreated)
	var created mdl.SecretResponseDto
	resp.JSON(t, &created)
	if created.Type != mdl.SECRETTYPE_BASIC_AUTH {
		t.Errorf("step 4 created type = %q, want basicAuth", created.Type)
	}

	// 5. Read, check type basicAuth + content.
	content := readSecret(t, h, name, mdl.SECRETTYPE_BASIC_AUTH)
	if content.BasicAuthSecretContent == nil {
		t.Fatalf("step 5: content is not basicAuth: %+v", content)
	}
	if got := content.BasicAuthSecretContent; got.Username != "dbadmin" || got.Password != "hunter2" {
		t.Errorf("step 5 content = %+v, want dbadmin/hunter2", got)
	}

	// 6. Create again, same name -> 409 already-exists.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: basicAuthContent("dbadmin", "hunter2"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusConflict)
	if code := errorCode(t, resp); code != "RESOURCE_ALREADY_EXISTS" {
		t.Errorf("step 6 errorCode = %q, want RESOURCE_ALREADY_EXISTS", code)
	}

	// 7. Update, change type to jwtToken and change the value.
	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathSecrets, Body: mdl.UpdateSecretRequestDto{
		Name: name, Secret: jwtContent("eyJhbGciOiJND.payload.sig"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var updated mdl.SecretResponseDto
	resp.JSON(t, &updated)
	if updated.Type != mdl.SECRETTYPE_JWT_TOKEN {
		t.Errorf("step 7 updated type = %q, want jwtToken", updated.Type)
	}

	// 8. Read, check type changed to jwtToken + value.
	content = readSecret(t, h, name, mdl.SECRETTYPE_JWT_TOKEN)
	if content.JwtTokenSecretContent == nil {
		t.Fatalf("step 8: content is not jwtToken: %+v", content)
	}
	if got := content.JwtTokenSecretContent.Content; got != "eyJhbGciOiJND.payload.sig" {
		t.Errorf("step 8 jwt content = %q, want the updated token", got)
	}

	// 9. Delete.
	resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathSecrets, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_JWT_TOKEN, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNoContent)

	// 10. Read after delete -> 404 not-found.
	resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: mdl.SecretRequestDto{
		Name: name, Type: mdl.SECRETTYPE_JWT_TOKEN, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusNotFound)
	if code := errorCode(t, resp); code != "RESOURCE_NOT_FOUND" {
		t.Errorf("step 10 errorCode = %q, want RESOURCE_NOT_FOUND", code)
	}
}

// readSecret POSTs to the content endpoint and returns the decoded
// SecretContent, failing the test on a non-200 status.
func readSecret(t *testing.T, h *itest.Harness, name string, stype mdl.SecretType) mdl.SecretContent {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: mdl.SecretRequestDto{
		Name: name, Type: stype, VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusOK)
	var out mdl.SecretContentResponseDto
	resp.JSON(t, &out)
	return out.Content
}
