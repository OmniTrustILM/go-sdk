package main_test

// Wire-level coverage of the generated secret/v1 oneOf wrappers: every
// SecretContent variant, the MetadataAttribute and BaseAttributeDto
// discriminators, driven through the running container. The model package's
// round-trip tests cover the wrappers in isolation; these prove the server
// decodes and encodes them over HTTP.

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/examples/internal/itest"
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// oneofSecretRequest is the SecretRequestDto the read/rotate/delete routes
// take for name+type under the configured credentials.
func oneofSecretRequest(name string, stype mdl.SecretType) mdl.SecretRequestDto {
	return mdl.SecretRequestDto{Name: name, Type: stype, VaultAttributes: validAuth()}
}

// oneofContentMap marshals a SecretContent to its generic JSON object so
// variants can be compared field by field regardless of AdditionalProperties
// being nil on one side and empty on the other.
func oneofContentMap(t *testing.T, c mdl.SecretContent) map[string]any {
	t.Helper()
	raw, err := json.Marshal(c)
	if err != nil {
		t.Fatalf("marshal SecretContent: %v", err)
	}
	var m map[string]any
	if err := json.Unmarshal(raw, &m); err != nil {
		t.Fatalf("unmarshal SecretContent %s: %v", raw, err)
	}
	return m
}

// oneofReadRaw POSTs to the content endpoint and returns the typed content
// plus the raw "content" object of the response body (to assert the wire
// discriminator independently of the model's decoder).
func oneofReadRaw(t *testing.T, h *itest.Harness, name string, stype mdl.SecretType) (mdl.SecretContent, map[string]any) {
	t.Helper()
	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretContent, Body: oneofSecretRequest(name, stype)})
	if !itest.AssertStatus(t, resp, http.StatusOK) {
		t.FailNow()
	}
	var typed mdl.SecretContentResponseDto
	resp.JSON(t, &typed)
	var raw struct {
		Content map[string]any `json:"content"`
	}
	resp.JSON(t, &raw)
	return typed.Content, raw.Content
}

// TestSecretV1SecretContentAllVariants creates, reads, rotates and deletes a
// secret of every SecretContent variant, so each oneOf arm crosses the wire
// in both directions and the discriminator-driven decoder picks the right one.
func TestSecretV1SecretContentAllVariants(t *testing.T) {
	h := startSecret(t)

	variants := []struct {
		name      string
		stype     mdl.SecretType
		content   mdl.SecretContent
		wantType  reflect.Type
		rotatable bool
	}{
		{"apiKey", mdl.SECRETTYPE_API_KEY, apiKeyContent("key-1"), reflect.TypeFor[*mdl.ApiKeySecretContent](), true},
		{"basicAuth", mdl.SECRETTYPE_BASIC_AUTH, basicAuthContent("user-1", "pass-1"), reflect.TypeFor[*mdl.BasicAuthSecretContent](), true},
		{"generic", mdl.SECRETTYPE_GENERIC, mdl.GenericSecretContentAsSecretContent(&mdl.GenericSecretContent{
			Type: mdl.SECRETTYPE_GENERIC, Content: "Z2VuZXJpYy1ibG9i",
		}), reflect.TypeFor[*mdl.GenericSecretContent](), true},
		{"jwtToken", mdl.SECRETTYPE_JWT_TOKEN, jwtContent("aaa.bbb.ccc"), reflect.TypeFor[*mdl.JwtTokenSecretContent](), false},
		{"keyStore", mdl.SECRETTYPE_KEY_STORE, mdl.KeyStoreSecretContentAsSecretContent(&mdl.KeyStoreSecretContent{
			Type: mdl.SECRETTYPE_KEY_STORE, KeyStoreType: mdl.KEYSTORETYPE_PKCS12, Content: "cGtjczEyLWJ5dGVz", Password: "ks-pass",
		}), reflect.TypeFor[*mdl.KeyStoreSecretContent](), false},
		{"keyValue", mdl.SECRETTYPE_KEY_VALUE, mdl.KeyValueSecretContentAsSecretContent(&mdl.KeyValueSecretContent{
			Type: mdl.SECRETTYPE_KEY_VALUE, Content: map[string]any{"host": "db.example", "port": "5432"},
		}), reflect.TypeFor[*mdl.KeyValueSecretContent](), false},
		{"privateKey", mdl.SECRETTYPE_PRIVATE_KEY, mdl.PrivateKeySecretContentAsSecretContent(&mdl.PrivateKeySecretContent{
			Type: mdl.SECRETTYPE_PRIVATE_KEY, Content: "LS0tLS1CRUdJTiBQUklWQVRFIEtFWS0tLS0t",
		}), reflect.TypeFor[*mdl.PrivateKeySecretContent](), false},
		{"secretKey", mdl.SECRETTYPE_SECRET_KEY, mdl.SecretKeySecretContentAsSecretContent(&mdl.SecretKeySecretContent{
			Type: mdl.SECRETTYPE_SECRET_KEY, Content: "c2VjcmV0LWtleS1ieXRlcw==",
		}), reflect.TypeFor[*mdl.SecretKeySecretContent](), true},
	}
	if got, want := len(variants), len(mdl.AllowedSecretTypeEnumValues); got != want {
		t.Fatalf("test covers %d variants, spec declares %d secret types", got, want)
	}

	for _, v := range variants {
		t.Run(v.name, func(t *testing.T) {
			secretName := "variant-" + v.name

			// create -> 201 with the discriminator echoed as Type
			resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
				Name: secretName, Secret: v.content, VaultAttributes: validAuth(),
			}})
			itest.AssertStatus(t, resp, http.StatusCreated)
			var created mdl.SecretResponseDto
			resp.JSON(t, &created)
			if created.Type != v.stype {
				t.Errorf("created type = %q, want %q", created.Type, v.stype)
			}

			// read -> exactly the expected variant, equal fields, and the raw
			// body carries the discriminator the server's MarshalJSON emits
			got, rawContent := oneofReadRaw(t, h, secretName, v.stype)
			if gt := reflect.TypeOf(got.GetActualInstance()); gt != v.wantType {
				t.Fatalf("read variant = %v, want %v", gt, v.wantType)
			}
			if rawContent["type"] != string(v.stype) {
				t.Errorf("raw content.type = %v, want %q", rawContent["type"], v.stype)
			}
			want := oneofContentMap(t, v.content)
			if gotMap := oneofContentMap(t, got); !reflect.DeepEqual(gotMap, want) {
				t.Errorf("read content = %v, want %v", gotMap, want)
			}

			// rotate: regenerates the rotatable types, refuses the rest
			resp = h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecretRotate, Body: oneofSecretRequest(secretName, v.stype)})
			if v.rotatable {
				itest.AssertStatus(t, resp, http.StatusOK)
				var rotated mdl.SecretResponseDto
				resp.JSON(t, &rotated)
				if rotated.Type != v.stype {
					t.Errorf("rotated type = %q, want %q", rotated.Type, v.stype)
				}
				after, _ := oneofReadRaw(t, h, secretName, v.stype)
				if gt := reflect.TypeOf(after.GetActualInstance()); gt != v.wantType {
					t.Fatalf("variant after rotate = %v, want %v", gt, v.wantType)
				}
				afterMap := oneofContentMap(t, after)
				if v.stype == mdl.SECRETTYPE_BASIC_AUTH {
					if afterMap["username"] != want["username"] {
						t.Errorf("rotated username = %v, want unchanged %v", afterMap["username"], want["username"])
					}
					if afterMap["password"] == want["password"] {
						t.Errorf("rotated password unchanged: %v", afterMap["password"])
					}
				} else if reflect.DeepEqual(afterMap["content"], want["content"]) {
					t.Errorf("rotated content unchanged: %v", afterMap["content"])
				}
			} else {
				itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "OPERATION_NOT_SUPPORTED")
				after, _ := oneofReadRaw(t, h, secretName, v.stype)
				if afterMap := oneofContentMap(t, after); !reflect.DeepEqual(afterMap, want) {
					t.Errorf("content after refused rotate = %v, want unchanged %v", afterMap, want)
				}
			}

			// delete -> 204
			resp = h.Do(t, itest.Request{Method: http.MethodDelete, Path: pathSecrets, Body: oneofSecretRequest(secretName, v.stype)})
			itest.AssertStatus(t, resp, http.StatusNoContent)
		})
	}
}

// TestSecretV1MetadataRoundTrip sends both MetadataAttribute arms on update
// and checks the store echoes them back: the version discriminator must
// survive as a JSON number and select the matching Go variant.
func TestSecretV1MetadataRoundTrip(t *testing.T) {
	h := startSecret(t)
	const name = "metadata-secret"

	resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathSecrets, Body: mdl.CreateSecretRequestDto{
		Name: name, Secret: apiKeyContent("k"), VaultAttributes: validAuth(),
	}})
	itest.AssertStatus(t, resp, http.StatusCreated)

	const (
		v3UUID = "22222222-2222-2222-2222-222222222222"
		v2UUID = "33333333-3333-3333-3333-333333333333"
	)
	v3 := mdl.MetadataAttributeV3AsMetadataAttribute(&mdl.MetadataAttributeV3{
		Uuid:          v3UUID,
		Name:          "owner",
		Version:       3,
		Type:          mdl.ATTRIBUTETYPE_META,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_STRING,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Properties:    mdl.MetadataAttributeProperties{Label: "Owner", Visible: true},
		Content: []mdl.BaseAttributeContentDtoV3{
			mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&mdl.StringAttributeContentV3{
				Data: "team-a", ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
			}),
		},
	})
	// V2 carries no content: V2 content variants are undecodable by design.
	v2 := mdl.MetadataAttributeV2AsMetadataAttribute(&mdl.MetadataAttributeV2{
		Uuid:        v2UUID,
		Name:        "legacy",
		Version:     2,
		Type:        mdl.ATTRIBUTETYPE_META,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Properties:  mdl.MetadataAttributeProperties{Label: "Legacy", Visible: true},
	})

	resp = h.Do(t, itest.Request{Method: http.MethodPut, Path: pathSecrets, Body: mdl.UpdateSecretRequestDto{
		Name: name, Secret: apiKeyContent("k2"), VaultAttributes: validAuth(),
		Metadata: []mdl.MetadataAttribute{v3, v2},
	}})
	itest.AssertStatus(t, resp, http.StatusOK)

	var updated mdl.SecretResponseDto
	resp.JSON(t, &updated)
	if len(updated.Metadata) != 2 {
		t.Fatalf("metadata len = %d, want 2\nbody: %s", len(updated.Metadata), resp.Body)
	}
	gotV3 := updated.Metadata[0].MetadataAttributeV3
	if gotV3 == nil || updated.Metadata[0].MetadataAttributeV2 != nil {
		t.Fatalf("metadata[0] = %+v, want only the V3 arm", updated.Metadata[0])
	}
	if gotV3.Uuid != v3UUID || gotV3.Version != 3 || gotV3.SchemaVersion != mdl.ATTRIBUTEVERSION_V3 {
		t.Errorf("metadata[0] = %+v, want uuid %s version 3 schemaVersion v3", gotV3, v3UUID)
	}
	if len(gotV3.Content) != 1 || gotV3.Content[0].StringAttributeContentV3 == nil || gotV3.Content[0].StringAttributeContentV3.Data != "team-a" {
		t.Errorf("metadata[0] content = %+v, want one string content team-a", gotV3.Content)
	}
	gotV2 := updated.Metadata[1].MetadataAttributeV2
	if gotV2 == nil || updated.Metadata[1].MetadataAttributeV3 != nil {
		t.Fatalf("metadata[1] = %+v, want only the V2 arm", updated.Metadata[1])
	}
	if gotV2.Uuid != v2UUID || gotV2.Version != 2 {
		t.Errorf("metadata[1] = %+v, want uuid %s version 2", gotV2, v2UUID)
	}

	// The discriminator travels as a JSON number, not a string.
	var raw struct {
		Metadata []map[string]any `json:"metadata"`
	}
	resp.JSON(t, &raw)
	if len(raw.Metadata) != 2 {
		t.Fatalf("raw metadata len = %d, want 2\nbody: %s", len(raw.Metadata), resp.Body)
	}
	for i, want := range []float64{3, 2} {
		if got, ok := raw.Metadata[i]["version"].(float64); !ok || got != want {
			t.Errorf("raw metadata[%d].version = %#v, want JSON number %v", i, raw.Metadata[i]["version"], want)
		}
	}
}

// TestSecretV1AttributeSchemasTyped decodes every attribute-schema endpoint
// into the typed BaseAttributeDto oneOf and checks the example's definitions,
// proving the server emits discriminators the generated decoder accepts.
func TestSecretV1AttributeSchemasTyped(t *testing.T) {
	h := startSecret(t)

	t.Run("vault attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathVaultAttrs})
		itest.AssertStatus(t, resp, http.StatusOK)
		var attrs []mdl.BaseAttributeDto
		resp.JSON(t, &attrs)
		if len(attrs) != 3 {
			t.Fatalf("got %d attributes, want 3\nbody: %s", len(attrs), resp.Body)
		}

		// [0] info attribute with one text content.
		if attrs[0].BaseAttributeDtoV3 == nil || attrs[0].BaseAttributeDtoV3.InfoAttributeV3 == nil {
			t.Fatalf("attrs[0] = %+v, want a V3 info attribute", attrs[0])
		}
		info := attrs[0].BaseAttributeDtoV3.InfoAttributeV3
		if info.Uuid != "07ec149a-c376-4523-9ba9-968ac59ef917" || info.ContentType != mdl.ATTRIBUTECONTENTTYPE_TEXT {
			t.Errorf("info attribute = uuid %q contentType %q", info.Uuid, info.ContentType)
		}
		if len(info.Content) != 1 || info.Content[0].TextAttributeContentV3 == nil || info.Content[0].TextAttributeContentV3.Data == "" {
			t.Errorf("info content = %+v, want one non-empty text content", info.Content)
		}

		// [1] username and [2] password: required string data attributes.
		for i, wantUUID := range []string{usernameAttrUUID, passwordAttrUUID} {
			a := attrs[i+1].BaseAttributeDtoV3
			if a == nil || a.DataAttributeV3 == nil {
				t.Fatalf("attrs[%d] = %+v, want a V3 data attribute", i+1, attrs[i+1])
			}
			d := a.DataAttributeV3
			if d.Uuid != wantUUID {
				t.Errorf("attrs[%d].uuid = %q, want %q", i+1, d.Uuid, wantUUID)
			}
			if d.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING || !d.Properties.Required || d.SchemaVersion != mdl.ATTRIBUTEVERSION_V3 {
				t.Errorf("attrs[%d] = contentType %q required %v schemaVersion %q, want string/required/v3",
					i+1, d.ContentType, d.Properties.Required, d.SchemaVersion)
			}
		}
	})

	t.Run("vault profile attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodPost, Path: pathVaultProfile, Body: validAuth()})
		itest.AssertStatus(t, resp, http.StatusOK)
		// Decoded through the BaseAttributeDto oneOf: its numeric "version"
		// discriminator accepts only 2 or 3, so an attribute emitted with any
		// other version would fail here exactly as it would for Core.
		var attrs []mdl.BaseAttributeDto
		resp.JSON(t, &attrs)
		if len(attrs) != 1 {
			t.Fatalf("got %d attributes, want 1\nbody: %s", len(attrs), resp.Body)
		}
		if attrs[0].BaseAttributeDtoV3 == nil || attrs[0].BaseAttributeDtoV3.DataAttributeV3 == nil {
			t.Fatalf("attrs[0] = %+v, want a V3 data attribute", attrs[0])
		}
		d := attrs[0].BaseAttributeDtoV3.DataAttributeV3
		if d.Uuid != "11111111-1111-1111-1111-111111111111" || d.ContentType != mdl.ATTRIBUTECONTENTTYPE_TEXT ||
			d.SchemaVersion != mdl.ATTRIBUTEVERSION_V3 || !d.Properties.ReadOnly {
			t.Errorf("profile attribute = uuid %q contentType %q schemaVersion %q readOnly %v",
				d.Uuid, d.ContentType, d.SchemaVersion, d.Properties.ReadOnly)
		}
		if len(d.Content) != 1 || d.Content[0].TextAttributeContentV3 == nil || d.Content[0].TextAttributeContentV3.Data != "Hello World!" {
			t.Errorf("profile attribute content = %+v, want one text content \"Hello World!\"", d.Content)
		}
	})

	t.Run("per secret type attributes", func(t *testing.T) {
		for _, st := range mdl.AllowedSecretTypeEnumValues {
			resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1/secretProvider/secrets/" + string(st) + "/attributes"})
			itest.AssertStatus(t, resp, http.StatusOK)
			var attrs []mdl.BaseAttributeDto
			resp.JSON(t, &attrs)
			// The example registers no per-type provider: the SDK convention is an empty array, never null.
			if attrs == nil {
				t.Errorf("%s attributes decoded to nil, want an empty array\nbody: %s", st, resp.Body)
			}
		}
	})

	t.Run("unknown secret type", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: "/v1/secretProvider/secrets/bogus/attributes"})
		itest.AssertProblem(t, resp, http.StatusUnprocessableEntity, "VALIDATION_FAILED")
	})

	t.Run("rotate attributes", func(t *testing.T) {
		resp := h.Do(t, itest.Request{Method: http.MethodGet, Path: pathRotateAttrs})
		itest.AssertStatus(t, resp, http.StatusOK)
		var attrs []mdl.BaseAttributeDto
		resp.JSON(t, &attrs)
		if attrs == nil {
			t.Errorf("rotate attributes decoded to nil, want an empty array\nbody: %s", resp.Body)
		}
	})
}
