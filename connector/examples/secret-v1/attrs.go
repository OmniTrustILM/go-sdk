package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// Hard-coded UUIDs for the vault-attribute definitions returned by this
// example connector. Match the JSON in the README / spec example used by
// CZERTAINLY core when rendering the credential-form for this connector.
const (
	infoAttrUUID     = "07ec149a-c376-4523-9ba9-968ac59ef917"
	usernameAttrUUID = "fc70ce69-ca60-4919-bd97-9461fc3cf892"
	passwordAttrUUID = "1050005a-d550-4ba5-9525-0294d2ff8cd9"
)

// Attrs is the example secret-provider attribute provider. It satisfies both
// the VaultAttributeProvider (GET /v1/secretProvider/vaults/attributes) and
// VaultProfileAttributeProvider (POST /v1/secretProvider/vaultProfiles/attributes)
// sub-interfaces of connector/provider/secret/v1.
//
// VaultAttributes returns the static credential-form definition (info text
// + username + password). VaultProfileAttributes returns a single Text-v3
// "Hello World!" attribute as a stand-in for a real profile attribute set.
type Attrs struct{}

// VaultAttributes returns the connector's credential-form schema:
//   - one info attribute explaining what the connector does
//   - one required string data attribute for the username
//   - one required string data attribute for the password
//
// The information is purely a schema definition; the actual values supplied
// by callers arrive in each Provider method's request DTO under
// VaultAttributes and are checked against APP_USERNAME / APP_PASSWORD in
// store.go.
func (a *Attrs) VaultAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{
		buildInfoAttr(),
		buildStringDataAttr(
			usernameAttrUUID,
			"data_secrets_v1_example_username",
			"Login username",
			"Login username; must match the connector's configured APP_USERNAME (validated on every request).",
		),
		buildStringDataAttr(
			passwordAttrUUID,
			"data_secrets_v1_example_password",
			"Login password",
			"Login password; must match the connector's configured APP_PASSWORD (validated on every request).",
		),
	}, nil
}

// VaultProfileAttributes returns a single V3 Text attribute carrying the
// literal "Hello World!" — kept from the original example to demonstrate
// how the oneOf BaseAttributeDto wrappers are assembled.
func (a *Attrs) VaultProfileAttributes(ctx context.Context, ctxAttrs []mdl.RequestAttribute) ([]mdl.BaseAttributeDto, error) {
	description := "Example text attribute"
	helloLabel := "Greeting"

	text := &mdl.TextAttributeContentV3{
		Data:        "Hello World!",
		ContentType: mdl.ATTRIBUTECONTENTTYPE_TEXT,
	}
	content := mdl.TextAttributeContentV3AsBaseAttributeContentDtoV3(text)

	dataAttr := &mdl.DataAttributeV3{
		Uuid:          "11111111-1111-1111-1111-111111111111",
		Name:          "hello",
		Description:   &description,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Version:       1,
		Type:          mdl.ATTRIBUTETYPE_DATA,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_TEXT,
		Content:       []mdl.BaseAttributeContentDtoV3{content},
		Properties: mdl.DataAttributeProperties{
			Label:    helloLabel,
			Visible:  true,
			Required: false,
			ReadOnly: true,
		},
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(dataAttr)
	base := mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
	return []mdl.BaseAttributeDto{base}, nil
}

// buildInfoAttr returns the standing info attribute that explains what this
// example connector does.
func buildInfoAttr() mdl.BaseAttributeDto {
	desc := "Secret-v1 Example Configuration description."
	body := "This is an example secrets connector. There is no third-party " +
		"technology, like for example Vault, backing the secrets management, " +
		"just a simple in-memory map, keyed by secret name. Therefore input " +
		"parameters (attributes) like for example Vault URL or Vault namespace " +
		"don't really make sense with this particular connector. For " +
		"demonstration purposes there are two mandatory input parameters:\n" +
		"-  **Username** - the login username, checked against the connector's configured value on every request.\n" +
		"-  **Password** - the login password, checked against the connector's configured value on every request."
	version := int32(3)

	text := &mdl.TextAttributeContentV3{
		Data:        body,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_TEXT,
	}
	content := mdl.TextAttributeContentV3AsBaseAttributeContentDtoV3(text)

	info := &mdl.InfoAttributeV3{
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Uuid:          infoAttrUUID,
		Name:          "info_secrets_v1_example_explanation",
		Description:   &desc,
		Content:       []mdl.BaseAttributeContentDtoV3{content},
		Version:       &version,
		Type:          mdl.ATTRIBUTETYPE_INFO,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_TEXT,
		Properties: mdl.InfoAttributeProperties{
			Label:   "Secret-v1 Example Configuration description",
			Visible: true,
		},
	}
	v3 := mdl.InfoAttributeV3AsBaseAttributeDtoV3(info)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}

// buildStringDataAttr returns a required, visible string data attribute used
// for the username / password fields of the credential form.
func buildStringDataAttr(uuid, name, label, description string) mdl.BaseAttributeDto {
	desc := description
	attr := &mdl.DataAttributeV3{
		Uuid:          uuid,
		Name:          name,
		Description:   &desc,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Version:       3,
		Type:          mdl.ATTRIBUTETYPE_DATA,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_STRING,
		Properties: mdl.DataAttributeProperties{
			Label:    label,
			Visible:  true,
			Required: true,
		},
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(attr)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}

// extractStringValue returns the first string value carried by attr's V3
// content, or "" when the attribute is absent or non-string. Callers should
// also verify the attribute was present in the request via a separate
// "found" check — empty string is a valid (though disallowed by auth) input.
func extractStringValue(attr mdl.RequestAttribute) (string, bool) {
	if attr.RequestAttributeV3 == nil {
		return "", false
	}
	for _, c := range attr.RequestAttributeV3.Content {
		if c.StringAttributeContentV3 != nil {
			return c.StringAttributeContentV3.Data, true
		}
	}
	return "", false
}
