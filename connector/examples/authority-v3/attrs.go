package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
)

// Attribute UUIDs are the stable identifiers Core matches attributes by.
// Hard-coded so the values in client requests stay valid across restarts.
const (
	// caNameAttrUUID identifies the mandatory ca_name authority attribute:
	// the name of the CA instance this stateless connector should act for.
	// The example provisions exactly one CA named cfg.CaName (default
	// "demo-ca"); any other value is rejected with VALIDATION_FAILED.
	caNameAttrUUID = "9c1d6f1a-3f4b-4e26-b9a8-7d2e0c5b8a01"

	// apiKeyAttrUUID identifies the mandatory api_key authority attribute:
	// the bearer credential for the upstream CA. Must equal cfg.ApiKey;
	// mismatches yield 401 UNAUTHORIZED, absence yields 422
	// VALIDATION_FAILED. Demonstrates per-request credential transport in
	// the stateless v3 model.
	apiKeyAttrUUID = "2f7e4d3c-8b1a-4c59-9e60-31d4f6a7b502"

	// validityDaysAttrUUID identifies the mandatory validity_days issue
	// attribute: requested certificate lifetime in days, 1..825. Returned
	// by listIssueAttributes and consumed by issue + renew.
	validityDaysAttrUUID = "6a8b2c4d-0e9f-4f13-a7d5-58c3b1e2f903"

	// metaSerialUUID / metaRegistrationUUID identify the connector-defined
	// metadata attributes this example emits as tracking handles.
	metaSerialUUID       = "4d5e6f70-1a2b-4c3d-8e9f-a0b1c2d3e404"
	metaRegistrationUUID = "8e9fa0b1-2c3d-4e5f-9607-18b9c0d1e205"
	metaJobUUID          = "0b1c2d3e-4f50-4617-8829-93a4b5c6d706"
)

// Attrs implements the five attribute provider interfaces of
// provider/authority/v3. Authority attributes are mandatory (required:true)
// and validated on every operation by Backend.checkAuth — this is the
// stateless-v3 pattern: schema published here, enforcement per request.
type Attrs struct {
	cfg *Config
}

func stringDataAttr(uuid, name, label, description string) mdl.BaseAttributeDto {
	d := mdl.NewDataAttributeV3(
		uuid,
		name,
		1,
		mdl.ATTRIBUTETYPE_DATA,
		mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewDataAttributeProperties(label, true, true, false, false, false, false),
		mdl.ATTRIBUTEVERSION_V3,
	)
	d.Description = &description
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(d)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

func integerDataAttr(uuid, name, label, description string) mdl.BaseAttributeDto {
	d := mdl.NewDataAttributeV3(
		uuid,
		name,
		1,
		mdl.ATTRIBUTETYPE_DATA,
		mdl.ATTRIBUTECONTENTTYPE_INTEGER,
		*mdl.NewDataAttributeProperties(label, true, true, false, false, false, false),
		mdl.ATTRIBUTEVERSION_V3,
	)
	d.Description = &description
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(d)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

// AuthorityAttributes publishes the mandatory authority attribute schema:
// ca_name + api_key, both required string data attributes. Every other v3
// operation must carry them as authorityAttributes.
func (a *Attrs) AuthorityAttributes(ctx context.Context) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{
		stringDataAttr(caNameAttrUUID, "ca_name", "CA Name",
			"Name of the CA instance to operate against (this example provisions exactly one)."),
		stringDataAttr(apiKeyAttrUUID, "api_key", "API Key",
			"Credential for the upstream CA. Validated on every request."),
	}, nil
}

// RAProfileAttributes publishes no RA-profile attributes — the example CA
// has no profile concept. Returning an empty schema is valid; Core renders
// an empty RA-profile form.
func (a *Attrs) RAProfileAttributes(ctx context.Context, _ []mdl.RequestAttribute) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}

// IssueAttributes publishes the mandatory issue-operation attribute schema:
// validity_days, a required integer consumed by issue and renew.
func (a *Attrs) IssueAttributes(ctx context.Context, _ *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{
		integerDataAttr(validityDaysAttrUUID, "validity_days", "Validity (days)",
			"Requested certificate lifetime in days (1-825)."),
	}, nil
}

// RevokeAttributes — revocation needs nothing beyond the certificate and
// the spec-level reason field.
func (a *Attrs) RevokeAttributes(ctx context.Context, _ *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}

// RegisterAttributes — registration carries its identity in the request DTO.
func (a *Attrs) RegisterAttributes(ctx context.Context, _ *mdl.CertificateAttributeListRequestDtoV3) ([]mdl.BaseAttributeDto, error) {
	return []mdl.BaseAttributeDto{}, nil
}

// --- request-side extraction helpers ----------------------------------------

// findString scans attrs for a v3 attribute with the given uuid and returns
// the string data of its first content item.
func findString(attrs []mdl.RequestAttribute, uuid string) (string, bool) {
	for _, a := range attrs {
		v3 := a.RequestAttributeV3
		if v3 == nil || v3.Uuid != uuid || len(v3.Content) == 0 {
			continue
		}
		if s := v3.Content[0].StringAttributeContentV3; s != nil {
			return s.Data, true
		}
	}
	return "", false
}

// findInt scans attrs for a v3 attribute with the given uuid and returns the
// integer data of its first content item.
func findInt(attrs []mdl.RequestAttribute, uuid string) (int32, bool) {
	for _, a := range attrs {
		v3 := a.RequestAttributeV3
		if v3 == nil || v3.Uuid != uuid || len(v3.Content) == 0 {
			continue
		}
		if i := v3.Content[0].IntegerAttributeContentV3; i != nil {
			return i.Data, true
		}
	}
	return 0, false
}

// metaString scans response-side metadata for a v3 metadata attribute with
// the given uuid and returns the string data of its first content item.
func metaString(meta []mdl.MetadataAttribute, uuid string) (string, bool) {
	for _, m := range meta {
		v3 := m.MetadataAttributeV3
		if v3 == nil || v3.Uuid != uuid || len(v3.Content) == 0 {
			continue
		}
		if s := v3.Content[0].StringAttributeContentV3; s != nil {
			return s.Data, true
		}
	}
	return "", false
}

// newMetaString builds a single-string MetadataAttribute (v3 schema) used as
// a connector-defined tracking handle in responses.
func newMetaString(uuid, name, label, value string) mdl.MetadataAttribute {
	content := mdl.StringAttributeContentV3{
		Data:        value,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
	}
	m := mdl.NewMetadataAttributeV3(
		uuid,
		name,
		1,
		mdl.ATTRIBUTETYPE_META,
		mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewMetadataAttributeProperties(label, false),
		mdl.ATTRIBUTEVERSION_V3,
	)
	m.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(&content),
	}
	return mdl.MetadataAttributeV3AsMetadataAttribute(m)
}
