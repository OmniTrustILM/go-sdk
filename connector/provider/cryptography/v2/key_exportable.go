package cryptography

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// The create-key attribute the contract reserves for the exportable intent. A
// connector that declares FeatureFlag.KEY_EXPORT publishes
// KeyExportableDefinition in its create-key attribute schema and reads the
// intent with SelectedKeyExportable. A key import states the same intent in
// its own exportable field, so the attribute belongs to key creation alone.
const (
	KeyExportableAttributeName = "keyExportable"
	KeyExportableAttributeUUID = "9d3f1a26-5d4e-4b6c-8f0a-6c1f2d7e4b83"
)

var (
	errKeyExportableRepeated   = errValidationFailed("keyExportable must be supplied at most once")
	errKeyExportableNotV3      = errValidationFailed("keyExportable must be a v3 attribute")
	errKeyExportableNotOneItem = errValidationFailed("keyExportable must carry exactly one content item")
	errKeyExportableNotBoolean = errValidationFailed("keyExportable must carry boolean content")
)

// KeyExportableDefinition builds the required v3 keyExportable definition,
// defaulting to not exportable.
func KeyExportableDefinition() mdl.BaseAttributeDto {
	properties := mdl.DataAttributeProperties{
		Label:           "Exportable",
		Visible:         true,
		Required:        true,
		ProtectionLevel: mdl.PROTECTIONLEVEL_NONE.Ptr(),
	}
	definition := mdl.NewDataAttributeV3(KeyExportableAttributeUUID, KeyExportableAttributeName,
		dataAttributeV3Version, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_BOOLEAN, properties, mdl.ATTRIBUTEVERSION_V3)
	description := "Whether the key may later be exported. It cannot be changed after the key exists."
	definition.Description = &description
	definition.Content = []mdl.BaseAttributeContentDtoV3{booleanContent(false)}
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(definition)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

// KeyExportableSelection is the createKeyAttributes entry Core sends to state
// the intent.
func KeyExportableSelection(exportable bool) mdl.RequestAttribute {
	selection := mdl.NewRequestAttributeV3(KeyExportableAttributeUUID, KeyExportableAttributeName,
		mdl.ATTRIBUTECONTENTTYPE_BOOLEAN, mdl.ATTRIBUTEVERSION_V3)
	selection.Content = []mdl.BaseAttributeContentDtoV3{booleanContent(exportable)}
	return mdl.RequestAttributeV3AsRequestAttribute(selection)
}

// SelectedKeyExportable reads the exportable intent from createKeyAttributes.
// An absent attribute means not exportable, so a request that lost it can
// never create an exportable key; one present but unusable renders 422
// VALIDATION_FAILED.
func SelectedKeyExportable(createKeyAttributes []mdl.RequestAttribute) (bool, error) {
	found, err := reservedAttribute(createKeyAttributes, KeyExportableAttributeName, errKeyExportableRepeated)
	if err != nil || found == nil {
		return false, err
	}
	attribute := found.RequestAttributeV3
	if attribute == nil {
		return false, errKeyExportableNotV3
	}
	if attribute.ContentType != mdl.ATTRIBUTECONTENTTYPE_BOOLEAN {
		return false, errKeyExportableNotBoolean
	}
	if len(attribute.Content) != 1 {
		return false, errKeyExportableNotOneItem
	}
	value := attribute.Content[0].BooleanAttributeContentV3
	if value == nil {
		return false, errKeyExportableNotBoolean
	}
	return value.Data, nil
}

func booleanContent(value bool) mdl.BaseAttributeContentDtoV3 {
	return mdl.BooleanAttributeContentV3AsBaseAttributeContentDtoV3(
		mdl.NewBooleanAttributeContentV3(value, mdl.ATTRIBUTECONTENTTYPE_BOOLEAN))
}
