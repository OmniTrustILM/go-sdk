package main

import (
	"slices"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const (
	keyAlgorithmAttributeName = "keyAlgorithm"
	keyAlgorithmAttributeUUID = "2d12a988-679b-478f-953d-b5bf743f5700"
)

const dataAttributeV3Version = 3

// pairAlgorithms are the key pair algorithms this Store creates.
var pairAlgorithms = []mdl.KeyAlgorithm{mdl.KEYALGORITHM_ECDSA, mdl.KEYALGORITHM_RSA}

var (
	errKeyAlgorithmNotSelected = keyAlgorithmRefusal("be supplied for a key pair")
	errKeyAlgorithmRepeated    = keyAlgorithmRefusal("be supplied once")
	errKeyAlgorithmNotOneValue = keyAlgorithmRefusal("be a v3 attribute carrying one string value")
	errKeyAlgorithmNotOffered  = keyAlgorithmRefusal("name an offered key pair algorithm")
)

// keyAlgorithmRefusal refuses a keyAlgorithm selection that breaks rule.
func keyAlgorithmRefusal(rule string) *shared.Error {
	return shared.Invalid("VALIDATION_FAILED", "keyAlgorithm must %s", rule)
}

// keyAlgorithmDefinition builds the required single-select keyAlgorithm definition.
func keyAlgorithmDefinition() mdl.BaseAttributeDto {
	properties := mdl.DataAttributeProperties{
		Label:           "Key Algorithm",
		Visible:         true,
		Required:        true,
		List:            true,
		ProtectionLevel: mdl.PROTECTIONLEVEL_NONE.Ptr(),
	}
	definition := mdl.NewDataAttributeV3(keyAlgorithmAttributeUUID, keyAlgorithmAttributeName,
		dataAttributeV3Version, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING, properties, mdl.ATTRIBUTEVERSION_V3)
	description := "Algorithm of the key pair to create"
	definition.Description = &description
	definition.Content = make([]mdl.BaseAttributeContentDtoV3, len(pairAlgorithms))
	for i, algorithm := range pairAlgorithms {
		definition.Content[i] = mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
			mdl.NewStringAttributeContentV3(string(algorithm), mdl.ATTRIBUTECONTENTTYPE_STRING))
	}
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(definition)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

// selectedKeyAlgorithm reads the key pair algorithm from createKeyAttributes.
func selectedKeyAlgorithm(createKeyAttributes []mdl.RequestAttribute) (mdl.KeyAlgorithm, error) {
	var found *mdl.RequestAttribute
	for i := range createKeyAttributes {
		if attributeName(createKeyAttributes[i]) != keyAlgorithmAttributeName {
			continue
		}
		if found != nil {
			return "", errKeyAlgorithmRepeated
		}
		found = &createKeyAttributes[i]
	}
	if found == nil {
		return "", errKeyAlgorithmNotSelected
	}
	selection := found.RequestAttributeV3
	if selection == nil || selection.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING ||
		len(selection.Content) != 1 || selection.Content[0].StringAttributeContentV3 == nil {
		return "", errKeyAlgorithmNotOneValue
	}
	algorithm := mdl.KeyAlgorithm(selection.Content[0].StringAttributeContentV3.Data)
	if !slices.Contains(pairAlgorithms, algorithm) {
		return "", errKeyAlgorithmNotOffered
	}
	return algorithm, nil
}

func attributeName(attribute mdl.RequestAttribute) string {
	switch {
	case attribute.RequestAttributeV3 != nil:
		return attribute.RequestAttributeV3.Name
	case attribute.RequestAttributeV2 != nil:
		return attribute.RequestAttributeV2.Name
	default:
		return ""
	}
}
