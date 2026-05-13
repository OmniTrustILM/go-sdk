package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
)

// Attrs is an example VaultProfileAttributeProvider. It returns a single
// V3 Text attribute carrying the literal string "Hello World!" — enough to
// demonstrate how to assemble the BaseAttributeDto oneOf wrappers from the
// generated model.
type Attrs struct{}

func (a *Attrs) VaultProfileAttributes(ctx context.Context, ctxAttrs []mdl.RequestAttribute) ([]mdl.BaseAttributeDto, error) {
	description := "Example text attribute"
	helloLabel := "Greeting"

	text := &mdl.TextAttributeContentV3{
		Data:        "Hello World!",
		ContentType: mdl.ATTRIBUTECONTENTTYPE_TEXT,
	}
	content := mdl.TextAttributeContentV3AsBaseAttributeContentDtoV3(text)

	dataAttr := &mdl.DataAttributeV3{
		Uuid:        "11111111-1111-1111-1111-111111111111",
		Name:        "hello",
		Description: &description,
		Version:     1,
		Type:        mdl.ATTRIBUTETYPE_DATA,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_TEXT,
		Content:     []mdl.BaseAttributeContentDtoV3{content},
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
