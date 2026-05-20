package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/credential/v1"
	credential "github.com/OmniTrustILM/go-sdk/connector/provider/credential/v1"
)

// Store is a minimal Credential Provider implementation. Two kinds are
// supported: "basic" (username + password) and "apiKey" (single api key
// string). Returns a V3 data attribute set per kind; ValidateAttributes
// runs a placeholder pass (each submitted attribute must carry a name) —
// it does not yet check requiredness against the schema returned by
// Attributes. Scope is wiring verification; tighten if a real example is
// needed.
type Store struct{}

func NewStore() *Store { return &Store{} }

func (s *Store) Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error) {
	switch kind {
	case "basic":
		return []mdl.BaseAttributeDto{
			stringAttr("11111111-1111-1111-1111-111111111111", "username", "Username", true),
			stringAttr("22222222-2222-2222-2222-222222222222", "password", "Password", true),
		}, nil
	case "apiKey":
		return []mdl.BaseAttributeDto{
			stringAttr("33333333-3333-3333-3333-333333333333", "apiKey", "API Key", true),
		}, nil
	default:
		return nil, credential.ErrKindNotFound.WithProperty("kind", kind)
	}
}

func (s *Store) ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) ([]string, error) {
	switch kind {
	case "basic", "apiKey":
	default:
		return nil, credential.ErrKindNotFound.WithProperty("kind", kind)
	}
	// Placeholder validation: each submitted attribute must have a name.
	// A real implementation would check requiredness, content type, and
	// constraint matches against the schema returned by Attributes.
	var errs []string
	for _, a := range attrs {
		ar := a.RequestAttributeV3
		if ar == nil || ar.Name == "" {
			errs = append(errs, "missing attribute name")
		}
	}
	return errs, nil
}

// stringAttr builds a V3 data attribute for a single required string field.
func stringAttr(uuid, name, label string, required bool) mdl.BaseAttributeDto {
	desc := label
	attr := &mdl.DataAttributeV3{
		Uuid:        uuid,
		Name:        name,
		Description: &desc,
		Version:     1,
		Type:        mdl.ATTRIBUTETYPE_DATA,
		ContentType: mdl.ATTRIBUTECONTENTTYPE_STRING,
		Properties: mdl.DataAttributeProperties{
			Label:    label,
			Visible:  true,
			Required: required,
		},
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(attr)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}
