package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v1"
	compliance "github.com/OmniTrustILM/go-sdk/connector/provider/compliance/v1"
)

// Store is a minimal Compliance Provider v1 implementation backed by
// hard-coded rules and groups keyed by kind. The compliance check returns
// "ok" for every requested rule that exists. Scope is wiring verification.
type Store struct {
	rules      map[string][]mdl.ComplianceRulesResponseDto
	groups     map[string][]mdl.ComplianceGroupsResponseDto
	groupRules map[string]map[string][]mdl.ComplianceRulesResponseDto
}

func NewStore() *Store {
	desc := "Reference compliance rule"
	groupDesc := "Reference compliance group"
	groupUuid := "33333333-3333-3333-3333-333333333333"

	rule1 := mdl.ComplianceRulesResponseDto{
		Uuid:            "11111111-1111-1111-1111-111111111111",
		Name:            "rsa-min-2048",
		Description:     &desc,
		CertificateType: mdl.CERTIFICATETYPE_X_509,
	}
	rule2 := mdl.ComplianceRulesResponseDto{
		Uuid:            "22222222-2222-2222-2222-222222222222",
		Name:            "valid-for-max-1y",
		Description:     &desc,
		CertificateType: mdl.CERTIFICATETYPE_X_509,
		GroupUuid:       &groupUuid,
	}
	group1 := mdl.ComplianceGroupsResponseDto{
		Uuid:        groupUuid,
		Name:        "baseline",
		Description: &groupDesc,
	}

	return &Store{
		rules: map[string][]mdl.ComplianceRulesResponseDto{
			"default": {rule1, rule2},
		},
		groups: map[string][]mdl.ComplianceGroupsResponseDto{
			"default": {group1},
		},
		groupRules: map[string]map[string][]mdl.ComplianceRulesResponseDto{
			"default": {
				groupUuid: {rule2},
			},
		},
	}
}

func (s *Store) GetRules(ctx context.Context, kind string) ([]mdl.ComplianceRulesResponseDto, error) {
	rs, ok := s.rules[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	return rs, nil
}

func (s *Store) GetGroups(ctx context.Context, kind string) ([]mdl.ComplianceGroupsResponseDto, error) {
	gs, ok := s.groups[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	return gs, nil
}

func (s *Store) GetGroupRules(ctx context.Context, kind, groupUuid string) ([]mdl.ComplianceRulesResponseDto, error) {
	g, ok := s.groupRules[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	rs, ok := g[groupUuid]
	if !ok {
		return nil, compliance.ErrGroupNotFound.WithProperty("uuid", groupUuid)
	}
	return rs, nil
}

// CheckCompliance marks every requested rule as "ok" if it exists in the
// kind's rule set, otherwise "na". Placeholder logic; a real check would
// inspect req.Certificate against the rule definition.
func (s *Store) CheckCompliance(ctx context.Context, kind string, req *mdl.ComplianceRequestDto) (*mdl.ComplianceResponseDto, error) {
	rules, ok := s.rules[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	known := map[string]string{} // uuid -> name
	for _, r := range rules {
		known[r.Uuid] = r.Name
	}

	out := &mdl.ComplianceResponseDto{
		Status: mdl.COMPLIANCESTATUS_OK,
		Rules:  []mdl.ComplianceResponseRulesDto{},
	}
	if req == nil {
		return out, nil
	}
	for _, rr := range req.Rules {
		name, exists := known[rr.Uuid]
		if !exists {
			out.Rules = append(out.Rules, mdl.ComplianceResponseRulesDto{
				Uuid:   rr.Uuid,
				Name:   "<unknown>",
				Status: mdl.COMPLIANCERULESTATUS_NA,
			})
			continue
		}
		out.Rules = append(out.Rules, mdl.ComplianceResponseRulesDto{
			Uuid:   rr.Uuid,
			Name:   name,
			Status: mdl.COMPLIANCERULESTATUS_OK,
		})
	}
	return out, nil
}

// Kind attribute schema (compliance.KindAttributeProvider): one required
// string attribute naming the compliance profile to evaluate against.
const (
	profileAttrUUID = "44444444-4444-4444-4444-444444444444"
	profileAttrName = "profile"
	// msgMissingProfile is the semantic validation error for a request
	// without the profile attribute (rendered as a v1 422 []string).
	msgMissingProfile = "missing required attribute profile"
)

// Attributes returns the per-kind attribute schema. Unknown kinds are
// rejected like every other kind-scoped operation of the store.
func (s *Store) Attributes(ctx context.Context, kind string) ([]mdl.BaseAttributeDto, error) {
	if _, ok := s.rules[kind]; !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	return []mdl.BaseAttributeDto{profileAttr()}, nil
}

// ValidateAttributes requires the profile attribute (a V3 request attribute
// with that name). Placeholder: its content is not inspected.
func (s *Store) ValidateAttributes(ctx context.Context, kind string, attrs []mdl.RequestAttribute) ([]string, error) {
	if _, ok := s.rules[kind]; !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	for _, a := range attrs {
		if a.RequestAttributeV3 != nil && a.RequestAttributeV3.Name == profileAttrName {
			return nil, nil
		}
	}
	return []string{msgMissingProfile}, nil
}

// profileAttr builds the required V3 string data attribute. version and
// schemaVersion are the wire discriminators the generated BaseAttributeDto
// decoder dispatches on (same construction as credential-v1 stringAttr).
func profileAttr() mdl.BaseAttributeDto {
	desc := "Compliance profile to evaluate against"
	attr := &mdl.DataAttributeV3{
		Uuid:          profileAttrUUID,
		Name:          profileAttrName,
		Description:   &desc,
		Version:       3,
		Type:          mdl.ATTRIBUTETYPE_DATA,
		ContentType:   mdl.ATTRIBUTECONTENTTYPE_STRING,
		SchemaVersion: mdl.ATTRIBUTEVERSION_V3,
		Properties: mdl.DataAttributeProperties{
			Label:    "Profile",
			Visible:  true,
			Required: true,
		},
	}
	v3 := mdl.DataAttributeV3AsBaseAttributeDtoV3(attr)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&v3)
}
