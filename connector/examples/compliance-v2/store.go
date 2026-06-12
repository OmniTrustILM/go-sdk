package main

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/compliance/v2"
	compliance "github.com/OmniTrustILM/go-sdk/connector/provider/compliance/v2"
)

// Store is a minimal Compliance Provider v2 implementation backed by hard-
// coded rules and groups. Scope is wiring verification, not real compliance
// logic. Rules are picked per kind; an unknown kind returns ErrKindNotFound.
type Store struct {
	rules     map[string][]mdl.ComplianceRuleResponseDto            // kind -> rules
	groups    map[string][]mdl.ComplianceGroupResponseDto           // kind -> groups
	groupRule map[string]map[string][]mdl.ComplianceRuleResponseDto // kind -> groupUUID -> rules
}

func NewStore() *Store {
	desc := "Reference compliance rule"
	groupDesc := "Reference compliance group"

	certResource := mdl.RESOURCE_CERTIFICATES

	rule1 := mdl.ComplianceRuleResponseDto{
		Uuid:        "11111111-1111-1111-1111-111111111111",
		Name:        "rsa-min-2048",
		Description: &desc,
		Resource:    certResource,
	}
	rule2 := mdl.ComplianceRuleResponseDto{
		Uuid:        "22222222-2222-2222-2222-222222222222",
		Name:        "valid-for-max-1y",
		Description: &desc,
		Resource:    certResource,
	}

	groupUuid := "33333333-3333-3333-3333-333333333333"
	group1 := mdl.ComplianceGroupResponseDto{
		Uuid:        groupUuid,
		Name:        "baseline",
		Description: &groupDesc,
		Resource:    &certResource,
	}
	// Mark rule2 as belonging to the group.
	rule2WithGroup := rule2
	rule2WithGroup.GroupUuid = &groupUuid

	return &Store{
		rules: map[string][]mdl.ComplianceRuleResponseDto{
			"default": {rule1, rule2WithGroup},
		},
		groups: map[string][]mdl.ComplianceGroupResponseDto{
			"default": {group1},
		},
		groupRule: map[string]map[string][]mdl.ComplianceRuleResponseDto{
			"default": {
				groupUuid: {rule2WithGroup},
			},
		},
	}
}

func (s *Store) GetRules(ctx context.Context, kind string) ([]mdl.ComplianceRuleResponseDto, error) {
	rs, ok := s.rules[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	return rs, nil
}

func (s *Store) GetRule(ctx context.Context, kind, ruleUuid string) (*mdl.ComplianceRuleResponseDto, error) {
	rs, ok := s.rules[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	for i := range rs {
		if rs[i].Uuid == ruleUuid {
			return &rs[i], nil
		}
	}
	return nil, compliance.ErrRuleNotFound.WithProperty("uuid", ruleUuid)
}

func (s *Store) GetRulesBatch(ctx context.Context, kind string, req *mdl.ComplianceRulesBatchRequestDto) (*mdl.ComplianceRulesBatchResponseDto, error) {
	if _, ok := s.rules[kind]; !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	withGroupRules := req != nil && req.WithGroupRules != nil && *req.WithGroupRules

	out := &mdl.ComplianceRulesBatchResponseDto{
		Rules:  []mdl.ComplianceRuleResponseDto{},
		Groups: []mdl.ComplianceGroupBatchResponseDto{},
	}
	if req != nil {
		for _, u := range req.RuleUuids {
			if r, err := s.GetRule(ctx, kind, u); err == nil {
				out.Rules = append(out.Rules, *r)
			}
		}
		for _, g := range req.GroupUuids {
			grp, err := s.GetGroup(ctx, kind, g)
			if err != nil {
				continue
			}
			batch := mdl.ComplianceGroupBatchResponseDto{
				Uuid:        grp.Uuid,
				Name:        grp.Name,
				Description: grp.Description,
				Resource:    grp.Resource,
			}
			if withGroupRules {
				if rs, ok := s.groupRule[kind][g]; ok {
					batch.Rules = rs
				}
			}
			out.Groups = append(out.Groups, batch)
		}
	}
	return out, nil
}

func (s *Store) GetGroups(ctx context.Context, kind string) ([]mdl.ComplianceGroupResponseDto, error) {
	gs, ok := s.groups[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	return gs, nil
}

func (s *Store) GetGroup(ctx context.Context, kind, groupUuid string) (*mdl.ComplianceGroupResponseDto, error) {
	gs, ok := s.groups[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	for i := range gs {
		if gs[i].Uuid == groupUuid {
			return &gs[i], nil
		}
	}
	return nil, compliance.ErrGroupNotFound.WithProperty("uuid", groupUuid)
}

func (s *Store) GetGroupRules(ctx context.Context, kind, groupUuid string) ([]mdl.ComplianceRuleResponseDto, error) {
	g, ok := s.groupRule[kind]
	if !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	rs, ok := g[groupUuid]
	if !ok {
		return nil, compliance.ErrGroupNotFound.WithProperty("uuid", groupUuid)
	}
	return rs, nil
}

// CheckCompliance marks every requested rule as "ok" if the resource type is
// known to the kind, otherwise "na". Placeholder logic; a real compliance
// check would inspect req.Data against the rule definition.
func (s *Store) CheckCompliance(ctx context.Context, kind string, req *mdl.ComplianceRequestDtoV2) (*mdl.ComplianceResponseDtoV2, error) {
	if _, ok := s.rules[kind]; !ok {
		return nil, compliance.ErrKindNotFound.WithProperty("kind", kind)
	}
	overall := mdl.COMPLIANCESTATUS_OK
	out := &mdl.ComplianceResponseDtoV2{
		Status: &overall,
		Rules:  []mdl.ComplianceResponseRuleDtoV2{},
	}
	if req == nil {
		return out, nil
	}
	for _, rr := range req.Rules {
		r, err := s.GetRule(ctx, kind, rr.Uuid)
		if err != nil {
			out.Rules = append(out.Rules, mdl.ComplianceResponseRuleDtoV2{
				Uuid:   rr.Uuid,
				Name:   "<unknown>",
				Status: mdl.COMPLIANCERULESTATUS_NOT_AVAILABLE,
			})
			continue
		}
		out.Rules = append(out.Rules, mdl.ComplianceResponseRuleDtoV2{
			Uuid:   r.Uuid,
			Name:   r.Name,
			Status: mdl.COMPLIANCERULESTATUS_OK,
		})
	}
	return out, nil
}
