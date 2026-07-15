package attributes

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
)

// attrInfo is the connector-global identity and optional trigger of one
// attribute definition, extracted from the polymorphic BaseAttributeDto.
type attrInfo struct {
	uuid     string
	name     string
	callback *mdl.AttributeCallback // nil unless the attribute declares one
	ok       bool                   // false when no concrete variant is set
}

// inspect extracts the uuid, name, and optional AttributeCallback from a
// polymorphic BaseAttributeDto (a doubly-nested oneOf: schema v2/v3, then one
// of the five attribute kinds). Only DATA and GROUP attributes carry a
// callback; the other kinds report a nil callback. ok is false when the
// definition carries no concrete variant.
func inspect(def mdl.BaseAttributeDto) attrInfo {
	var inst any
	switch {
	case def.BaseAttributeDtoV3 != nil:
		inst = def.BaseAttributeDtoV3.GetActualInstance()
	case def.BaseAttributeDtoV2 != nil:
		inst = def.BaseAttributeDtoV2.GetActualInstance()
	default:
		return attrInfo{}
	}
	switch v := inst.(type) {
	case *mdl.DataAttributeV3:
		return attrInfo{uuid: v.Uuid, name: v.Name, callback: v.AttributeCallback, ok: true}
	case *mdl.GroupAttributeV3:
		return attrInfo{uuid: v.Uuid, name: v.Name, callback: v.AttributeCallback, ok: true}
	case *mdl.InfoAttributeV3:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	case *mdl.MetadataAttributeV3:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	case *mdl.CustomAttributeV3:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	case *mdl.DataAttributeV2:
		return attrInfo{uuid: v.Uuid, name: v.Name, callback: v.AttributeCallback, ok: true}
	case *mdl.GroupAttributeV2:
		return attrInfo{uuid: v.Uuid, name: v.Name, callback: v.AttributeCallback, ok: true}
	case *mdl.InfoAttributeV2:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	case *mdl.MetadataAttributeV2:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	case *mdl.CustomAttributeV2:
		return attrInfo{uuid: v.Uuid, name: v.Name, ok: true}
	default:
		return attrInfo{}
	}
}

// armCounts reports how many arms of a polymorphic BaseAttributeDto are
// populated at the outer (schema-version) level and, for a single populated
// outer arm, at the nested (attribute-kind) level. A well-formed definition
// has exactly one at each level. buildRegistry rejects anything else, because
// inspect and the generated MarshalJSON select arms in different orders
// (inspect probes V3 first; MarshalJSON emits V2 first) — a multi-arm
// definition would be indexed by one arm but served as another.
func armCounts(def mdl.BaseAttributeDto) (outer, nested int) {
	if def.BaseAttributeDtoV3 != nil {
		outer++
		nested = nestedArmsV3(def.BaseAttributeDtoV3)
	}
	if def.BaseAttributeDtoV2 != nil {
		outer++
		if def.BaseAttributeDtoV3 == nil {
			nested = nestedArmsV2(def.BaseAttributeDtoV2)
		}
	}
	return outer, nested
}

func nestedArmsV3(w *mdl.BaseAttributeDtoV3) int {
	n := 0
	for _, set := range []bool{
		w.CustomAttributeV3 != nil, w.DataAttributeV3 != nil, w.GroupAttributeV3 != nil,
		w.InfoAttributeV3 != nil, w.MetadataAttributeV3 != nil,
	} {
		if set {
			n++
		}
	}
	return n
}

func nestedArmsV2(w *mdl.BaseAttributeDtoV2) int {
	n := 0
	for _, set := range []bool{
		w.CustomAttributeV2 != nil, w.DataAttributeV2 != nil, w.GroupAttributeV2 != nil,
		w.InfoAttributeV2 != nil, w.MetadataAttributeV2 != nil,
	} {
		if set {
			n++
		}
	}
	return n
}

// DefinitionUUID returns the connector-global UUID of a polymorphic attribute
// definition across every attribute kind and schema version, or "" when the
// definition carries no concrete variant.
func DefinitionUUID(def mdl.BaseAttributeDto) string { return inspect(def).uuid }

// DefinitionName returns the name of a polymorphic attribute definition, or ""
// when the definition carries no concrete variant.
func DefinitionName(def mdl.BaseAttributeDto) string { return inspect(def).name }
