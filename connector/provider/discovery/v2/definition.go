package discovery

import mdl "github.com/OmniTrustILM/go-sdk/connector/model/discovery/v2"

func DefinitionUUID(def mdl.BaseAttributeDto) string {
	var inst any
	switch {
	case def.BaseAttributeDtoV3 != nil:
		inst = def.BaseAttributeDtoV3.GetActualInstance()
	case def.BaseAttributeDtoV2 != nil:
		inst = def.BaseAttributeDtoV2.GetActualInstance()
	default:
		return ""
	}
	switch v := inst.(type) {
	case *mdl.DataAttributeV3:
		return v.Uuid
	case *mdl.InfoAttributeV3:
		return v.Uuid
	case *mdl.GroupAttributeV3:
		return v.Uuid
	case *mdl.MetadataAttributeV3:
		return v.Uuid
	case *mdl.CustomAttributeV3:
		return v.Uuid
	case *mdl.DataAttributeV2:
		return v.Uuid
	case *mdl.InfoAttributeV2:
		return v.Uuid
	case *mdl.GroupAttributeV2:
		return v.Uuid
	case *mdl.MetadataAttributeV2:
		return v.Uuid
	case *mdl.CustomAttributeV2:
		return v.Uuid
	default:
		return ""
	}
}
