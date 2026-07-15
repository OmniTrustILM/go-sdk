package attributes

import (
	"fmt"

	"github.com/google/uuid"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/attributes/v2"
)

// registry is the validated, indexed form of a connector's attribute
// definitions: the ordered list (GET /v2/attributes), a uuid->index map
// (GET /v2/attributes/{uuid}), and a uuid->callback dispatch map
// (POST /v2/attributes/callback).
type registry struct {
	connectorVersion string
	defs             []mdl.BaseAttributeDto
	byUUID           map[string]int
	callbacks        map[string]CallbackFunc
}

// Validate runs the startup registry self-check without building a handler and
// reports the first inconsistency found (nil when the registry is sound). The
// rules mirror the interfaces contract:
//
//   - every definition resolves to a concrete attribute variant (exactly one
//     schema-version arm and one attribute-kind arm) with a valid UUID;
//   - definition UUIDs are unique across all attribute types;
//   - no attribute callback sets both dependsOn and callbackContext (the two
//     trigger modes are at most one);
//   - an attribute that declares an NG callback (its AttributeCallback carries a
//     non-nil dependsOn) has a registered Callback func, and an attribute that
//     declares no such trigger has none — so every NG callback is dispatchable;
//   - every attribute named in any dependsOn list resolves to a known attribute
//     in the registry.
//
// NewHandler runs the same check and fails fast, so a misconfigured connector
// never starts serving.
func Validate(defs []Definition) error {
	_, err := buildRegistry("", defs)
	return err
}

// declaresNGCallback reports whether an attribute's callback is an Attributes v2
// (NG) callback: presence of a (non-nil) dependsOn is the marker (an empty but
// non-nil list means "fire on form open"). A callback with dependsOn == nil is
// either absent or the legacy callbackContext form, neither of which this NG
// surface dispatches.
func declaresNGCallback(cb *mdl.AttributeCallback) bool {
	return cb != nil && cb.DependsOn != nil
}

func buildRegistry(connectorVersion string, defs []Definition) (*registry, error) {
	r := &registry{
		connectorVersion: connectorVersion,
		defs:             make([]mdl.BaseAttributeDto, 0, len(defs)),
		byUUID:           make(map[string]int, len(defs)),
		callbacks:        make(map[string]CallbackFunc, len(defs)),
	}
	names := make(map[string]struct{}, len(defs)) // all definition names, for dependsOn resolution

	// dependsOnRef records a dependsOn edge to check once every name is known.
	type dependsOnRef struct{ from, to string }
	var deps []dependsOnRef

	for i, d := range defs {
		info := inspect(d.Attribute)
		if !info.ok {
			return nil, fmt.Errorf("attributes: definition at index %d has no concrete attribute variant", i)
		}
		if info.uuid == "" {
			return nil, fmt.Errorf("attributes: definition %q (index %d) has an empty uuid", info.name, i)
		}
		// Definition identifiers are connector-global UUIDs per the contract
		// (the callback dispatch key and the GET /{uuid} path segment).
		if err := uuid.Validate(info.uuid); err != nil {
			return nil, fmt.Errorf("attributes: definition %q (index %d) uuid %q is not a valid UUID: %w", info.name, i, info.uuid, err)
		}
		if outer, nested := armCounts(d.Attribute); outer != 1 || nested != 1 {
			return nil, fmt.Errorf("attributes: definition %q (index %d) must populate exactly one schema-version arm and one attribute-kind arm, found outer=%d nested=%d", info.name, i, outer, nested)
		}
		if _, dup := r.byUUID[info.uuid]; dup {
			return nil, fmt.Errorf("attributes: duplicate definition uuid %q (attribute %q)", info.uuid, info.name)
		}

		if cb := info.callback; cb != nil && cb.DependsOn != nil && cb.CallbackContext != nil {
			return nil, fmt.Errorf("attributes: attribute %q (uuid %s) sets both dependsOn and callbackContext; at most one may be set", info.name, info.uuid)
		}

		ng := declaresNGCallback(info.callback)
		switch {
		case ng && d.Callback == nil:
			return nil, fmt.Errorf("attributes: attribute %q (uuid %s) declares a dependsOn callback but no Callback func is registered", info.name, info.uuid)
		case !ng && d.Callback != nil:
			return nil, fmt.Errorf("attributes: attribute %q (uuid %s) has a Callback func but declares no dependsOn trigger", info.name, info.uuid)
		}

		r.byUUID[info.uuid] = len(r.defs)
		r.defs = append(r.defs, d.Attribute)
		if d.Callback != nil {
			r.callbacks[info.uuid] = d.Callback
		}
		if info.name != "" {
			names[info.name] = struct{}{}
		}
		if ng {
			for _, dep := range info.callback.DependsOn {
				deps = append(deps, dependsOnRef{from: info.name, to: dep})
			}
		}
	}

	for _, e := range deps {
		if _, ok := names[e.to]; !ok {
			return nil, fmt.Errorf("attributes: attribute %q dependsOn %q, which is not a known attribute in the registry", e.from, e.to)
		}
	}
	return r, nil
}
