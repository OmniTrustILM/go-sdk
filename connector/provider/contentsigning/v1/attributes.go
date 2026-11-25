package contentsigning

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
)

// Values are the attribute values of one operation after the profile's and the
// request's have been merged, keyed by attribute name.
type Values map[string][]mdl.BaseAttributeContentDtoV3

// Resolve merges the profile attribute values with the request's for one
// operation, the request winning. Profile attributes the operation does not
// declare are ignored: the profile carries the values of every operation. A
// request attribute the operation does not declare, a name sent twice in one
// list, an attribute that is not schema v3 and a value or content item whose
// content type differs from its definition are refused with ATTRIBUTES_REJECTED.
func Resolve(declared Attributes, profile, request []mdl.RequestAttribute) (Values, error) {
	known, err := index(declared.Profile, declared.Request)
	if err != nil {
		return nil, err
	}
	requestable, err := index(declared.Request)
	if err != nil {
		return nil, err
	}
	values := Values{}
	if err := values.merge(profile, known, false); err != nil {
		return nil, err
	}
	if err := values.merge(request, requestable, true); err != nil {
		return nil, err
	}
	return values, nil
}

// index maps the names of the definitions in lists to their definitions.
func index(lists ...[]mdl.BaseAttributeDto) (map[string]definition, error) {
	byName := map[string]definition{}
	for _, list := range lists {
		defs, err := defineAll(list)
		if err != nil {
			return nil, err
		}
		for _, d := range defs {
			byName[d.Name] = d
		}
	}
	return byName, nil
}

// merge checks list against the definitions in allowed and stores its values.
// An attribute outside allowed is refused when strict, otherwise ignored.
func (v Values) merge(list []mdl.RequestAttribute, allowed map[string]definition, strict bool) error {
	seen := map[string]bool{}
	for _, a := range list {
		name := attributeName(a)
		def, ok := allowed[name]
		if !ok {
			if strict {
				return AttributesRejected("attribute %q is not a request attribute of this operation", name)
			}
			continue
		}
		if seen[name] {
			return AttributesRejected("attribute %q is sent more than once", name)
		}
		seen[name] = true
		if a.RequestAttributeV3 == nil {
			return AttributesRejected("attribute %q must use schema version v3", name)
		}
		if got := a.RequestAttributeV3.ContentType; got != def.ContentType {
			return AttributesRejected("attribute %q has content type %q, want %q", name, got, def.ContentType)
		}
		for _, c := range a.RequestAttributeV3.Content {
			if got := contentTypeOf(c); got != def.ContentType {
				return AttributesRejected("attribute %q has content of type %q, want %q", name, got, def.ContentType)
			}
		}
		v[name] = a.RequestAttributeV3.Content
	}
	return nil
}

// contentTypeOf returns the content type a content item carries, or "" when it
// carries none.
func contentTypeOf(c mdl.BaseAttributeContentDtoV3) mdl.AttributeContentType {
	if typed, ok := c.GetActualInstance().(interface {
		GetContentType() mdl.AttributeContentType
	}); ok {
		return typed.GetContentType()
	}
	return ""
}

func attributeName(a mdl.RequestAttribute) string {
	switch {
	case a.RequestAttributeV3 != nil:
		return a.RequestAttributeV3.Name
	case a.RequestAttributeV2 != nil:
		return a.RequestAttributeV2.Name
	default:
		return ""
	}
}

// Has reports whether the attribute has a value.
func (v Values) Has(name string) bool {
	_, ok := v[name]
	return ok
}

// String returns the value of a string or text attribute.
func (v Values) String(name string) (string, bool) {
	if c := v[name]; len(c) > 0 {
		switch {
		case c[0].StringAttributeContentV3 != nil:
			return c[0].StringAttributeContentV3.Data, true
		case c[0].TextAttributeContentV3 != nil:
			return c[0].TextAttributeContentV3.Data, true
		}
	}
	return "", false
}

// Bool returns the value of a boolean attribute.
func (v Values) Bool(name string) (bool, bool) {
	if c := v[name]; len(c) > 0 && c[0].BooleanAttributeContentV3 != nil {
		return c[0].BooleanAttributeContentV3.Data, true
	}
	return false, false
}
