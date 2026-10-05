package cryptography

import (
	"fmt"
	"slices"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

const dataAttributeV3Version = 3

// algorithmAttribute is a reserved single-select string attribute for picking
// one code of a contract enum.
type algorithmAttribute[T ~string] struct {
	uuid        string
	name        string
	label       string
	description string
	codes       []labeledCode[T]
	selectionErrors
	// unknown refuses a code outside the contract as VALIDATION_FAILED, as
	// Java's findByCode does. A known code the key lacks is the provider's call.
	unknown error
}

// selectionErrors are the VALIDATION_FAILED refusals of a malformed selection.
// Their details name both reserved identifiers, as the Java SDK's do.
type selectionErrors struct {
	notSelected error
	repeated    error
	notV3       error
	notString   error
}

// selectionErrorsFor builds the refusals for the attribute carried in list,
// such as "Cipher".
func selectionErrorsFor(list, name, uuid string) selectionErrors {
	attribute := fmt.Sprintf("attribute with name '%s' and UUID '%s'", name, uuid)
	return selectionErrors{
		notSelected: errValidationFailed(list + " attributes must select one value of the " + attribute + "."),
		repeated:    errValidationFailed(list + " " + attribute + " must be supplied once."),
		notV3:       errValidationFailed(list + " " + attribute + " must be a v3 attribute."),
		notString:   errValidationFailed(list + " " + attribute + " must carry a string value."),
	}
}

type labeledCode[T ~string] struct {
	code  T
	label string
}

// all returns every contract code, in the contract's order.
func (a algorithmAttribute[T]) all() []T {
	out := make([]T, len(a.codes))
	for i, entry := range a.codes {
		out[i] = entry.code
	}
	return out
}

// contains reports whether code is a contract code in its canonical spelling.
func (a algorithmAttribute[T]) contains(code T) bool {
	return slices.ContainsFunc(a.codes, func(entry labeledCode[T]) bool { return entry.code == code })
}

// labelOf returns the label of a canonically spelled code. Any other spelling
// gets an empty label.
func (a algorithmAttribute[T]) labelOf(code T) string {
	for _, entry := range a.codes {
		if entry.code == code {
			return entry.label
		}
	}
	return ""
}

// definition builds the required single-select v3 definition offering supported.
func (a algorithmAttribute[T]) definition(supported []T) mdl.BaseAttributeDto {
	properties := mdl.DataAttributeProperties{
		Label:           a.label,
		Visible:         true,
		Required:        true,
		List:            true,
		ProtectionLevel: mdl.PROTECTIONLEVEL_NONE.Ptr(),
	}
	definition := mdl.NewDataAttributeV3(a.uuid, a.name,
		dataAttributeV3Version, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING, properties, mdl.ATTRIBUTEVERSION_V3)
	description := a.description
	definition.Description = &description
	definition.Content = make([]mdl.BaseAttributeContentDtoV3, len(supported))
	for i, algorithm := range supported {
		definition.Content[i] = a.option(algorithm)
	}
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(definition)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

// selection is the request attribute Core sends to select algorithm.
func (a algorithmAttribute[T]) selection(algorithm T) mdl.RequestAttribute {
	selection := mdl.NewRequestAttributeV3(a.uuid, a.name, mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V3)
	selection.Content = []mdl.BaseAttributeContentDtoV3{a.option(algorithm)}
	return mdl.RequestAttributeV3AsRequestAttribute(selection)
}

func (a algorithmAttribute[T]) selected(attrs []mdl.RequestAttribute) (T, error) {
	selection, err := a.find(attrs)
	if err != nil {
		return "", err
	}
	given, err := a.value(selection)
	if err != nil {
		return "", err
	}
	entry, ok := a.lookupIgnoringCase(given)
	if !ok {
		return "", a.unknown
	}
	return entry.code, nil
}

// find returns the one attribute claiming the reserved UUID or name. It
// refuses a second claimant and one carrying only one of the two identifiers.
func (a algorithmAttribute[T]) find(attrs []mdl.RequestAttribute) (*mdl.RequestAttributeV3, error) {
	found, err := soleClaimant(attrs, a.matchesUUIDOrName, a.repeated)
	if err != nil {
		return nil, err
	}
	if found == nil {
		return nil, a.notSelected
	}
	if !a.matchesUUIDAndName(*found) {
		return nil, a.notSelected
	}
	if found.RequestAttributeV3 == nil || found.RequestAttributeV3.Version != mdl.ATTRIBUTEVERSION_V3 {
		return nil, a.notV3
	}
	return found.RequestAttributeV3, nil
}

func (a algorithmAttribute[T]) matchesUUIDOrName(attr mdl.RequestAttribute) bool {
	uuid, name := requestAttributeIdentity(attr)
	return sameUUID(uuid, a.uuid) || name == a.name
}

func (a algorithmAttribute[T]) matchesUUIDAndName(attr mdl.RequestAttribute) bool {
	uuid, name := requestAttributeIdentity(attr)
	return sameUUID(uuid, a.uuid) && name == a.name
}

// value returns the single string the selection carries.
func (a algorithmAttribute[T]) value(selection *mdl.RequestAttributeV3) (string, error) {
	if len(selection.Content) != 1 {
		return "", a.notSelected
	}
	item := selection.Content[0].StringAttributeContentV3
	if selection.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING || item == nil || item.ContentType != mdl.ATTRIBUTECONTENTTYPE_STRING {
		return "", a.notString
	}
	return item.Data, nil
}

func (a algorithmAttribute[T]) lookupIgnoringCase(given string) (labeledCode[T], bool) {
	for _, entry := range a.codes {
		if strings.EqualFold(string(entry.code), given) {
			return entry, true
		}
	}
	return labeledCode[T]{}, false
}

// option offers algorithm under its contract spelling and label. A code
// outside the contract is offered verbatim, unlabeled.
func (a algorithmAttribute[T]) option(algorithm T) mdl.BaseAttributeContentDtoV3 {
	entry, ok := a.lookupIgnoringCase(string(algorithm))
	if !ok {
		return mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
			mdl.NewStringAttributeContentV3(string(algorithm), mdl.ATTRIBUTECONTENTTYPE_STRING))
	}
	item := mdl.NewStringAttributeContentV3(string(entry.code), mdl.ATTRIBUTECONTENTTYPE_STRING)
	item.Reference = &entry.label
	return mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(item)
}

// attributeNamed returns the one attribute named name, or nil. A second one is
// refused with repeated.
func attributeNamed(attrs []mdl.RequestAttribute, name string, repeated error) (*mdl.RequestAttribute, error) {
	return soleClaimant(attrs, func(attr mdl.RequestAttribute) bool {
		_, attrName := requestAttributeIdentity(attr)
		return attrName == name
	}, repeated)
}

// soleClaimant returns the one attribute that claims accepts, or nil. A second
// one is refused with repeated.
func soleClaimant(attrs []mdl.RequestAttribute, claims func(mdl.RequestAttribute) bool, repeated error) (*mdl.RequestAttribute, error) {
	var found *mdl.RequestAttribute
	for i := range attrs {
		if !claims(attrs[i]) {
			continue
		}
		if found != nil {
			return nil, repeated
		}
		found = &attrs[i]
	}
	return found, nil
}

func requestAttributeIdentity(a mdl.RequestAttribute) (uuid, name string) {
	switch {
	case a.RequestAttributeV3 != nil:
		return a.RequestAttributeV3.Uuid, a.RequestAttributeV3.Name
	case a.RequestAttributeV2 != nil:
		return a.RequestAttributeV2.Uuid, a.RequestAttributeV2.Name
	default:
		return "", ""
	}
}

func sameUUID(x, y string) bool {
	return strings.EqualFold(x, y)
}
