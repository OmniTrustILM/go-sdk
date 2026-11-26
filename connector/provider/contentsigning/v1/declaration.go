package contentsigning

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"slices"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
)

var familyCode = regexp.MustCompile(`^[a-z][a-z0-9-]*$`)

// levelOrder is the order a family climbs: it declares a prefix of it.
var levelOrder = []mdl.SignatureLevel{
	mdl.SIGNATURELEVEL_SIGNED,
	mdl.SIGNATURELEVEL_TIMESTAMPED,
	mdl.SIGNATURELEVEL_LONG_TERM,
	mdl.SIGNATURELEVEL_ARCHIVAL,
}

// operations lists every operation that can carry attribute definitions.
var operations = []Operation{
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_VALUE,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_TIMESTAMP,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_ARCHIVE_TIMESTAMP_IMPRINT,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_ARCHIVE_TIMESTAMP,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EXTEND_TO_LEVEL,
}

// declaration is what a provider declares, read once and checked.
type declaration struct {
	family Family
	attrs  map[Operation]Attributes
}

func newDeclaration(p Provider) (*declaration, error) {
	d := &declaration{family: p.Family(), attrs: make(map[Operation]Attributes, len(operations))}
	if err := checkFamily(d.family); err != nil {
		return nil, err
	}
	seen := map[string]definition{}
	for _, op := range operations {
		a := p.Attributes(op)
		if err := checkAttributes(op, a, seen); err != nil {
			return nil, fmt.Errorf("attributes of %s: %w", op, err)
		}
		d.attrs[op] = a
	}
	return d, nil
}

func (d *declaration) declares(level mdl.SignatureLevel) bool {
	return slices.ContainsFunc(d.family.Levels, func(l mdl.SignatureLevelDeclaration) bool { return l.Level == level })
}

func checkFamily(f Family) error {
	if !familyCode.MatchString(f.Code) {
		return fmt.Errorf("family code %q must match %s", f.Code, familyCode)
	}
	if len(f.Levels) == 0 {
		return errors.New("family declares no levels")
	}
	for i, l := range f.Levels {
		if i >= len(levelOrder) || l.Level != levelOrder[i] {
			return fmt.Errorf("level %d is %q: levels follow %v in order, each once, without gaps", i+1, l.Level, levelOrder)
		}
	}
	if len(f.TransferModes) == 0 {
		return errors.New("family declares no transfer modes")
	}
	return nil
}

// definition is the part of an attribute definition the checks read.
type definition struct {
	Name        string                   `json:"name"`
	Type        mdl.AttributeType        `json:"type"`
	ContentType mdl.AttributeContentType `json:"contentType"`
	raw         []byte
	request     bool
}

func define(a mdl.BaseAttributeDto) (definition, error) {
	var d definition
	raw, err := json.Marshal(a)
	if err == nil {
		err = json.Unmarshal(raw, &d)
	}
	d.raw = raw
	return d, err
}

// defineAll describes a list of definitions and refuses a name listed twice.
func defineAll(list []mdl.BaseAttributeDto) ([]definition, error) {
	defs := make([]definition, 0, len(list))
	names := map[string]bool{}
	for _, a := range list {
		d, err := define(a)
		if err != nil {
			return nil, fmt.Errorf("attribute definition cannot be read: %w", err)
		}
		if names[d.Name] {
			return nil, fmt.Errorf("attribute %q is listed twice", d.Name)
		}
		names[d.Name] = true
		defs = append(defs, d)
	}
	return defs, nil
}

// checkAttributes checks one operation's definitions; seen carries the
// definition each name had in the operations checked before. Only
// computeDtbs may list request attributes, and a request attribute's name
// may not be a profile attribute of any operation.
func checkAttributes(op Operation, a Attributes, seen map[string]definition) error {
	if len(a.Request) > 0 && op != mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS {
		return errors.New("only computeDtbs may list request attributes")
	}
	profile, err := defineAll(a.Profile)
	if err != nil {
		return err
	}
	request, err := defineAll(a.Request)
	if err != nil {
		return err
	}
	for i := range request {
		request[i].request = true
	}
	for _, d := range request {
		if slices.ContainsFunc(profile, func(p definition) bool { return p.Name == d.Name }) {
			return fmt.Errorf("attribute %q is both a profile and a request attribute", d.Name)
		}
		if d.Type != mdl.ATTRIBUTETYPE_DATA {
			return fmt.Errorf("request attribute %q must be a data attribute", d.Name)
		}
	}
	for _, d := range append(profile, request...) {
		prev, ok := seen[d.Name]
		switch {
		case ok && prev.request != d.request:
			return fmt.Errorf("attribute %q is a profile attribute of one operation and a request attribute of another", d.Name)
		case ok && !bytes.Equal(prev.raw, d.raw):
			return fmt.Errorf("attribute %q has two different definitions", d.Name)
		}
		seen[d.Name] = d
	}
	return nil
}

// capability returns the provider's implementation of T when the family
// declares the level that needs it, and an error when it does not implement T.
func capability[T any](p Provider, d *declaration, level mdl.SignatureLevel, name string) (T, error) {
	var none T
	if !d.declares(level) {
		return none, nil
	}
	c, ok := p.(T)
	if !ok {
		return none, fmt.Errorf("family declares level %q but the provider does not implement %s", level, name)
	}
	return c, nil
}

// operationLevel is the level that makes an operation reachable.
var operationLevel = map[Operation]mdl.SignatureLevel{
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS:                        mdl.SIGNATURELEVEL_SIGNED,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_VALUE:               mdl.SIGNATURELEVEL_SIGNED,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_SIGNATURE_TIMESTAMP_IMPRINT: mdl.SIGNATURELEVEL_TIMESTAMPED,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_TIMESTAMP:           mdl.SIGNATURELEVEL_TIMESTAMPED,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_ARCHIVE_TIMESTAMP_IMPRINT:   mdl.SIGNATURELEVEL_ARCHIVAL,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_ARCHIVE_TIMESTAMP:             mdl.SIGNATURELEVEL_ARCHIVAL,
	mdl.CONTENTSIGNINGFORMATTINGOPERATION_EXTEND_TO_LEVEL:                     mdl.SIGNATURELEVEL_LONG_TERM,
}

// attributesOf returns the definitions of an operation the family reaches,
// and none for an operation it never reaches.
func (d *declaration) attributesOf(op Operation) Attributes {
	if !d.declares(operationLevel[op]) {
		return Attributes{}
	}
	return d.attrs[op]
}
