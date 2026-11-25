package contentsigning

import (
	"encoding/json"
	"errors"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// attrOf decodes a request attribute from its wire form.
func attrOf(t *testing.T, name, version, contentType, content string) mdl.RequestAttribute {
	t.Helper()
	raw := `{"uuid":"d0235059-d463-4937-a2aa-20efdd000001","name":"` + name + `","version":"` + version +
		`","contentType":"` + contentType + `","content":[` + content + `]}`
	var a mdl.RequestAttribute
	if err := json.Unmarshal([]byte(raw), &a); err != nil {
		t.Fatal(err)
	}
	return a
}

func stringAttr(t *testing.T, name, value string) mdl.RequestAttribute {
	return attrOf(t, name, "v3", "string", `{"contentType":"string","data":"`+value+`"}`)
}

func boolAttr(t *testing.T, name string, value bool) mdl.RequestAttribute {
	data := "false"
	if value {
		data = "true"
	}
	return attrOf(t, name, "v3", "boolean", `{"contentType":"boolean","data":`+data+`}`)
}

func declaredAttrs() Attributes {
	return Attributes{
		Profile: list(str("prefix", "Prefix"), dataAttr("strict", "Strict", mdl.ATTRIBUTECONTENTTYPE_BOOLEAN)),
		Request: list(str("tag", "Tag")),
	}
}

func wantRejected(t *testing.T, err error, detail string) {
	t.Helper()
	var se *shared.Error
	if !errors.As(err, &se) || se.Status != 422 || se.ErrorCode != "ATTRIBUTES_REJECTED" || !strings.Contains(se.Detail, detail) {
		t.Fatalf("error = %v, want 422 ATTRIBUTES_REJECTED naming %q", err, detail)
	}
}

func TestResolveReturnsProfileValue(t *testing.T) {
	v, err := Resolve(declaredAttrs(), []mdl.RequestAttribute{stringAttr(t, "prefix", "P"), boolAttr(t, "strict", true)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v.String("prefix"); !ok || s != "P" {
		t.Fatalf("prefix = %q, %v", s, ok)
	}
	if b, ok := v.Bool("strict"); !ok || !b {
		t.Fatalf("strict = %v, %v", b, ok)
	}
	if !v.Has("prefix") || v.Has("tag") {
		t.Fatal("Has reports the wrong names")
	}
}

func TestResolveRequestWins(t *testing.T) {
	v, err := Resolve(declaredAttrs(),
		[]mdl.RequestAttribute{stringAttr(t, "tag", "from-profile")},
		[]mdl.RequestAttribute{stringAttr(t, "tag", "from-request")})
	if err != nil {
		t.Fatal(err)
	}
	if s, _ := v.String("tag"); s != "from-request" {
		t.Fatalf("tag = %q", s)
	}
}

func TestResolveIgnoresUndeclaredProfileAttributes(t *testing.T) {
	v, err := Resolve(declaredAttrs(), []mdl.RequestAttribute{stringAttr(t, "other", "x"), attrOf(t, "legacy", "v2", "string", "")}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(v) != 0 {
		t.Fatalf("values = %v", v)
	}
}

func TestResolveRefusals(t *testing.T) {
	tests := []struct {
		name           string
		profile, reqst []mdl.RequestAttribute
		detail         string
	}{
		{"undeclared request attribute", nil, []mdl.RequestAttribute{stringAttr(t, "prefix", "x")}, `"prefix"`},
		{"unknown request attribute", nil, []mdl.RequestAttribute{stringAttr(t, "nope", "x")}, `"nope"`},
		{"wrong content type in request", nil, []mdl.RequestAttribute{boolAttr(t, "tag", true)}, "content type"},
		{"wrong content type in profile", []mdl.RequestAttribute{boolAttr(t, "prefix", true)}, nil, "content type"},
		{"wrong content item type", []mdl.RequestAttribute{attrOf(t, "strict", "v3", "boolean", `{"contentType":"string","data":"true"}`)}, nil, "content of type"},
		{"schema v2 in request", nil, []mdl.RequestAttribute{attrOf(t, "tag", "v2", "string", "")}, "schema version v3"},
		{"schema v2 in profile", []mdl.RequestAttribute{attrOf(t, "prefix", "v2", "string", "")}, nil, "schema version v3"},
		{"name twice in request", nil, []mdl.RequestAttribute{stringAttr(t, "tag", "a"), stringAttr(t, "tag", "b")}, "more than once"},
		{"name twice in profile", []mdl.RequestAttribute{stringAttr(t, "prefix", "a"), stringAttr(t, "prefix", "b")}, nil, "more than once"},
		{"attribute without a version", nil, []mdl.RequestAttribute{{}}, `""`},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := Resolve(declaredAttrs(), tc.profile, tc.reqst)
			wantRejected(t, err, tc.detail)
		})
	}
}

func TestResolveRefusalsDoNotEchoValues(t *testing.T) {
	_, err := Resolve(declaredAttrs(), nil, []mdl.RequestAttribute{boolAttr(t, "tag", true), stringAttr(t, "tag", "secret-value")})
	if err != nil && strings.Contains(err.Error(), "secret-value") {
		t.Fatalf("error echoes a value: %v", err)
	}
}

func TestValuesAccessorsReportAbsentOnMismatch(t *testing.T) {
	v, err := Resolve(declaredAttrs(), []mdl.RequestAttribute{stringAttr(t, "prefix", "P"), boolAttr(t, "strict", true)}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := v.String("strict"); ok {
		t.Error("String on a boolean attribute must report absent")
	}
	if _, ok := v.Bool("prefix"); ok {
		t.Error("Bool on a string attribute must report absent")
	}
	if _, ok := v.String("undeclared"); ok {
		t.Error("String on an undeclared name must report absent")
	}
	if _, ok := v.Bool("undeclared"); ok {
		t.Error("Bool on an undeclared name must report absent")
	}
}

func TestValuesReadTextAttributes(t *testing.T) {
	declared := Attributes{Profile: list(dataAttr("note", "Note", mdl.ATTRIBUTECONTENTTYPE_TEXT))}
	a := attrOf(t, "note", "v3", "text", `{"contentType":"text","data":"hello"}`)
	v, err := Resolve(declared, []mdl.RequestAttribute{a}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if s, ok := v.String("note"); !ok || s != "hello" {
		t.Fatalf("note = %q, %v", s, ok)
	}
}

func TestResolveRejectsUnreadableDeclaration(t *testing.T) {
	if _, err := Resolve(Attributes{Profile: []mdl.BaseAttributeDto{{}}}, nil, nil); err == nil {
		t.Fatal("an unreadable definition must fail")
	}
	if _, err := Resolve(Attributes{Request: []mdl.BaseAttributeDto{{}}}, nil, nil); err == nil {
		t.Fatal("an unreadable request definition must fail")
	}
}
