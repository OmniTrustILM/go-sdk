package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// pinSpec is a minimal spec carrying both spellings of a pin: a $ref with a
// sibling one-element enum (how springdoc publishes a per-variant
// discriminator) and a bare const.
const pinSpec = `{
  "components": {
    "schemas": {
      "Kind": {"type": "string", "enum": ["alpha", "beta"]},
      "AlphaDto": {
        "type": "object",
        "properties": {
          "kind": {"$ref": "#/components/schemas/Kind", "enum": ["alpha"]},
          "role": {"type": "string", "const": "Primary"},
          "name": {"type": "string"}
        }
      }
    }
  }
}`

// writeSpec writes one spec file into a fresh directory and returns the dir.
func writeSpec(t *testing.T, name, body string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// TestDiscoverPinsBothSpellings verifies the pin pass reads a $ref-plus-enum
// pin and a const pin out of a spec, since the generator drops both.
func TestDiscoverPinsBothSpellings(t *testing.T) {
	pins, err := discoverPins(writeSpec(t, "widget-v2.json", pinSpec))
	if err != nil {
		t.Fatalf("discoverPins: %v", err)
	}
	if len(pins) != 2 {
		t.Fatalf("found %d pins, want 2: %+v", len(pins), pins)
	}

	byProperty := map[string]pin{}
	for _, p := range pins {
		byProperty[p.property] = p
	}

	kind, ok := byProperty["kind"]
	if !ok {
		t.Fatal("the $ref-plus-enum pin on kind was not found")
	}
	if kind.value != "alpha" || kind.enumRef != "Kind" || kind.schema != "AlphaDto" {
		t.Errorf("kind pin = %+v, want value alpha, enumRef Kind, schema AlphaDto", kind)
	}
	if kind.modelDir != filepath.Join("widget", "v2") {
		t.Errorf("kind pin modelDir = %q, want widget/v2", kind.modelDir)
	}

	role, ok := byProperty["role"]
	if !ok {
		t.Fatal("the const pin on role was not found")
	}
	if role.value != "Primary" || role.enumRef != "" {
		t.Errorf("role pin = %+v, want value Primary and no enumRef", role)
	}
}

// TestDiscoverPinsRejectsUnpatchableLocation guards the pass's contract: only
// a schema's own property maps onto a generated struct field, so a
// single-valued enum anywhere else must fail loudly rather than ship
// unenforced.
func TestDiscoverPinsRejectsUnpatchableLocation(t *testing.T) {
	const nested = `{
  "components": {
    "schemas": {
      "ListDto": {
        "type": "object",
        "properties": {
          "items": {"type": "array", "items": {"type": "string", "const": "only"}}
        }
      }
    }
  }
}`
	_, err := discoverPins(writeSpec(t, "widget.json", nested))
	if err == nil {
		t.Fatal("expected an error for a pin nested inside items")
	}
	if !strings.Contains(err.Error(), "cannot patch") {
		t.Errorf("error %q does not explain that the location is unpatchable", err)
	}
}

// TestDiscoverPinsRejectsNonStringPin documents the other unsupported shape:
// the generated field would not be a string, so the guards would not compile.
func TestDiscoverPinsRejectsNonStringPin(t *testing.T) {
	const numeric = `{
  "components": {
    "schemas": {
      "VersionedDto": {
        "type": "object",
        "properties": {"version": {"type": "integer", "const": 3}}
      }
    }
  }
}`
	if _, err := discoverPins(writeSpec(t, "widget.json", numeric)); err == nil {
		t.Fatal("expected an error for a non-string pin")
	}
}

// TestModelDirForSpec pins the convention the pass shares with gen.sh's SPECS
// table: a trailing -vN is the generation, everything else defaults to v1.
func TestModelDirForSpec(t *testing.T) {
	cases := map[string]string{
		"cryptography-v2.json": filepath.Join("cryptography", "v2"),
		"authority-v3.json":    filepath.Join("authority", "v3"),
		"credential.json":      filepath.Join("credential", "v1"),
		"cryptography.json":    filepath.Join("cryptography", "v1"),
		"attributes-v2.json":   filepath.Join("attributes", "v2"),
	}
	for specFile, want := range cases {
		if got := modelDirForSpec(specFile); got != want {
			t.Errorf("modelDirForSpec(%q) = %q, want %q", specFile, got, want)
		}
	}
}

// generatedModel is a stripped-down copy of what openapi-generator emits for
// a model with one required property: a constructor taking it, a ToMap that
// writes it, and an UnmarshalJSON that commits the decoded value. None of
// them enforces the pinned value, which is the defect the pass fixes.
const generatedModel = `package v2

import (
	"bytes"
	"encoding/json"
	"fmt"
)

type Kind string

const (
	KIND_ALPHA Kind = "alpha"
	KIND_BETA  Kind = "beta"
)

type AlphaDto struct {
	Name *string ` + "`json:\"name,omitempty\"`" + `
	Kind Kind    ` + "`json:\"kind\"`" + `
}

type _AlphaDto AlphaDto

func NewAlphaDto(kind Kind) *AlphaDto {
	this := AlphaDto{}
	this.Kind = kind
	return &this
}

func NewAlphaDtoWithDefaults() *AlphaDto {
	this := AlphaDto{}
	return &this
}

func (o AlphaDto) MarshalJSON() ([]byte, error) {
	toSerialize, err := o.ToMap()
	if err != nil {
		return []byte{}, err
	}
	return json.Marshal(toSerialize)
}

func (o AlphaDto) ToMap() (map[string]interface{}, error) {
	toSerialize := map[string]interface{}{}
	toSerialize["kind"] = o.Kind
	return toSerialize, nil
}

func (o *AlphaDto) UnmarshalJSON(data []byte) (err error) {
	varAlphaDto := _AlphaDto{}

	decoder := json.NewDecoder(bytes.NewReader(data))
	decoder.DisallowUnknownFields()
	err = decoder.Decode(&varAlphaDto)

	if err != nil {
		return err
	}

	*o = AlphaDto(varAlphaDto)

	return err
}

func unused() { fmt.Print() }
`

// writeModel lays out a model root containing one generated package.
func writeModel(t *testing.T, modelDir, body string) string {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, modelDir)
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "model_alpha_dto.go"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestApplyPinWritesAllThreeGuards is the end-to-end expectation: the
// constructor supplies the pinned value and loses its parameter, and both
// ToMap and UnmarshalJSON reject anything else.
func TestApplyPinWritesAllThreeGuards(t *testing.T) {
	root := writeModel(t, filepath.Join("widget", "v2"), generatedModel)
	p := pin{
		schema:   "AlphaDto",
		property: "kind",
		value:    "alpha",
		enumRef:  "Kind",
		modelDir: filepath.Join("widget", "v2"),
		specFile: "widget-v2.json",
	}

	target, err := resolvePin(root, p)
	if err != nil {
		t.Fatalf("resolvePin: %v", err)
	}
	if target.fieldName != "Kind" {
		t.Fatalf("resolved field = %q, want Kind", target.fieldName)
	}
	if target.valueExpr != "KIND_ALPHA" {
		t.Fatalf("resolved value expression = %q, want the enum constant KIND_ALPHA", target.valueExpr)
	}

	applied, err := applyPin(target)
	if err != nil {
		t.Fatalf("applyPin: %v", err)
	}
	if !applied {
		t.Fatal("applyPin reported no change on unpatched source")
	}

	patched, err := os.ReadFile(target.path)
	if err != nil {
		t.Fatal(err)
	}
	got := string(patched)
	for _, want := range []string{
		"func NewAlphaDto() *AlphaDto {",
		"this.Kind = KIND_ALPHA",
		"if o.Kind != KIND_ALPHA {",
		"return nil, fmt.Errorf(",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("patched source is missing %q\n%s", want, got)
		}
	}
	// The constructor must no longer accept the pinned value.
	if strings.Contains(got, "func NewAlphaDto(kind Kind)") {
		t.Error("the constructor still takes the pinned property as a parameter")
	}
	// Both the encode and the decode side must be guarded.
	if strings.Count(got, "if o.Kind != KIND_ALPHA {") != 2 {
		t.Errorf("expected a guard in both ToMap and UnmarshalJSON, got %d",
			strings.Count(got, "if o.Kind != KIND_ALPHA {"))
	}
	// WithDefaults must pin it too, or a caller of that path emits a value
	// its own decoder rejects.
	if strings.Count(got, "this.Kind = KIND_ALPHA") != 2 {
		t.Error("NewAlphaDtoWithDefaults does not set the pinned value")
	}
}

// TestApplyPinIsIdempotent confirms a second run leaves the file untouched,
// so running the tool by hand after a regen cannot stack duplicate guards.
func TestApplyPinIsIdempotent(t *testing.T) {
	root := writeModel(t, filepath.Join("widget", "v2"), generatedModel)
	p := pin{
		schema:   "AlphaDto",
		property: "kind",
		value:    "alpha",
		enumRef:  "Kind",
		modelDir: filepath.Join("widget", "v2"),
		specFile: "widget-v2.json",
	}
	target, err := resolvePin(root, p)
	if err != nil {
		t.Fatalf("resolvePin: %v", err)
	}
	if _, err := applyPin(target); err != nil {
		t.Fatalf("first applyPin: %v", err)
	}
	first, err := os.ReadFile(target.path)
	if err != nil {
		t.Fatal(err)
	}

	applied, err := applyPin(target)
	if err != nil {
		t.Fatalf("second applyPin: %v", err)
	}
	if applied {
		t.Error("the second run reported a change")
	}
	second, err := os.ReadFile(target.path)
	if err != nil {
		t.Fatal(err)
	}
	if string(first) != string(second) {
		t.Error("the second run modified the file")
	}
}

// TestResolvePinUnknownProperty guards the failure path: a pin the generated
// code does not carry must stop the run rather than be skipped, because the
// alternative ships the unenforced version.
func TestResolvePinUnknownProperty(t *testing.T) {
	root := writeModel(t, filepath.Join("widget", "v2"), generatedModel)
	_, err := resolvePin(root, pin{
		schema:   "AlphaDto",
		property: "absent",
		value:    "alpha",
		modelDir: filepath.Join("widget", "v2"),
		specFile: "widget-v2.json",
	})
	if err == nil {
		t.Fatal("expected an error for a property the struct does not declare")
	}
	if !strings.Contains(err.Error(), "absent") {
		t.Errorf("error %q does not name the missing property", err)
	}
}

// TestResolvePinValueOutsideEnum guards the case the wrappers table cannot:
// a pinned value with no matching constant means the spec and the generated
// enum have drifted apart.
func TestResolvePinValueOutsideEnum(t *testing.T) {
	root := writeModel(t, filepath.Join("widget", "v2"), generatedModel)
	_, err := resolvePin(root, pin{
		schema:   "AlphaDto",
		property: "kind",
		value:    "gamma",
		enumRef:  "Kind",
		modelDir: filepath.Join("widget", "v2"),
		specFile: "widget-v2.json",
	})
	if err == nil {
		t.Fatal("expected an error for a value no constant carries")
	}
	if !strings.Contains(err.Error(), "gamma") {
		t.Errorf("error %q does not name the unmatched value", err)
	}
}

// --- wrappers-table verification ---------------------------------------------

// TestVerifyWrappersCatchesCaseKeyTypo is the safeguard checkCompleteness
// cannot provide: it validates case values against the generated struct, so a
// mistyped case *key* passes it and then fails to decode at runtime.
func TestVerifyWrappersCatchesCaseKeyTypo(t *testing.T) {
	stanzas := map[string]specDiscriminator{
		"KeyCreationResponse": {
			propertyName: "keyRequestType",
			mapping:      map[string]string{"secret": "SecretDto", "keyPair": "KeyPairDto"},
			specFile:     "cryptography-v2.json",
		},
	}
	list := []wrapper{{
		typeName:      "KeyCreationResponse",
		discriminator: "keyRequestType",
		cases:         map[string]string{"secret": "SecretDto", "keypair": "KeyPairDto"},
	}}
	err := verifyWrappers(stanzas, list)
	if err == nil {
		t.Fatal("expected the mistyped case key to be rejected")
	}
	if !strings.Contains(err.Error(), "keypair") {
		t.Errorf("error %q does not show the offending cases map", err)
	}
}

// TestVerifyWrappersCatchesRenamedProperty covers an upstream rename of the
// discriminator property, which leaves the table decoding on a field the wire
// no longer carries.
func TestVerifyWrappersCatchesRenamedProperty(t *testing.T) {
	stanzas := map[string]specDiscriminator{
		"SecretContent": {propertyName: "kind", specFile: "secret.json"},
	}
	list := []wrapper{{
		typeName:      "SecretContent",
		discriminator: "type",
		cases:         map[string]string{"secret": "SecretDto"},
	}}
	err := verifyWrappers(stanzas, list)
	if err == nil {
		t.Fatal("expected the renamed discriminator property to be rejected")
	}
	if !strings.Contains(err.Error(), "kind") {
		t.Errorf("error %q does not name the published property", err)
	}
}

// TestVerifyWrappersNoSpecStanzaBothWays checks the marker used by the
// entries whose Java wire contract diverges from the published one: absent
// stanza passes, and a stanza that appears upstream is reported so the
// hand-written entry stops being silently authoritative.
func TestVerifyWrappersNoSpecStanzaBothWays(t *testing.T) {
	list := []wrapper{{
		typeName:      "MetadataAttribute",
		discriminator: "version",
		cases:         map[string]string{"2": "V2", "3": "V3"},
		specSchema:    noSpecStanza,
	}}
	if err := verifyWrappers(map[string]specDiscriminator{}, list); err != nil {
		t.Fatalf("an absent stanza should pass: %v", err)
	}

	appeared := map[string]specDiscriminator{
		"MetadataAttribute": {propertyName: "version", specFile: "secret.json"},
	}
	err := verifyWrappers(appeared, list)
	if err == nil {
		t.Fatal("expected a newly published stanza to be reported")
	}
	if !strings.Contains(err.Error(), "noSpecStanza") {
		t.Errorf("error %q does not point at the marker to drop", err)
	}
}

// TestVerifyWrappersFollowsSpecSchema covers the indirection the generator
// forces: an inline array-item wrapper is named after the property
// (FieldMappingFieldsInner) while the stanza lives on the schema
// (MappedField).
func TestVerifyWrappersFollowsSpecSchema(t *testing.T) {
	stanzas := map[string]specDiscriminator{
		"MappedField": {propertyName: "fieldType", specFile: "authority-v3.json"},
	}
	list := []wrapper{{
		typeName:      "FieldMappingFieldsInner",
		discriminator: "fieldType",
		cases:         map[string]string{"rdn": "RdnMappedField"},
		specSchema:    "MappedField",
	}}
	if err := verifyWrappers(stanzas, list); err != nil {
		t.Fatalf("specSchema indirection should resolve: %v", err)
	}
}

// TestDiscoverDiscriminatorsRejectsDisagreement guards the shared platform
// schemas: they appear in every spec, and two specs publishing different
// stanzas for one schema must not resolve to whichever file was read last.
func TestDiscoverDiscriminatorsRejectsDisagreement(t *testing.T) {
	dir := t.TempDir()
	for name, property := range map[string]string{"a-v1.json": "type", "b-v1.json": "kind"} {
		body := `{"components":{"schemas":{"Shared":{"discriminator":{"propertyName":"` +
			property + `"}}}}}`
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	_, err := discoverDiscriminators(dir)
	if err == nil {
		t.Fatal("expected disagreeing specs to be rejected")
	}
	if !strings.Contains(err.Error(), "Shared") {
		t.Errorf("error %q does not name the schema", err)
	}
}

// TestRealWrappersTableMatchesRealSpecs is the regression this whole pass
// exists for: the committed table must agree with the committed specs, so a
// spec change that lands without a table update fails here rather than at
// runtime. Mirrors TestEnsureAllWrappersKnownRecognised.
func TestRealWrappersTableMatchesRealSpecs(t *testing.T) {
	specDir := filepath.Join("..", "..", "connector", "spec")
	if _, err := os.Stat(specDir); err != nil {
		t.Skipf("spec directory not available: %v", err)
	}
	if err := verifyWrappersAgainstSpecs(specDir); err != nil {
		t.Fatalf("the wrappers table disagrees with the specs: %v", err)
	}
}

// TestRealSpecPinsResolve is the companion check for the pin pass: every pin
// the committed specs declare must resolve against the committed models.
func TestRealSpecPinsResolve(t *testing.T) {
	specDir := filepath.Join("..", "..", "connector", "spec")
	modelRoot := filepath.Join("..", "..", "connector", "model")
	if _, err := os.Stat(specDir); err != nil {
		t.Skipf("spec directory not available: %v", err)
	}
	pins, err := discoverPins(specDir)
	if err != nil {
		t.Fatalf("discoverPins: %v", err)
	}
	if len(pins) == 0 {
		t.Fatal("no pins discovered; the pass would be silently inert")
	}
	for _, p := range pins {
		if _, err := resolvePin(modelRoot, p); err != nil {
			t.Errorf("%s.%s: %v", p.schema, p.property, err)
		}
	}
}

// TestPinnedModelsCarryTheGuard verifies the committed generated code
// actually ships the guards, catching a regen that skipped the pass.
func TestPinnedModelsCarryTheGuard(t *testing.T) {
	specDir := filepath.Join("..", "..", "connector", "spec")
	modelRoot := filepath.Join("..", "..", "connector", "model")
	if _, err := os.Stat(specDir); err != nil {
		t.Skipf("spec directory not available: %v", err)
	}
	pins, err := discoverPins(specDir)
	if err != nil {
		t.Fatalf("discoverPins: %v", err)
	}
	for _, p := range pins {
		target, err := resolvePin(modelRoot, p)
		if err != nil {
			t.Fatalf("%s.%s: %v", p.schema, p.property, err)
		}
		src, err := os.ReadFile(target.path)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(src), pinMarker) {
			t.Errorf("%s carries no pin guard — re-run gen.sh", target.path)
		}
	}
}

// TestSameMapping covers the comparison helper directly, including the
// length-equal-but-different case a naive loop would pass.
func TestSameMapping(t *testing.T) {
	if !sameMapping(map[string]string{"a": "A"}, map[string]string{"a": "A"}) {
		t.Error("identical mappings compared unequal")
	}
	if sameMapping(map[string]string{"a": "A"}, map[string]string{"a": "B"}) {
		t.Error("different values compared equal")
	}
	if sameMapping(map[string]string{"a": "A"}, map[string]string{"b": "A"}) {
		t.Error("different keys compared equal")
	}
	if sameMapping(map[string]string{"a": "A"}, map[string]string{"a": "A", "b": "B"}) {
		t.Error("different sizes compared equal")
	}
}

// TestSingleValueShapes covers the two spellings and the shapes that are not
// pins at all, since a false positive would patch an unrelated property.
func TestSingleValueShapes(t *testing.T) {
	decode := func(body string) map[string]any {
		var node map[string]any
		if err := json.Unmarshal([]byte(body), &node); err != nil {
			t.Fatal(err)
		}
		return node
	}
	cases := []struct {
		body       string
		wantValue  string
		wantPinned bool
	}{
		{`{"const":"X"}`, "X", true},
		{`{"enum":["X"]}`, "X", true},
		{`{"enum":["X","Y"]}`, "", false},
		{`{"type":"string"}`, "", false},
	}
	for _, tc := range cases {
		value, pinned, err := singleValue(decode(tc.body))
		if err != nil {
			t.Errorf("%s: %v", tc.body, err)
			continue
		}
		if pinned != tc.wantPinned || value != tc.wantValue {
			t.Errorf("%s: got (%q, %v), want (%q, %v)", tc.body, value, pinned, tc.wantValue, tc.wantPinned)
		}
	}
}
