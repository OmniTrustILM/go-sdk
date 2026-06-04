package main

import (
	"go/parser"
	"go/token"
	"strings"
	"testing"
)

// TestCheckCompletenessMissingField guards the bug from PR#18 review: a
// variant pointer field present on the generated wrapper struct that is
// missing from the cases map MUST cause fixoneof to fail. The original
// silent-omission behaviour shipped un-decodable payloads at runtime.
func TestCheckCompletenessMissingField(t *testing.T) {
	src := `package v1

type Wrapper struct {
	Foo *Foo
	Bar *Bar
	Baz *Baz
}

func (w *Wrapper) GetActualInstance() interface{} { return nil }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	w := wrapper{
		typeName:      "Wrapper",
		discriminator: "kind",
		cases: map[string]string{
			"foo": "Foo",
			"bar": "Bar",
			// "baz": "Baz" is intentionally omitted to trigger the guard.
		},
	}
	err = checkCompleteness("synthetic.go", w, f)
	if err == nil {
		t.Fatal("checkCompleteness returned nil; expected error for missing Baz field")
	}
	if !strings.Contains(err.Error(), "Baz") {
		t.Errorf("error %q does not mention the missing field Baz", err.Error())
	}
	if !strings.Contains(err.Error(), "missing variants") {
		t.Errorf("error %q does not mention 'missing variants' classifier", err.Error())
	}
}

// TestCheckCompletenessExtraEntry guards the inverse case: a cases entry
// for a variant that was removed upstream must also fail so the wrappers
// table cannot accumulate dead entries.
func TestCheckCompletenessExtraEntry(t *testing.T) {
	src := `package v1

type Wrapper struct {
	Foo *Foo
}

func (w *Wrapper) GetActualInstance() interface{} { return nil }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	w := wrapper{
		typeName:      "Wrapper",
		discriminator: "kind",
		cases: map[string]string{
			"foo":  "Foo",
			"gone": "Removed",
		},
	}
	err = checkCompleteness("synthetic.go", w, f)
	if err == nil {
		t.Fatal("checkCompleteness returned nil; expected error for extra Removed entry")
	}
	if !strings.Contains(err.Error(), "Removed") {
		t.Errorf("error %q does not mention the stale entry Removed", err.Error())
	}
	if !strings.Contains(err.Error(), "extra variants") {
		t.Errorf("error %q does not mention 'extra variants' classifier", err.Error())
	}
}

// TestCheckCompletenessHappyPath verifies that a struct + cases that match
// 1:1 (and the many-to-one case used by ResourceObjectContentData) pass.
func TestCheckCompletenessHappyPath(t *testing.T) {
	src := `package v1

type Wrapper struct {
	Foo *Foo
	Bar *Bar
}

func (w *Wrapper) GetActualInstance() interface{} { return nil }
`
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, "synthetic.go", src, parser.ParseComments)
	if err != nil {
		t.Fatalf("parse synthetic: %v", err)
	}
	w := wrapper{
		typeName:      "Wrapper",
		discriminator: "kind",
		// Two disc values both routing to Foo — exercises the many-to-one
		// pattern used by ResourceObjectContentData.
		cases: map[string]string{
			"foo1": "Foo",
			"foo2": "Foo",
			"bar":  "Bar",
		},
	}
	if err := checkCompleteness("synthetic.go", w, f); err != nil {
		t.Fatalf("checkCompleteness returned %v; expected nil", err)
	}
}

// TestEnsureAllWrappersKnownUnknown guards the second safeguard layer: a
// brand-new oneOf wrapper type emitted by openapi-generator (recognised by
// the GetActualInstance method) that has no entry in either wrappers or
// knownUnpatchable MUST cause fixoneof to fail with an actionable message.
func TestEnsureAllWrappersKnownUnknown(t *testing.T) {
	found := map[string]discoveredWrapper{
		"BrandNewWrapper": {
			typeName:      "BrandNewWrapper",
			variantFields: map[string]string{"VariantA": "VariantA", "VariantB": "VariantB"},
			sourcePath:    "connector/model/x/v1/model_brand_new_wrapper.go",
		},
	}
	err := ensureAllWrappersKnown(found)
	if err == nil {
		t.Fatal("ensureAllWrappersKnown returned nil; expected error for unknown wrapper")
	}
	if !strings.Contains(err.Error(), "BrandNewWrapper") {
		t.Errorf("error %q does not name the unknown wrapper", err.Error())
	}
	if !strings.Contains(err.Error(), "VariantA") || !strings.Contains(err.Error(), "VariantB") {
		t.Errorf("error %q does not list the variant fields for diagnosis", err.Error())
	}
}

// TestEnsureAllWrappersKnownTolerated verifies that a discovered wrapper
// present in knownUnpatchable passes the guard. Lets oneOfs with no spec
// discriminator coexist with the post-processor without spamming false
// alarms — see knownUnpatchable docstring.
func TestEnsureAllWrappersKnownTolerated(t *testing.T) {
	if len(knownUnpatchable) == 0 {
		t.Skip("knownUnpatchable is empty; nothing to assert tolerance for")
	}
	var name string
	for k := range knownUnpatchable {
		name = k
		break
	}
	found := map[string]discoveredWrapper{
		name: {typeName: name, variantFields: map[string]string{}, sourcePath: "any"},
	}
	if err := ensureAllWrappersKnown(found); err != nil {
		t.Fatalf("ensureAllWrappersKnown rejected knownUnpatchable entry %q: %v", name, err)
	}
}

// TestEnsureAllWrappersKnownRecognised verifies that every wrapper in the
// hard-coded list passes (no stale entries that don't exist as oneOfs).
func TestEnsureAllWrappersKnownRecognised(t *testing.T) {
	found := make(map[string]discoveredWrapper, len(wrappers))
	for _, w := range wrappers {
		found[w.typeName] = discoveredWrapper{
			typeName:      w.typeName,
			variantFields: map[string]string{},
			sourcePath:    w.fileSuffix,
		}
	}
	if err := ensureAllWrappersKnown(found); err != nil {
		t.Fatalf("ensureAllWrappersKnown rejected a known wrapper: %v", err)
	}
}

// TestGenerateUnmarshalGroupsCases verifies that when multiple discriminator
// values route to the same variant field (ResourceObjectContentData pattern),
// the generated switch emits a single grouped `case` clause for them rather
// than duplicate clauses. Keeps output readable and avoids redundant decode.
func TestGenerateUnmarshalGroupsCases(t *testing.T) {
	w := wrapper{
		typeName:      "Group",
		discriminator: "kind",
		cases: map[string]string{
			"a": "Same",
			"b": "Same",
			"c": "Same",
			"x": "Other",
		},
	}
	out := generateUnmarshal(w)
	// All three labels for Same on one case line. Order is alphabetical
	// because generateUnmarshal sorts disc values per field.
	if !strings.Contains(out, `case "a", "b", "c":`) {
		t.Errorf("generated code missing grouped case clause for Same; got:\n%s", out)
	}
	if !strings.Contains(out, `case "x":`) {
		t.Errorf("generated code missing single case for Other; got:\n%s", out)
	}
	if strings.Count(out, "var v Same") != 1 {
		t.Errorf("expected exactly one `var v Same` block; got:\n%s", out)
	}
}
