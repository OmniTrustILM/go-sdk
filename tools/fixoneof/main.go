// Post-processes openapi-generator's Go output to replace ambiguous oneOf
// UnmarshalJSON methods with discriminator-aware versions.
//
// Problem: the generator emits a "try every variant, count matches" decoder.
// When two or more variants share the same Go struct shape — e.g. every V3
// content type with fields {Reference, Data, ContentType} — the count is
// always > 1 and decoding fails with "data matches more than one schema in
// oneOf(...)". OpenAPI specs typically resolve this with a `discriminator`
// stanza on the oneOf schema, but the openapi-generator Go template does not
// honour it. This tool patches the affected files in place so every regen
// pass produces working code.
//
// Run after openapi-generator:
//
//	go run ./tools/fixoneof connector/model
//
// The list of patched wrappers is hard-coded below; extend it when new oneOf
// types are added to the specs.
package main

import (
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// wrapper describes one oneOf type whose generated UnmarshalJSON is replaced.
//
// fileSuffix matches the model file name under each connector/model/*/v*/
// package; typeName is the wrapper struct; discriminator is the JSON field
// inspected to pick the variant; cases maps each JSON discriminator value
// to the wrapper field name to populate. Multiple discriminator values may
// point to the same field when the spec routes them to a single variant
// (e.g. ResourceObjectContentData maps authorities/entities/locations/
// credentials all to ResourceSimpleContentData).
type wrapper struct {
	fileSuffix    string
	typeName      string
	discriminator string
	cases         map[string]string
	// numeric, when true, reads the discriminator as a JSON number (e.g. the
	// attribute `version` 2/3 that the Java BaseAttributeSerializer writes)
	// rather than a string, normalizing it to its textual form for the switch.
	numeric bool
	// defaultDisc, when non-empty, is the discriminator value assumed when the
	// field is absent/empty on the wire — matching a Java deserializer's
	// defaultImpl (e.g. BaseAttribute/RequestAttribute default a missing
	// version to V2).
	defaultDisc string
}

var wrappers = []wrapper{
	{
		fileSuffix:    "model_base_attribute_content_dto_v3.go",
		typeName:      "BaseAttributeContentDtoV3",
		discriminator: "contentType",
		cases: map[string]string{
			"boolean":   "BooleanAttributeContentV3",
			"codeblock": "CodeBlockAttributeContentV3",
			"date":      "DateAttributeContentV3",
			"datetime":  "DateTimeAttributeContentV3",
			"file":      "FileAttributeContentV3",
			"float":     "FloatAttributeContentV3",
			"integer":   "IntegerAttributeContentV3",
			"object":    "ObjectAttributeContentV3",
			"resource":  "ResourceObjectContent",
			"string":    "StringAttributeContentV3",
			"text":      "TextAttributeContentV3",
			"time":      "TimeAttributeContentV3",
		},
	},
	{
		fileSuffix:    "model_base_attribute_dto_v3.go",
		typeName:      "BaseAttributeDtoV3",
		discriminator: "type",
		cases: map[string]string{
			"custom": "CustomAttributeV3",
			"data":   "DataAttributeV3",
			"group":  "GroupAttributeV3",
			"info":   "InfoAttributeV3",
			"meta":   "MetadataAttributeV3",
		},
	},
	{
		fileSuffix:    "model_base_attribute_dto_v2.go",
		typeName:      "BaseAttributeDtoV2",
		discriminator: "type",
		cases: map[string]string{
			"custom": "CustomAttributeV2",
			"data":   "DataAttributeV2",
			"group":  "GroupAttributeV2",
			"info":   "InfoAttributeV2",
			"meta":   "MetadataAttributeV2",
		},
	},
	{
		// BaseAttribute (outer V2/V3 selector). The Java wire discriminator is
		// a NUMERIC `version` (2/3) written by BaseAttributeSerializer, NOT the
		// `schemaVersion` string the OpenAPI declares (that field is only
		// emitted when a concrete subtype is serialized by its own type, and is
		// absent on the canonical connector-definition wire). A missing version
		// defaults to 2 (V2), matching BaseAttributeDeserializer.
		fileSuffix:    "model_base_attribute_dto.go",
		typeName:      "BaseAttributeDto",
		discriminator: "version",
		numeric:       true,
		defaultDisc:   "2",
		cases: map[string]string{
			"2": "BaseAttributeDtoV2",
			"3": "BaseAttributeDtoV3",
		},
	},
	{
		// DataAttribute (V2/V3), same numeric `version` selector as BaseAttribute.
		fileSuffix:    "model_data_attribute.go",
		typeName:      "DataAttribute",
		discriminator: "version",
		numeric:       true,
		defaultDisc:   "2",
		cases: map[string]string{
			"2": "DataAttributeV2",
			"3": "DataAttributeV3",
		},
	},
	{
		// MetadataAttribute (V2/V3), same numeric `version` selector.
		fileSuffix:    "model_metadata_attribute.go",
		typeName:      "MetadataAttribute",
		discriminator: "version",
		numeric:       true,
		defaultDisc:   "2",
		cases: map[string]string{
			"2": "MetadataAttributeV2",
			"3": "MetadataAttributeV3",
		},
	},
	{
		// RequestAttribute uses a STRING `version` ("v2"/"v3"); a missing
		// version defaults to V2 (Java @JsonTypeInfo defaultImpl).
		fileSuffix:    "model_request_attribute.go",
		typeName:      "RequestAttribute",
		discriminator: "version",
		defaultDisc:   "v2",
		cases: map[string]string{
			"v2": "RequestAttributeV2",
			"v3": "RequestAttributeV3",
		},
	},
	{
		fileSuffix:    "model_response_attribute.go",
		typeName:      "ResponseAttribute",
		discriminator: "version",
		cases: map[string]string{
			"v2": "ResponseAttributeV2",
			"v3": "ResponseAttributeV3",
		},
	},
	{
		fileSuffix:    "model_base_attribute_constraint.go",
		typeName:      "BaseAttributeConstraint",
		discriminator: "type",
		defaultDisc:   "regExp", // Java defaultImpl = RegexpAttributeConstraint
		cases: map[string]string{
			"dateTime": "DateTimeAttributeConstraint",
			"range":    "RangeAttributeConstraint",
			"regExp":   "RegexpAttributeConstraint",
		},
	},
	{
		fileSuffix:    "model_resource_object_content_data.go",
		typeName:      "ResourceObjectContentData",
		discriminator: "resource",
		cases: map[string]string{
			"authorities":  "ResourceSimpleContentData",
			"entities":     "ResourceSimpleContentData",
			"locations":    "ResourceSimpleContentData",
			"credentials":  "ResourceSimpleContentData",
			"certificates": "ResourceCertificateContentData",
			"secrets":      "ResourceSecretContentData",
		},
	},
	{
		fileSuffix:    "model_secret_content.go",
		typeName:      "SecretContent",
		discriminator: "type",
		cases: map[string]string{
			"apiKey":     "ApiKeySecretContent",
			"basicAuth":  "BasicAuthSecretContent",
			"generic":    "GenericSecretContent",
			"jwtToken":   "JwtTokenSecretContent",
			"keyStore":   "KeyStoreSecretContent",
			"keyValue":   "KeyValueSecretContent",
			"privateKey": "PrivateKeySecretContent",
			"secretKey":  "SecretKeySecretContent",
		},
	},
	{
		// authority-v3: anonymous oneOf inside FieldMapping.fields[] items.
		// The spec's discriminator sits on the MappedField allOf base
		// (propertyName "fieldType", FieldType enum rdn/san/extension); each
		// variant is allOf(MappedField + specifics), so fieldType selects the
		// variant. Patching by discriminator is stricter than the generator's
		// match-counting fallback (a contradictory payload like
		// {fieldType:"rdn", extensionOid:...} is rejected rather than resolved
		// by shape).
		fileSuffix:    "model_field_mapping_fields_inner.go",
		typeName:      "FieldMappingFieldsInner",
		discriminator: "fieldType",
		cases: map[string]string{
			"extension": "ExtensionMappedField",
			"rdn":       "RdnMappedField",
			"san":       "SanMappedField",
		},
	},
}

// knownUnpatchable lists oneOf wrappers the generator emits but for which
// the OpenAPI spec defines NO discriminator stanza. Without a discriminator
// the wrapper-discovery safeguard would flag them every run, yet there is
// no reliable way for fixoneof to write a discriminator-aware decoder. The
// generator's match-counting fallback ships for these — it works when the
// variants are shape-distinct (different field names or types) and FAILS
// when they collide.
//
// The map value documents the per-wrapper rationale. To remove an entry,
// add a `discriminator` stanza in the corresponding spec schema, regenerate,
// and add a matching wrappers entry above.
var knownUnpatchable = map[string]string{
	// These two oneOfs have NO per-object wire discriminator, so no in-object field lets
	// a decoder pick a variant — Java itself cannot either. They are inherently
	// parent-context-only and cannot round-trip a standalone element.
	"BaseAttributeContentDtoV2": "V2 attribute content carries NO per-object discriminator on the Java wire: BaseAttributeContentV2.getContentType() is @JsonIgnore, every variant serializes as bare {reference,data}, and Java's AttributeContentDeserializer decodes them all into the single base type (never a specific variant). The V2/V3 choice comes from the parent attribute's sibling contentType, and V2-variant selection is parent-context/data-shape only. Not fixable without a spec/wire discriminator on the V2 content object itself.",
	"KeyDataValue":              "KeyData.value uses @JsonTypeInfo(EXTERNAL_PROPERTY, property=\"format\") — the discriminator is a sibling field on the parent KeyData, not inside the value object. RawKeyValue/SpkiKeyValue/PrkiKeyValue/EprkiKeyValue serialize as byte-identical {\"value\":\"...\"}; only KeyData.format distinguishes them. No in-object field exists to dispatch on, so a standalone KeyDataValue cannot be resolved to a variant (Java needs the parent's format).",
}

// generateUnmarshal renders the discriminator-aware UnmarshalJSON body for w.
// The replacement clears every variant pointer to zero before populating the
// matched one, so a reused dst does not carry stale pointers from a previous
// call. When multiple discriminator values map to the same variant field
// (e.g. ResourceObjectContentData's authorities/entities/locations/credentials
// all routing to ResourceSimpleContentData), they are emitted as a single
// `case "a", "b", "c":` clause.
func generateUnmarshal(w wrapper) string {
	// Build field -> sorted []discValue map so we can emit one switch case
	// per field with all matching disc values listed.
	byField := make(map[string][]string)
	for disc, field := range w.cases {
		byField[field] = append(byField[field], disc)
	}
	fields := make([]string, 0, len(byField))
	for field, discs := range byField {
		sort.Strings(discs)
		fields = append(fields, field)
	}
	sort.Strings(fields)

	var b strings.Builder
	fmt.Fprintf(&b,
		"// UnmarshalJSON decodes %s by switching on the JSON %q field.\n",
		w.typeName, w.discriminator)
	b.WriteString("// Patched by tools/fixoneof — the generator's match-counting decoder\n")
	b.WriteString("// fails on this oneOf because multiple variants share the same Go struct\n")
	b.WriteString("// shape and pass strict decode simultaneously.\n")
	fmt.Fprintf(&b, "func (dst *%s) UnmarshalJSON(data []byte) error {\n", w.typeName)
	probeType := "string"
	if w.numeric {
		probeType = "json.Number"
	}
	b.WriteString("\tvar probe struct {\n")
	fmt.Fprintf(&b, "\t\tDisc %s `json:\"%s\"`\n", probeType, w.discriminator)
	b.WriteString("\t}\n")
	b.WriteString("\tif err := json.Unmarshal(data, &probe); err != nil {\n")
	fmt.Fprintf(&b, "\t\treturn fmt.Errorf(\"%s: probe %s: %%w\", err)\n", w.typeName, w.discriminator)
	b.WriteString("\t}\n")
	if w.numeric {
		b.WriteString("\tdisc := string(probe.Disc)\n")
	} else {
		b.WriteString("\tdisc := probe.Disc\n")
	}
	if w.defaultDisc != "" {
		b.WriteString("\tif disc == \"\" {\n")
		fmt.Fprintf(&b, "\t\tdisc = %q // absent %s defaults to this per the Java wire contract\n", w.defaultDisc, w.discriminator)
		b.WriteString("\t}\n")
	}

	// Reset every distinct variant pointer so reused dst values do not retain
	// stale data from a previous decode call.
	for _, field := range fields {
		fmt.Fprintf(&b, "\tdst.%s = nil\n", field)
	}

	b.WriteString("\tswitch disc {\n")
	for _, field := range fields {
		discs := byField[field]
		caseLabels := make([]string, len(discs))
		for i, d := range discs {
			caseLabels[i] = fmt.Sprintf("%q", d)
		}
		fmt.Fprintf(&b, "\tcase %s:\n", strings.Join(caseLabels, ", "))
		fmt.Fprintf(&b, "\t\tvar v %s\n", field)
		b.WriteString("\t\tif err := json.Unmarshal(data, &v); err != nil {\n")
		fmt.Fprintf(&b, "\t\t\treturn fmt.Errorf(\"%s: decode %s: %%w\", err)\n", w.typeName, field)
		b.WriteString("\t\t}\n")
		fmt.Fprintf(&b, "\t\tdst.%s = &v\n", field)
		b.WriteString("\t\treturn nil\n")
	}
	b.WriteString("\tdefault:\n")
	fmt.Fprintf(&b, "\t\treturn fmt.Errorf(\"%s: unknown %s %%q\", disc)\n", w.typeName, w.discriminator)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// collectVariantFields walks f looking for `type w.typeName struct { ... }`
// and returns the names of every `*Foo` pointer field. By openapi-generator
// convention each oneOf branch is a field of that shape on the wrapper, so
// this set is the authoritative list of variants the file ships. Returns
// (nil, false) when the struct declaration is absent.
//
// Used to assert the hard-coded `variants` map for w lists every variant
// present in the regenerated file — see patchFile for the failure path.
func collectVariantFields(f *ast.File, typeName string) (map[string]string, bool) {
	for _, decl := range f.Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.TYPE {
			continue
		}
		for _, spec := range gd.Specs {
			ts, ok := spec.(*ast.TypeSpec)
			if !ok || ts.Name.Name != typeName {
				continue
			}
			st, ok := ts.Type.(*ast.StructType)
			if !ok {
				return nil, false
			}
			fields := make(map[string]string, len(st.Fields.List))
			for _, fld := range st.Fields.List {
				ptr, ok := fld.Type.(*ast.StarExpr)
				if !ok {
					continue
				}
				id, ok := ptr.X.(*ast.Ident)
				if !ok {
					continue
				}
				for _, name := range fld.Names {
					fields[name.Name] = id.Name
				}
			}
			return fields, true
		}
	}
	return nil, false
}

// checkCompleteness fails when the struct in f declares a variant pointer
// field that has no entry in w.cases (would silently fall through to the
// default branch at runtime and fail to decode), or when w.cases names a
// field absent from the struct (stale entry left after a spec change).
//
// This is the safeguard that catches upstream spec changes: when a new
// oneOf branch appears in the generated model, regeneration MUST stop with
// a clear error so the wrappers table gets updated. Silent omission (the
// prior behaviour, see PR#18 review on ResourceObjectContent) made values
// un-decodable at runtime.
func checkCompleteness(path string, w wrapper, f *ast.File) error {
	fields, ok := collectVariantFields(f, w.typeName)
	if !ok {
		return nil
	}
	covered := make(map[string]bool, len(w.cases))
	for _, field := range w.cases {
		covered[field] = true
	}
	var missing, extra []string
	for name := range fields {
		if !covered[name] {
			missing = append(missing, name)
		}
	}
	for name := range covered {
		if _, has := fields[name]; !has {
			extra = append(extra, name)
		}
	}
	if len(missing) == 0 && len(extra) == 0 {
		return nil
	}
	sort.Strings(missing)
	sort.Strings(extra)
	return fmt.Errorf(
		"%s: wrappers[%s] out of sync with generated struct; "+
			"missing variants (present in struct, absent from cases) %v; "+
			"extra variants (in cases, absent from struct) %v — "+
			"update tools/fixoneof wrappers and re-run",
		path, w.typeName, missing, extra)
}

// patchFile parses path, locates UnmarshalJSON on w.typeName, and replaces
// the function body with the generated discriminator-aware version. Returns
// nil when the function is not present (post-process re-run is idempotent
// because the new body parses identically).
//
// Before patching, runs checkCompleteness against the parsed struct so any
// variant present in the struct but missing from w.variants aborts the run
// before broken output is written.
func patchFile(path string, w wrapper) (bool, error) {
	src, err := os.ReadFile(path)
	if err != nil {
		return false, err
	}
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, src, parser.ParseComments)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", path, err)
	}

	if err := checkCompleteness(path, w, f); err != nil {
		return false, err
	}

	for _, decl := range f.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok {
			continue
		}
		if fd.Recv == nil || len(fd.Recv.List) != 1 {
			continue
		}
		star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
		if !ok {
			continue
		}
		id, ok := star.X.(*ast.Ident)
		if !ok || id.Name != w.typeName {
			continue
		}
		if fd.Name.Name != "UnmarshalJSON" {
			continue
		}

		// Include the doc comment in the byte range if present so we
		// replace it too — the new body carries its own doc.
		start := fset.Position(fd.Pos()).Offset
		if fd.Doc != nil {
			start = fset.Position(fd.Doc.Pos()).Offset
		}
		end := fset.Position(fd.End()).Offset

		out := append([]byte{}, src[:start]...)
		out = append(out, []byte(generateUnmarshal(w))...)
		out = append(out, src[end:]...)
		// The original UnmarshalJSON was the only consumer of the
		// validator import; drop it so the file still compiles.
		out = dropImport(out, "gopkg.in/validator.v2")
		if err := os.WriteFile(path, out, 0644); err != nil {
			return false, err
		}
		return true, nil
	}
	return false, nil
}

// dropImport removes a single import line of the form `<TAB>"path"` from src.
// Idempotent: noop when the import is absent. Only handles the simple form
// emitted by openapi-generator; multi-line aliased imports are left alone.
func dropImport(src []byte, path string) []byte {
	line := []byte("\t\"" + path + "\"\n")
	idx := strings.Index(string(src), string(line))
	if idx < 0 {
		return src
	}
	return append(src[:idx], src[idx+len(line):]...)
}

// discoveredWrapper records a oneOf wrapper found in the model tree along
// with the variant field names declared on its struct. variantFields maps
// field name -> pointee type name (Go convention: identical, but kept both
// for clarity).
type discoveredWrapper struct {
	typeName      string
	variantFields map[string]string
	sourcePath    string
}

// discoverOneOfWrappers walks root looking for openapi-generator oneOf
// wrappers, recognised by the presence of a `func (x *T) GetActualInstance()`
// method (generated only for oneOf types). For each unique typeName, returns
// one record carrying its struct's variant pointer fields. The result is
// keyed by typeName.
//
// Used by ensureAllWrappersKnown to fail when a brand-new wrapper type is
// emitted by the generator but absent from the hard-coded wrappers list —
// catches the case where a spec gains an entirely new oneOf schema and the
// post-processor would otherwise silently leave the broken generated
// UnmarshalJSON in place.
func discoverOneOfWrappers(root string) (map[string]discoveredWrapper, error) {
	out := make(map[string]discoveredWrapper)
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() || !strings.HasSuffix(path, ".go") {
			return nil
		}
		fset := token.NewFileSet()
		f, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return fmt.Errorf("parse %s: %w", path, err)
		}
		// Collect any `(*T) GetActualInstance()` receivers in this file —
		// these are the oneOf wrapper types defined in `f`.
		for _, decl := range f.Decls {
			fd, ok := decl.(*ast.FuncDecl)
			if !ok || fd.Name.Name != "GetActualInstance" {
				continue
			}
			if fd.Recv == nil || len(fd.Recv.List) != 1 {
				continue
			}
			star, ok := fd.Recv.List[0].Type.(*ast.StarExpr)
			if !ok {
				continue
			}
			id, ok := star.X.(*ast.Ident)
			if !ok {
				continue
			}
			if _, seen := out[id.Name]; seen {
				continue
			}
			fields, ok := collectVariantFields(f, id.Name)
			if !ok {
				continue
			}
			out[id.Name] = discoveredWrapper{
				typeName:      id.Name,
				variantFields: fields,
				sourcePath:    path,
			}
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	return out, nil
}

// ensureAllWrappersKnown fails when discoverOneOfWrappers finds a wrapper
// type that has no entry in either the hard-coded wrappers list or
// knownUnpatchable. Reports the missing type name, the file it was found
// in, and the variant fields the generator emitted so the operator can
// fill in the discriminator when extending wrappers.
//
// A wrapper present in knownUnpatchable passes this check without being
// patched — see knownUnpatchable's docstring for the trade-off.
func ensureAllWrappersKnown(found map[string]discoveredWrapper) error {
	known := make(map[string]bool, len(wrappers)+len(knownUnpatchable))
	for _, w := range wrappers {
		known[w.typeName] = true
	}
	for name := range knownUnpatchable {
		known[name] = true
	}
	var unknown []string
	for name := range found {
		if !known[name] {
			unknown = append(unknown, name)
		}
	}
	if len(unknown) == 0 {
		return nil
	}
	sort.Strings(unknown)
	var b strings.Builder
	b.WriteString("unknown oneOf wrapper(s) found in model tree — add entries to tools/fixoneof wrappers (or knownUnpatchable if the spec has no discriminator):\n")
	for _, name := range unknown {
		dw := found[name]
		fieldNames := make([]string, 0, len(dw.variantFields))
		for k := range dw.variantFields {
			fieldNames = append(fieldNames, k)
		}
		sort.Strings(fieldNames)
		fmt.Fprintf(&b, "  - %s (at %s) variants: %v\n", name, dw.sourcePath, fieldNames)
	}
	return fmt.Errorf("%s", b.String())
}

func main() {
	root := "connector/model"
	if len(os.Args) > 1 {
		root = os.Args[1]
	}

	// Pre-pass: every oneOf wrapper the generator emitted must have a
	// wrappers entry. Catches new wrapper types introduced by spec changes
	// before they ship with the generator's broken UnmarshalJSON.
	found, err := discoverOneOfWrappers(root)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	if err := ensureAllWrappersKnown(found); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}

	patched := 0
	skipped := 0
	if err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if d.IsDir() {
			return nil
		}
		base := filepath.Base(path)
		for _, w := range wrappers {
			if base != w.fileSuffix {
				continue
			}
			ok, err := patchFile(path, w)
			if err != nil {
				return err
			}
			if ok {
				fmt.Printf("patched %s [%s]\n", path, w.typeName)
				patched++
			} else {
				fmt.Printf("skipped %s [%s] (UnmarshalJSON not found)\n", path, w.typeName)
				skipped++
			}
		}
		return nil
	}); err != nil {
		fmt.Fprintln(os.Stderr, err)
		os.Exit(1)
	}
	fmt.Printf("\n%d patched, %d skipped\n", patched, skipped)
}
