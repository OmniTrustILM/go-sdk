// Second post-processing pass: enforce single-valued ("pinned") properties.
//
// Problem: OpenAPI 3.1 lets a schema narrow one property to exactly one
// admissible value, either as a `$ref` with a sibling one-element `enum`
// (how springdoc publishes a per-variant discriminator) or as a bare
// `const`. The openapi-generator Go template drops both: a pinned
// discriminator becomes the full enum type, and a pinned `const` string
// becomes a plain `string`. The result is a package that can marshal a
// document its own UnmarshalJSON rejects — e.g. a KeyPairDataResponseV2Dto
// carrying keyRequestType "secret" round-trips to a decode failure.
//
// This pass reads the specs rather than a hand-written table, so a pin that
// appears, moves, or changes value upstream is picked up by the next regen
// instead of being transcribed by hand. For every pin it patches the
// generated type to make the invariant unbreakable:
//
//   - ToMap rejects a mismatched value, so the package cannot emit a
//     document it would refuse to read back;
//   - UnmarshalJSON rejects a mismatched value, which also makes each
//     variant self-disambiguating on the wire;
//   - the constructor sets the pinned value and drops the corresponding
//     parameter, turning a wrong value from a runtime error into a
//     compile error.
//
// Any pin whose Go counterpart cannot be resolved is a hard error: the
// alternative is shipping the generator's unenforced version silently.

package main

import (
	"encoding/json"
	"fmt"
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

// pinMarker is written into every patched function. It makes the pass
// idempotent (a re-run skips an already-patched function) and the applied
// guards greppable in the generated tree.
const pinMarker = "// fixoneof: pinned by the spec"

// pin is one property that its schema narrows to a single value.
//
// schema/property are the OpenAPI names; value is the sole admissible
// value; enumRef is the referenced enum schema when the pin is a `$ref`
// plus sibling `enum`, and empty when it is a bare `const` (which the
// generator renders as a plain Go string). modelDir is the package the
// spec generates into, relative to the model root.
type pin struct {
	schema   string
	property string
	value    string
	enumRef  string
	modelDir string
	specFile string
}

// pinTarget is a pin resolved against the generated Go it must patch.
type pinTarget struct {
	pin       pin
	path      string
	typeName  string
	fieldName string
	// valueExpr renders the pinned value in Go: an enum constant
	// identifier, or a quoted literal when the field is a plain string.
	valueExpr string
}

// modelDirForSpec maps a spec file name to its generated package directory,
// following the same convention as gen.sh's SPECS table: a trailing -vN in
// the file name is the generation, and everything else defaults to v1.
func modelDirForSpec(specFile string) string {
	name := strings.TrimSuffix(filepath.Base(specFile), ".json")
	if idx := strings.LastIndex(name, "-v"); idx > 0 {
		if version := name[idx+1:]; len(version) > 1 && version[1] >= '0' && version[1] <= '9' {
			return filepath.Join(name[:idx], version)
		}
	}
	return filepath.Join(name, "v1")
}

// discoverPins reads every spec in specDir and returns the pinned
// properties it declares.
//
// Only a pin on a schema's own property can be patched, because that is the
// only shape that maps onto a field of a generated struct. A single-valued
// enum or const found anywhere else (inside `items`, an `allOf` member, a
// nested inline object) is reported as an error rather than skipped — it
// would otherwise ship unenforced with no trace.
func discoverPins(specDir string) ([]pin, error) {
	files, err := filepath.Glob(filepath.Join(specDir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var pins []pin
	var unsupported []string
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Components struct {
				Schemas map[string]map[string]any `json:"schemas"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}

		names := make([]string, 0, len(doc.Components.Schemas))
		for name := range doc.Components.Schemas {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			schema := doc.Components.Schemas[name]
			properties, _ := schema["properties"].(map[string]any)

			propNames := make([]string, 0, len(properties))
			for prop := range properties {
				propNames = append(propNames, prop)
			}
			sort.Strings(propNames)

			for _, prop := range propNames {
				node, ok := properties[prop].(map[string]any)
				if !ok {
					continue
				}
				value, pinned, err := singleValue(node)
				if err != nil {
					return nil, fmt.Errorf("%s: %s.%s: %w", file, name, prop, err)
				}
				if !pinned {
					continue
				}
				ref, _ := node["$ref"].(string)
				pins = append(pins, pin{
					schema:   name,
					property: prop,
					value:    value,
					enumRef:  refName(ref),
					modelDir: modelDirForSpec(file),
					specFile: filepath.Base(file),
				})
				// Already accounted for; do not re-report it below.
				delete(node, "const")
				delete(node, "enum")
			}

			// Anything single-valued left elsewhere in this schema is a
			// shape this pass cannot patch.
			for _, path := range findSingleValued(schema, name) {
				unsupported = append(unsupported, filepath.Base(file)+": "+path)
			}
		}
	}

	if len(unsupported) > 0 {
		sort.Strings(unsupported)
		return nil, fmt.Errorf(
			"single-valued enum/const in a position tools/fixoneof cannot patch "+
				"(only a schema's own property maps to a generated struct field):\n  %s",
			strings.Join(unsupported, "\n  "))
	}
	return pins, nil
}

// singleValue reports whether node narrows its value to exactly one string,
// via `const` or a one-element `enum`, and returns that value. A
// single-valued non-string is an error: the generated field would not be a
// string and the guards this pass writes would not compile.
func singleValue(node map[string]any) (string, bool, error) {
	if raw, ok := node["const"]; ok {
		value, ok := raw.(string)
		if !ok {
			return "", false, fmt.Errorf("const %v is not a string", raw)
		}
		return value, true, nil
	}
	list, ok := node["enum"].([]any)
	if !ok || len(list) != 1 {
		return "", false, nil
	}
	value, ok := list[0].(string)
	if !ok {
		return "", false, fmt.Errorf("enum %v is not a list of strings", list)
	}
	return value, true, nil
}

// findSingleValued walks node and returns a path for every single-valued
// enum or const it still contains. discoverPins deletes the ones it handled
// before calling this, so whatever remains is unpatchable.
func findSingleValued(node any, path string) []string {
	var found []string
	switch typed := node.(type) {
	case map[string]any:
		if value, pinned, err := singleValue(typed); err == nil && pinned {
			found = append(found, path+" (= "+value+")")
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			found = append(found, findSingleValued(typed[key], path+"/"+key)...)
		}
	case []any:
		for i, item := range typed {
			found = append(found, findSingleValued(item, fmt.Sprintf("%s[%d]", path, i))...)
		}
	}
	return found
}

// refName returns the schema name a $ref points at.
func refName(ref string) string {
	if ref == "" {
		return ""
	}
	return ref[strings.LastIndex(ref, "/")+1:]
}

// packageIndex is the parsed Go files of one generated package, indexed by
// the type each file declares.
type packageIndex struct {
	dir   string
	files map[string]string // type name -> file path
	asts  map[string]*ast.File
}

// indexPackage parses every Go file in dir and records which type each one
// declares, so a pin can be resolved without reproducing the generator's
// file-naming rules.
func indexPackage(dir string) (*packageIndex, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	idx := &packageIndex{dir: dir, files: map[string]string{}, asts: map[string]*ast.File{}}
	for _, entry := range entries {
		if entry.IsDir() || !strings.HasSuffix(entry.Name(), ".go") {
			continue
		}
		path := filepath.Join(dir, entry.Name())
		fset := token.NewFileSet()
		file, err := parser.ParseFile(fset, path, nil, parser.ParseComments)
		if err != nil {
			return nil, fmt.Errorf("parse %s: %w", path, err)
		}
		idx.asts[path] = file
		for _, decl := range file.Decls {
			gd, ok := decl.(*ast.GenDecl)
			if !ok || gd.Tok != token.TYPE {
				continue
			}
			for _, spec := range gd.Specs {
				if ts, ok := spec.(*ast.TypeSpec); ok {
					idx.files[ts.Name.Name] = path
				}
			}
		}
	}
	return idx, nil
}

// resolvePin maps one spec pin onto the generated struct field and the Go
// expression for its pinned value.
func resolvePin(root string, p pin) (pinTarget, error) {
	dir := filepath.Join(root, p.modelDir)
	idx, err := indexPackage(dir)
	if err != nil {
		return pinTarget{}, fmt.Errorf("%s pins %s.%s: %w", p.specFile, p.schema, p.property, err)
	}
	path, ok := idx.files[p.schema]
	if !ok {
		return pinTarget{}, fmt.Errorf(
			"%s pins %s.%s but no type %s is declared in %s",
			p.specFile, p.schema, p.property, p.schema, dir)
	}

	fieldName, fieldType, ok := fieldByJSONTag(idx.asts[path], p.schema, p.property)
	if !ok {
		return pinTarget{}, fmt.Errorf(
			"%s pins %s.%s but %s declares no field tagged json:%q",
			p.specFile, p.schema, p.property, p.schema, p.property)
	}

	valueExpr := strconv.Quote(p.value)
	if fieldType != "string" {
		constName, ok := enumConstant(idx, fieldType, p.value)
		if !ok {
			return pinTarget{}, fmt.Errorf(
				"%s pins %s.%s to %q but no constant of type %s has that value",
				p.specFile, p.schema, p.property, p.value, fieldType)
		}
		valueExpr = constName
	}

	return pinTarget{
		pin:       p,
		path:      path,
		typeName:  p.schema,
		fieldName: fieldName,
		valueExpr: valueExpr,
	}, nil
}

// fieldByJSONTag finds the struct field of typeName carrying the given json
// tag name, returning its Go name and the name of its type. Matching on the
// tag rather than on a mangled field name keeps this independent of the
// generator's naming rules.
func fieldByJSONTag(file *ast.File, typeName, jsonName string) (string, string, bool) {
	for _, decl := range file.Decls {
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
				return "", "", false
			}
			for _, field := range st.Fields.List {
				if field.Tag == nil || len(field.Names) != 1 {
					continue
				}
				tag, err := strconv.Unquote(field.Tag.Value)
				if err != nil {
					continue
				}
				if jsonTagName(tag) != jsonName {
					continue
				}
				id, ok := field.Type.(*ast.Ident)
				if !ok {
					return "", "", false
				}
				return field.Names[0].Name, id.Name, true
			}
			return "", "", false
		}
	}
	return "", "", false
}

// jsonTagName extracts the property name from a struct tag's json entry.
func jsonTagName(tag string) string {
	const key = `json:"`
	idx := strings.Index(tag, key)
	if idx < 0 {
		return ""
	}
	rest := tag[idx+len(key):]
	end := strings.Index(rest, `"`)
	if end < 0 {
		return ""
	}
	name := rest[:end]
	if comma := strings.Index(name, ","); comma >= 0 {
		name = name[:comma]
	}
	return name
}

// enumConstant finds the constant of the named enum type whose value is
// want, e.g. KEYREQUESTTYPE_KEY_PAIR for "keyPair". Reading the generated
// const block avoids reproducing the generator's enum-name mangling.
func enumConstant(idx *packageIndex, typeName, want string) (string, bool) {
	path, ok := idx.files[typeName]
	if !ok {
		return "", false
	}
	for _, decl := range idx.asts[path].Decls {
		gd, ok := decl.(*ast.GenDecl)
		if !ok || gd.Tok != token.CONST {
			continue
		}
		for _, spec := range gd.Specs {
			vs, ok := spec.(*ast.ValueSpec)
			if !ok || len(vs.Names) != 1 || len(vs.Values) != 1 {
				continue
			}
			lit, ok := vs.Values[0].(*ast.BasicLit)
			if !ok || lit.Kind != token.STRING {
				continue
			}
			value, err := strconv.Unquote(lit.Value)
			if err != nil || value != want {
				continue
			}
			return vs.Names[0].Name, true
		}
	}
	return "", false
}

// edit is a byte-range replacement in one file.
type edit struct {
	start, end int
	text       string
}

// applyPin writes the three guards for one resolved pin. Returns false when
// the file already carries them, which makes a re-run a no-op.
func applyPin(target pinTarget) (bool, error) {
	src, err := os.ReadFile(target.path)
	if err != nil {
		return false, err
	}
	if strings.Contains(string(src), pinMarker) {
		return false, nil
	}
	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, target.path, src, parser.ParseComments)
	if err != nil {
		return false, fmt.Errorf("parse %s: %w", target.path, err)
	}
	if !importsPackage(file, "fmt") {
		return false, fmt.Errorf("%s: guards need the fmt import, which the file does not have", target.path)
	}

	offset := func(pos token.Pos) int { return fset.Position(pos).Offset }

	var edits []edit
	for _, decl := range file.Decls {
		fd, ok := decl.(*ast.FuncDecl)
		if !ok || fd.Body == nil {
			continue
		}
		switch {
		case isMethodOn(fd, target.typeName, "ToMap"):
			edits = append(edits, edit{
				start: offset(fd.Body.Lbrace) + 1,
				end:   offset(fd.Body.Lbrace) + 1,
				text:  "\n" + guard(target, "return nil, "),
			})
		case isMethodOn(fd, target.typeName, "UnmarshalJSON"):
			assign, ok := receiverAssignment(fd)
			if !ok {
				return false, fmt.Errorf(
					"%s: UnmarshalJSON on %s has no `*o = ...` assignment to guard",
					target.path, target.typeName)
			}
			edits = append(edits, edit{
				start: offset(assign.End()),
				end:   offset(assign.End()),
				text:  "\n" + guard(target, "return "),
			})
		case fd.Name.Name == "New"+target.typeName:
			constructorEdits, err := pinConstructor(fd, target, fset, src)
			if err != nil {
				return false, fmt.Errorf("%s: %w", target.path, err)
			}
			edits = append(edits, constructorEdits...)
		case fd.Name.Name == "New"+target.typeName+"WithDefaults":
			ret, ok := trailingReturn(fd)
			if !ok {
				return false, fmt.Errorf(
					"%s: New%sWithDefaults has no trailing return to pin before",
					target.path, target.typeName)
			}
			edits = append(edits, edit{
				start: offset(ret.Pos()),
				end:   offset(ret.Pos()),
				text:  fmt.Sprintf("this.%s = %s\n\t", target.fieldName, target.valueExpr),
			})
		}
	}

	if len(edits) == 0 {
		return false, fmt.Errorf("%s: no ToMap/UnmarshalJSON/constructor found for %s",
			target.path, target.typeName)
	}

	sort.Slice(edits, func(i, j int) bool { return edits[i].start > edits[j].start })
	out := append([]byte{}, src...)
	for _, e := range edits {
		out = append(out[:e.start], append([]byte(e.text), out[e.end:]...)...)
	}
	if err := os.WriteFile(target.path, out, 0644); err != nil {
		return false, err
	}
	return true, nil
}

// guard renders the mismatch check inserted into ToMap and UnmarshalJSON.
// returnPrefix carries the extra zero value ToMap's signature needs.
func guard(target pinTarget, returnPrefix string) string {
	return fmt.Sprintf(`	%s to %s: any other value would not round-trip.
	if o.%s != %s {
		%sfmt.Errorf("%s must be %%q for %s, got %%q", %s, o.%s)
	}`,
		pinMarker, strconv.Quote(target.pin.value),
		target.fieldName, target.valueExpr,
		returnPrefix, target.pin.property, target.typeName,
		target.valueExpr, target.fieldName)
}

// pinConstructor makes New<Type> set the pinned value itself and drops the
// now-redundant parameter, so a wrong value fails to compile rather than
// failing to marshal.
func pinConstructor(fd *ast.FuncDecl, target pinTarget, fset *token.FileSet, src []byte) ([]edit, error) {
	assign, paramName, ok := fieldAssignment(fd, target.fieldName)
	if !ok {
		return nil, fmt.Errorf("New%s does not assign %s from a parameter",
			target.typeName, target.fieldName)
	}
	offset := func(pos token.Pos) int { return fset.Position(pos).Offset }

	// Replace the assigned parameter with the pinned constant.
	edits := []edit{{
		start: offset(assign.Rhs[0].Pos()),
		end:   offset(assign.Rhs[0].End()),
		text:  target.valueExpr,
	}}

	// Re-render the parameter list without that parameter.
	var kept []string
	for _, param := range fd.Type.Params.List {
		if len(param.Names) == 1 && param.Names[0].Name == paramName {
			continue
		}
		kept = append(kept, string(src[offset(param.Pos()):offset(param.End())]))
	}
	edits = append(edits, edit{
		start: offset(fd.Type.Params.Pos()) + 1,
		end:   offset(fd.Type.Params.End()) - 1,
		text:  strings.Join(kept, ", "),
	})
	return edits, nil
}

// isMethodOn reports whether fd is the named method on typeName, with
// either a value or pointer receiver.
func isMethodOn(fd *ast.FuncDecl, typeName, method string) bool {
	if fd.Name.Name != method || fd.Recv == nil || len(fd.Recv.List) != 1 {
		return false
	}
	expr := fd.Recv.List[0].Type
	if star, ok := expr.(*ast.StarExpr); ok {
		expr = star.X
	}
	id, ok := expr.(*ast.Ident)
	return ok && id.Name == typeName
}

// receiverAssignment finds the generated `*o = T(varT)` statement that
// commits the decoded value, which is the point after which the pinned
// field can be checked.
func receiverAssignment(fd *ast.FuncDecl) (*ast.AssignStmt, bool) {
	for _, stmt := range fd.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 {
			continue
		}
		if _, ok := assign.Lhs[0].(*ast.StarExpr); ok {
			return assign, true
		}
	}
	return nil, false
}

// fieldAssignment finds `this.<field> = <param>` in fd and returns both the
// statement and the parameter name it reads.
func fieldAssignment(fd *ast.FuncDecl, field string) (*ast.AssignStmt, string, bool) {
	for _, stmt := range fd.Body.List {
		assign, ok := stmt.(*ast.AssignStmt)
		if !ok || len(assign.Lhs) != 1 || len(assign.Rhs) != 1 {
			continue
		}
		sel, ok := assign.Lhs[0].(*ast.SelectorExpr)
		if !ok || sel.Sel.Name != field {
			continue
		}
		id, ok := assign.Rhs[0].(*ast.Ident)
		if !ok {
			continue
		}
		return assign, id.Name, true
	}
	return nil, "", false
}

// trailingReturn returns the final return statement of fd's body.
func trailingReturn(fd *ast.FuncDecl) (*ast.ReturnStmt, bool) {
	if len(fd.Body.List) == 0 {
		return nil, false
	}
	ret, ok := fd.Body.List[len(fd.Body.List)-1].(*ast.ReturnStmt)
	return ret, ok
}

// importsPackage reports whether file imports the given path.
func importsPackage(file *ast.File, path string) bool {
	for _, spec := range file.Imports {
		if value, err := strconv.Unquote(spec.Path.Value); err == nil && value == path {
			return true
		}
	}
	return false
}

// applyPins resolves every pin the specs declare and patches the generated
// code. Returns the number of pins applied and the number already in place.
func applyPins(root, specDir string) (applied, alreadyPinned int, err error) {
	pins, err := discoverPins(specDir)
	if err != nil {
		return 0, 0, err
	}
	for _, p := range pins {
		target, err := resolvePin(root, p)
		if err != nil {
			return applied, alreadyPinned, err
		}
		ok, err := applyPin(target)
		if err != nil {
			return applied, alreadyPinned, err
		}
		if ok {
			fmt.Printf("pinned %s [%s.%s = %s]\n", target.path, target.typeName, target.fieldName, p.value)
			applied++
		} else {
			alreadyPinned++
		}
	}
	return applied, alreadyPinned, nil
}

// specDiscriminator is the `discriminator` stanza one schema publishes. The
// mapping is optional in OpenAPI — a stanza may name only the property, in
// which case there is nothing to compare the wrappers table's cases against.
type specDiscriminator struct {
	propertyName string
	mapping      map[string]string
	specFile     string
}

// discoverDiscriminators indexes every discriminator stanza in specDir by
// schema name. Specs share the platform schemas, so the same stanza appears
// in many files; two files publishing different stanzas for one schema is an
// error rather than a last-one-wins race.
func discoverDiscriminators(specDir string) (map[string]specDiscriminator, error) {
	files, err := filepath.Glob(filepath.Join(specDir, "*.json"))
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	out := make(map[string]specDiscriminator)
	for _, file := range files {
		raw, err := os.ReadFile(file)
		if err != nil {
			return nil, err
		}
		var doc struct {
			Components struct {
				Schemas map[string]struct {
					Discriminator *struct {
						PropertyName string            `json:"propertyName"`
						Mapping      map[string]string `json:"mapping"`
					} `json:"discriminator"`
				} `json:"schemas"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			return nil, fmt.Errorf("parse %s: %w", file, err)
		}

		names := make([]string, 0, len(doc.Components.Schemas))
		for name := range doc.Components.Schemas {
			names = append(names, name)
		}
		sort.Strings(names)

		for _, name := range names {
			stanza := doc.Components.Schemas[name].Discriminator
			if stanza == nil {
				continue
			}
			found := specDiscriminator{
				propertyName: stanza.PropertyName,
				mapping:      map[string]string{},
				specFile:     filepath.Base(file),
			}
			for value, ref := range stanza.Mapping {
				found.mapping[value] = refName(ref)
			}
			previous, seen := out[name]
			if !seen {
				out[name] = found
				continue
			}
			if previous.propertyName != found.propertyName || !sameMapping(previous.mapping, found.mapping) {
				return nil, fmt.Errorf(
					"schema %s publishes different discriminators in %s and %s",
					name, previous.specFile, found.specFile)
			}
		}
	}
	return out, nil
}

// sameMapping compares two discriminator mappings.
func sameMapping(a, b map[string]string) bool {
	if len(a) != len(b) {
		return false
	}
	for key, value := range a {
		if b[key] != value {
			return false
		}
	}
	return true
}

// verifyWrappersAgainstSpecs checks each wrappers entry against the
// discriminator its schema publishes: the property name always, and the
// value-to-variant mapping whenever the stanza carries one. It is the
// safeguard checkCompleteness cannot provide — that one validates case
// *values* against the generated struct, so a mistyped case *key*
// ("keypair" for "keyPair") or a renamed discriminator property passes it
// and then fails to decode at runtime.
//
// An entry marked noSpecStanza is verified in the other direction: the
// stanza must still be absent. That way an upstream spec that starts
// publishing a discriminator is reported instead of leaving the
// hand-written entry unchallenged.
func verifyWrappersAgainstSpecs(specDir string) error {
	stanzas, err := discoverDiscriminators(specDir)
	if err != nil {
		return err
	}
	return verifyWrappers(stanzas, wrappers)
}

// verifyWrappers is the comparison verifyWrappersAgainstSpecs performs, split
// out so it can be driven with fixture stanzas and entries.
func verifyWrappers(stanzas map[string]specDiscriminator, list []wrapper) error {
	var problems []string
	for _, w := range list {
		schemaName := w.specSchema
		switch schemaName {
		case noSpecStanza:
			if stanza, ok := stanzas[w.typeName]; ok {
				problems = append(problems, fmt.Sprintf(
					"%s is marked noSpecStanza but %s now publishes discriminator %q — "+
						"drop the marker and verify the table against it",
					w.typeName, stanza.specFile, stanza.propertyName))
			}
			continue
		case "":
			schemaName = w.typeName
		}

		stanza, ok := stanzas[schemaName]
		if !ok {
			problems = append(problems, fmt.Sprintf(
				"%s: no spec publishes a discriminator for schema %s — point specSchema at "+
					"the schema that does, or mark the entry noSpecStanza",
				w.typeName, schemaName))
			continue
		}
		if stanza.propertyName != w.discriminator {
			problems = append(problems, fmt.Sprintf(
				"%s: discriminator is %q in the table but %q in %s",
				w.typeName, w.discriminator, stanza.propertyName, stanza.specFile))
		}
		if len(stanza.mapping) > 0 && !sameMapping(stanza.mapping, w.cases) {
			problems = append(problems, fmt.Sprintf(
				"%s: cases %v do not match the %s mapping %v",
				w.typeName, w.cases, stanza.specFile, stanza.mapping))
		}
	}

	if len(problems) == 0 {
		return nil
	}
	sort.Strings(problems)
	return fmt.Errorf("tools/fixoneof wrappers table disagrees with the specs:\n  %s",
		strings.Join(problems, "\n  "))
}
