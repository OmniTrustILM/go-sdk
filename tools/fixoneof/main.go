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
// inspected to pick the variant; variants maps wrapper field -> JSON value.
type wrapper struct {
	fileSuffix    string
	typeName      string
	discriminator string
	variants      map[string]string
}

var wrappers = []wrapper{
	{
		fileSuffix:    "model_base_attribute_content_dto_v3.go",
		typeName:      "BaseAttributeContentDtoV3",
		discriminator: "contentType",
		variants: map[string]string{
			"BooleanAttributeContentV3":   "boolean",
			"CodeBlockAttributeContentV3": "codeblock",
			"DateAttributeContentV3":      "date",
			"DateTimeAttributeContentV3":  "datetime",
			"FileAttributeContentV3":      "file",
			"FloatAttributeContentV3":     "float",
			"IntegerAttributeContentV3":   "integer",
			"ObjectAttributeContentV3":    "object",
			"StringAttributeContentV3":    "string",
			"TextAttributeContentV3":      "text",
			"TimeAttributeContentV3":      "time",
		},
	},
	{
		fileSuffix:    "model_base_attribute_dto_v3.go",
		typeName:      "BaseAttributeDtoV3",
		discriminator: "type",
		variants: map[string]string{
			"CustomAttributeV3":   "custom",
			"DataAttributeV3":     "data",
			"GroupAttributeV3":    "group",
			"InfoAttributeV3":     "info",
			"MetadataAttributeV3": "meta",
		},
	},
	{
		fileSuffix:    "model_base_attribute_dto_v2.go",
		typeName:      "BaseAttributeDtoV2",
		discriminator: "type",
		variants: map[string]string{
			"CustomAttributeV2":   "custom",
			"DataAttributeV2":     "data",
			"GroupAttributeV2":    "group",
			"InfoAttributeV2":     "info",
			"MetadataAttributeV2": "meta",
		},
	},
	{
		fileSuffix:    "model_base_attribute_dto.go",
		typeName:      "BaseAttributeDto",
		discriminator: "schemaVersion",
		variants: map[string]string{
			"BaseAttributeDtoV2": "v2",
			"BaseAttributeDtoV3": "v3",
		},
	},
	{
		fileSuffix:    "model_request_attribute.go",
		typeName:      "RequestAttribute",
		discriminator: "version",
		variants: map[string]string{
			"RequestAttributeV2": "v2",
			"RequestAttributeV3": "v3",
		},
	},
	{
		fileSuffix:    "model_response_attribute.go",
		typeName:      "ResponseAttribute",
		discriminator: "version",
		variants: map[string]string{
			"ResponseAttributeV2": "v2",
			"ResponseAttributeV3": "v3",
		},
	},
}

// generateUnmarshal renders the discriminator-aware UnmarshalJSON body for w.
// The replacement clears every variant pointer to zero before populating the
// matched one, so a reused dst does not carry stale pointers from a previous
// call.
func generateUnmarshal(w wrapper) string {
	keys := make([]string, 0, len(w.variants))
	for k := range w.variants {
		keys = append(keys, k)
	}
	sort.Strings(keys)

	var b strings.Builder
	fmt.Fprintf(&b,
		"// UnmarshalJSON decodes %s by switching on the JSON %q field.\n",
		w.typeName, w.discriminator)
	b.WriteString("// Patched by tools/fixoneof — the generator's match-counting decoder\n")
	b.WriteString("// fails on this oneOf because multiple variants share the same Go struct\n")
	b.WriteString("// shape and pass strict decode simultaneously.\n")
	fmt.Fprintf(&b, "func (dst *%s) UnmarshalJSON(data []byte) error {\n", w.typeName)
	b.WriteString("\tvar probe struct {\n")
	fmt.Fprintf(&b, "\t\tDisc string `json:\"%s\"`\n", w.discriminator)
	b.WriteString("\t}\n")
	b.WriteString("\tif err := json.Unmarshal(data, &probe); err != nil {\n")
	fmt.Fprintf(&b, "\t\treturn fmt.Errorf(\"%s: probe %s: %%w\", err)\n", w.typeName, w.discriminator)
	b.WriteString("\t}\n")

	// Reset all variant pointers so reused dst values do not retain stale data.
	for _, field := range keys {
		fmt.Fprintf(&b, "\tdst.%s = nil\n", field)
	}

	b.WriteString("\tswitch probe.Disc {\n")
	for _, field := range keys {
		disc := w.variants[field]
		fmt.Fprintf(&b, "\tcase %q:\n", disc)
		fmt.Fprintf(&b, "\t\tvar v %s\n", field)
		b.WriteString("\t\tif err := json.Unmarshal(data, &v); err != nil {\n")
		fmt.Fprintf(&b, "\t\t\treturn fmt.Errorf(\"%s: decode %s: %%w\", err)\n", w.typeName, field)
		b.WriteString("\t\t}\n")
		fmt.Fprintf(&b, "\t\tdst.%s = &v\n", field)
		b.WriteString("\t\treturn nil\n")
	}
	b.WriteString("\tdefault:\n")
	fmt.Fprintf(&b, "\t\treturn fmt.Errorf(\"%s: unknown %s %%q\", probe.Disc)\n", w.typeName, w.discriminator)
	b.WriteString("\t}\n")
	b.WriteString("}\n")
	return b.String()
}

// patchFile parses path, locates UnmarshalJSON on w.typeName, and replaces
// the function body with the generated discriminator-aware version. Returns
// nil when the function is not present (post-process re-run is idempotent
// because the new body parses identically).
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

func main() {
	root := "connector/model"
	if len(os.Args) > 1 {
		root = os.Args[1]
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
				fmt.Fprintf(os.Stderr, "WARN: %v\n", err)
				return nil
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
