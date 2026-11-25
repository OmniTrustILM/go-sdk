package contentsigning

import (
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/contentsigning/v1"
)

func str(name, label string) mdl.BaseAttributeDto {
	return dataAttr(name, label, mdl.ATTRIBUTECONTENTTYPE_STRING)
}

func TestNewHandler(t *testing.T) {
	computeDtbs := mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS
	embed := mdl.CONTENTSIGNINGFORMATTINGOPERATION_EMBED_SIGNATURE_VALUE

	tests := []struct {
		name  string
		build func() Provider
		want  string // empty: no error
	}{
		{"valid", func() Provider { return newBasic(levelSigned) }, ""},
		{"nil provider", func() Provider { return nil }, "provider must not be nil"},
		{"uppercase code", func() Provider { return withFamily(func(f *Family) { f.Code = "Mrtd" }) }, `family code "Mrtd"`},
		{"leading digit code", func() Provider { return withFamily(func(f *Family) { f.Code = "1x" }) }, `family code "1x"`},
		{"empty code", func() Provider { return withFamily(func(f *Family) { f.Code = "" }) }, "family code"},
		{"no levels", func() Provider { return newBasic() }, "no levels"},
		{"first level timestamped", func() Provider { return newBasic(levelTimestamped) }, `level 1 is "timestamped"`},
		{"gap in levels", func() Provider { return newBasic(levelSigned, levelLongTerm) }, `level 2 is "long_term"`},
		{"repeated level", func() Provider { return newBasic(levelSigned, levelSigned) }, `level 2 is "signed"`},
		{"too many levels", func() Provider {
			return newBasic(levelSigned, levelTimestamped, levelLongTerm, levelArchival, levelArchival)
		}, `level 5 is "archival"`},
		{"no transfer modes", func() Provider { return withFamily(func(f *Family) { f.TransferModes = nil }) }, "no transfer modes"},
		{"name in both lists", func() Provider {
			return withAttrs(computeDtbs, Attributes{Profile: list(str("a", "A")), Request: list(str("a", "A"))})
		}, `"a" is both a profile and a request attribute`},
		{"request attribute that is not data", func() Provider {
			return withAttrs(computeDtbs, Attributes{Request: list(infoAttr("note"))})
		}, `request attribute "note" must be a data attribute`},
		{"name listed twice", func() Provider {
			return withAttrs(computeDtbs, Attributes{Profile: list(str("a", "A"), str("a", "A"))})
		}, `"a" is listed twice`},
		{"two definitions across operations", func() Provider {
			p := newBasic(levelSigned)
			p.attrs = map[Operation]Attributes{
				computeDtbs: {Profile: list(str("a", "First"))},
				embed:       {Profile: list(str("a", "Second"))},
			}
			return p
		}, `"a" has two different definitions`},
		{"same definition across operations", func() Provider {
			p := newBasic(levelSigned)
			p.attrs = map[Operation]Attributes{
				computeDtbs: {Profile: list(str("a", "A"))},
				embed:       {Profile: list(str("a", "A"))},
			}
			return p
		}, ""},
		{"timestamped without SignatureTimestamper", func() Provider { return newBasic(levelSigned, levelTimestamped) }, "SignatureTimestamper"},
		{"long_term without Extender", func() Provider {
			return withTimestamp{basic: newBasic(levelSigned, levelTimestamped, levelLongTerm)}
		}, "Extender"},
		{"archival without ArchiveTimestamper", func() Provider {
			return &fullExceptArchive{full: newFull(new(bool)), levels: []mdl.SignatureLevel{levelSigned, levelTimestamped, levelLongTerm, levelArchival}}
		}, "ArchiveTimestamper"},
		{"every capability", func() Provider { return newFull(new(bool)) }, ""},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewHandler(tc.build())
			switch {
			case tc.want == "" && err != nil:
				t.Fatalf("unexpected error: %v", err)
			case tc.want != "" && (err == nil || !strings.Contains(err.Error(), tc.want)):
				t.Fatalf("error = %v, want one naming %q", err, tc.want)
			}
		})
	}
}

func TestNewHandlerReadsDeclarationOnce(t *testing.T) {
	p := &countingProvider{basic: newBasic(levelSigned)}
	if _, err := NewHandler(p); err != nil {
		t.Fatal(err)
	}
	if p.families != 1 || p.attributes != len(operations) {
		t.Fatalf("Family read %d times, Attributes %d times", p.families, p.attributes)
	}
}

func TestNewHandlerSurfacesUnreadableDefinition(t *testing.T) {
	p := newBasic(levelSigned)
	p.attrs = map[Operation]Attributes{mdl.CONTENTSIGNINGFORMATTINGOPERATION_COMPUTE_DTBS: {Profile: []mdl.BaseAttributeDto{{}}}}
	if _, err := NewHandler(p); err == nil || !strings.Contains(err.Error(), "cannot be read") {
		t.Fatalf("error = %v", err)
	}
}

func list(a ...mdl.BaseAttributeDto) []mdl.BaseAttributeDto { return a }

func withFamily(edit func(*Family)) *basic {
	p := newBasic(levelSigned)
	edit(&p.family)
	return p
}

func withAttrs(op Operation, a Attributes) *basic {
	p := newBasic(levelSigned)
	p.attrs = map[Operation]Attributes{op: a}
	return p
}

// fullExceptArchive declares every level but hides the archive capability.
type fullExceptArchive struct {
	*full
	levels []mdl.SignatureLevel
}

func (f *fullExceptArchive) Family() Family { return demoFamily(f.levels...) }

// ComputeArchiveTimestampImprint shadows the promoted method with a different
// signature, so the type no longer implements ArchiveTimestamper.
func (f *fullExceptArchive) ComputeArchiveTimestampImprint() {}

type countingProvider struct {
	*basic
	families, attributes int
}

func (c *countingProvider) Family() Family {
	c.families++
	return c.basic.Family()
}

func (c *countingProvider) Attributes(op Operation) Attributes {
	c.attributes++
	return c.basic.Attributes(op)
}
