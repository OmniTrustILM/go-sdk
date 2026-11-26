package cms

import (
	"bytes"
	"crypto/sha256"
	"encoding/asn1"
	"encoding/hex"
	"slices"
	"testing"
	"time"
)

var (
	oidMRTDSecurityObject = asn1.ObjectIdentifier{2, 23, 136, 1, 1, 1}
	fixedDigest           = mustDecode("000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f")
)

func basicInput(signingTime *time.Time) SignedAttributesInput {
	return SignedAttributesInput{ContentType: oidMRTDSecurityObject, MessageDigest: fixedDigest, SigningTime: signingTime}
}

func timePtr(t time.Time) *time.Time { return &t }

type parsedAttribute struct {
	encoding []byte
	Type     asn1.ObjectIdentifier
	Values   []asn1.RawValue
}

type attributeFields struct {
	Type   asn1.ObjectIdentifier
	Values []asn1.RawValue `asn1:"set"`
}

// parseAttributes splits a DER SET OF Attribute into its members.
func parseAttributes(t *testing.T, der []byte) []parsedAttribute {
	t.Helper()
	var set asn1.RawValue
	if rest, err := asn1.Unmarshal(der, &set); err != nil || len(rest) != 0 {
		t.Fatalf("parse set: %v (rest %d)", err, len(rest))
	}
	if set.Class != asn1.ClassUniversal || set.Tag != asn1.TagSet || !set.IsCompound {
		t.Fatalf("not a SET: %+v", set)
	}
	var attrs []parsedAttribute
	for rest := set.Bytes; len(rest) > 0; {
		var raw asn1.RawValue
		var err error
		if rest, err = asn1.Unmarshal(rest, &raw); err != nil {
			t.Fatalf("parse attribute: %v", err)
		}
		var fields attributeFields
		if _, err := asn1.Unmarshal(raw.FullBytes, &fields); err != nil {
			t.Fatalf("parse attribute: %v", err)
		}
		attrs = append(attrs, parsedAttribute{encoding: raw.FullBytes, Type: fields.Type, Values: fields.Values})
	}
	return attrs
}

func findAttribute(attrs []parsedAttribute, oid asn1.ObjectIdentifier) *parsedAttribute {
	for i := range attrs {
		if attrs[i].Type.Equal(oid) {
			return &attrs[i]
		}
	}
	return nil
}

func TestSignedAttributesGolden(t *testing.T) {
	got, err := SignedAttributes(basicInput(timePtr(time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))))
	if err != nil {
		t.Fatal(err)
	}
	if want := readGoldenHex(t, "signedattrs-basic.hex"); !bytes.Equal(got, want) {
		t.Errorf("got  %x\nwant %x", got, want)
	}
}

func TestSignedAttributesDEROrder(t *testing.T) {
	extra := []Attribute{
		{Type: asn1.ObjectIdentifier{1, 2, 3, 9}, Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x09}}}},
		{Type: asn1.ObjectIdentifier{1, 2, 3, 5}, Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x05}}}},
		{Type: asn1.ObjectIdentifier{1, 2, 3, 1}, Values: []asn1.RawValue{{FullBytes: []byte{0x04, 0x01, 0x01}}}},
	}
	in := basicInput(timePtr(time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC)))
	in.Extra = extra
	got, err := SignedAttributes(in)
	if err != nil {
		t.Fatal(err)
	}
	if got[0] != 0x31 {
		t.Fatalf("first byte %#x, want 0x31", got[0])
	}
	attrs := parseAttributes(t, got)
	if len(attrs) != 6 {
		t.Fatalf("got %d attributes, want 6", len(attrs))
	}
	var encodings [][]byte
	for _, a := range attrs {
		encodings = append(encodings, a.encoding)
	}
	if !slices.IsSortedFunc(encodings, bytes.Compare) {
		t.Errorf("attributes are not in DER order")
	}
}

func TestSignedAttributesWithoutSigningTime(t *testing.T) {
	got, err := SignedAttributes(basicInput(nil))
	if err != nil {
		t.Fatal(err)
	}
	attrs := parseAttributes(t, got)
	if len(attrs) != 2 || findAttribute(attrs, oidAttrSigningTime) != nil {
		t.Errorf("unexpected attributes %d", len(attrs))
	}
}

func TestSignedAttributesTimeNormalisation(t *testing.T) {
	want, err := SignedAttributes(basicInput(timePtr(time.Date(2026, 11, 24, 10, 0, 0, 0, time.UTC))))
	if err != nil {
		t.Fatal(err)
	}
	zone := time.FixedZone("CET", 3600)
	got, err := SignedAttributes(basicInput(timePtr(time.Date(2026, 11, 24, 11, 0, 0, 999_000_000, zone))))
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(got, want) {
		t.Errorf("offset and sub-second time changed the output:\n got %x\nwant %x", got, want)
	}
}

func TestSignedAttributesTimeEncoding(t *testing.T) {
	cases := []struct {
		name string
		when time.Time
		tag  int
	}{
		{"last UTCTime second", time.Date(2049, 12, 31, 23, 59, 59, 0, time.UTC), asn1.TagUTCTime},
		{"first GeneralizedTime second", time.Date(2050, 1, 1, 0, 0, 0, 0, time.UTC), asn1.TagGeneralizedTime},
		{"before 1950", time.Date(1949, 12, 31, 23, 59, 59, 0, time.UTC), asn1.TagGeneralizedTime},
		{"first UTCTime second", time.Date(1950, 1, 1, 0, 0, 0, 0, time.UTC), asn1.TagUTCTime},
		{"offset crossing 2050", time.Date(2050, 1, 1, 0, 30, 0, 0, time.FixedZone("x", 3600)), asn1.TagUTCTime},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			der, err := SignedAttributes(basicInput(&tc.when))
			if err != nil {
				t.Fatal(err)
			}
			attr := findAttribute(parseAttributes(t, der), oidAttrSigningTime)
			if attr == nil || len(attr.Values) != 1 {
				t.Fatal("no signing time attribute")
			}
			if attr.Values[0].Tag != tc.tag {
				t.Errorf("tag %d, want %d", attr.Values[0].Tag, tc.tag)
			}
		})
	}
}

func TestSignedAttributesTimeOutOfRange(t *testing.T) {
	if _, err := SignedAttributes(basicInput(timePtr(time.Date(10000, 1, 1, 0, 0, 0, 0, time.UTC)))); err == nil {
		t.Error("expected an error for a year beyond 9999")
	}
}

func TestSignedAttributesAlgorithmProtection(t *testing.T) {
	alg, _ := Lookup("ML-DSA-65")
	in := basicInput(nil)
	in.AlgorithmProtection = &alg
	got, err := SignedAttributes(in)
	if err != nil {
		t.Fatal(err)
	}
	// contentType, algorithmProtection [digest SHA-512, signature [1] ML-DSA-65], messageDigest.
	want := mustHex(t, `31 73
		30 15 06 09 2a864886f70d010903 31 08 06 06 678108010101
		30 29 06 09 2a864886f70d010934 31 1c 30 1a
			300b0609608648016503040203
			a10b0609608648016503040312
		30 2f 06 09 2a864886f70d010904 31 22 04 20
			000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f`)
	if !bytes.Equal(got, want) {
		t.Errorf("got  %x\nwant %x", got, want)
	}
}

func TestSignedAttributesErrors(t *testing.T) {
	odd := asn1.RawValue{FullBytes: []byte{0x04, 0x01, 0x01}}
	cases := map[string]func(*SignedAttributesInput){
		"empty content type":   func(in *SignedAttributesInput) { in.ContentType = nil },
		"empty message digest": func(in *SignedAttributesInput) { in.MessageDigest = nil },
		"extra content type": func(in *SignedAttributesInput) {
			in.Extra = []Attribute{{Type: oidAttrContentType, Values: []asn1.RawValue{odd}}}
		},
		"extra message digest": func(in *SignedAttributesInput) {
			in.Extra = []Attribute{{Type: oidAttrMessageDigest, Values: []asn1.RawValue{odd}}}
		},
		"extra signing time": func(in *SignedAttributesInput) {
			in.Extra = []Attribute{{Type: oidAttrSigningTime, Values: []asn1.RawValue{odd}}}
		},
		"extra without values": func(in *SignedAttributesInput) {
			in.Extra = []Attribute{{Type: asn1.ObjectIdentifier{1, 2, 3}}}
		},
		"duplicate extra": func(in *SignedAttributesInput) {
			a := Attribute{Type: asn1.ObjectIdentifier{1, 2, 3}, Values: []asn1.RawValue{odd}}
			in.Extra = []Attribute{a, a}
		},
		"extra clashes with protection": func(in *SignedAttributesInput) {
			alg, _ := Lookup("Ed25519")
			in.AlgorithmProtection = &alg
			in.Extra = []Attribute{{Type: oidAttrAlgorithmProtection, Values: []asn1.RawValue{odd}}}
		},
		"invalid extra oid": func(in *SignedAttributesInput) {
			in.Extra = []Attribute{{Type: asn1.ObjectIdentifier{1}, Values: []asn1.RawValue{odd}}}
		},
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			in := basicInput(nil)
			mutate(&in)
			if _, err := SignedAttributes(in); err == nil {
				t.Error("expected an error")
			}
		})
	}
}

func TestSignedAttributesDeterministic(t *testing.T) {
	digest := sha256.Sum256([]byte("x"))
	in := SignedAttributesInput{
		ContentType: oidMRTDSecurityObject, MessageDigest: digest[:],
		SigningTime: timePtr(time.Date(2026, 1, 2, 3, 4, 5, 0, time.UTC)),
	}
	a, errA := SignedAttributes(in)
	b, errB := SignedAttributes(in)
	if errA != nil || errB != nil || !bytes.Equal(a, b) {
		t.Errorf("outputs differ: %v %v", errA, errB)
	}
}

func mustDecode(s string) []byte {
	b, err := hex.DecodeString(s)
	if err != nil {
		panic(err)
	}
	return b
}
