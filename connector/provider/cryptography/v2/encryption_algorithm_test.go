package cryptography_test

import (
	"encoding/json"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// contractEncryptionAlgorithms is a copy of the Java EncryptionAlgorithm enum, in its order.
var contractEncryptionAlgorithms = []struct{ code, label string }{
	{"RSA/ECB/PKCS1Padding", "RSAES-PKCS1-v1_5"},
	{"RSA/ECB/OAEPWithSHA-1AndMGF1Padding", "RSAES-OAEP with SHA-1"},
	{"RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "RSAES-OAEP with SHA-256"},
	{"RSA/ECB/OAEPWithSHA-384AndMGF1Padding", "RSAES-OAEP with SHA-384"},
	{"RSA/ECB/OAEPWithSHA-512AndMGF1Padding", "RSAES-OAEP with SHA-512"},
}

// encryptionSelectionJSON renders a v3 encryptionAlgorithm selection holding content.
func encryptionSelectionJSON(content string) string {
	return `{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"encryptionAlgorithm","contentType":"string","version":"v3",` +
		`"content":` + content + `}`
}

func TestEncryptionAlgorithmsListTheContractCodesAndLabels(t *testing.T) {
	got := cryptography.EncryptionAlgorithms()
	if len(got) != len(contractEncryptionAlgorithms) {
		t.Fatalf("EncryptionAlgorithms() has %d codes, want %d: %v", len(got), len(contractEncryptionAlgorithms), got)
	}
	for i, want := range contractEncryptionAlgorithms {
		if string(got[i]) != want.code {
			t.Errorf("EncryptionAlgorithms()[%d] = %q, want %q", i, got[i], want.code)
		}
		if label := got[i].Label(); label != want.label {
			t.Errorf("%s.Label() = %q, want %q", want.code, label, want.label)
		}
		if !got[i].IsValid() {
			t.Errorf("%s.IsValid() = false, want true", want.code)
		}
	}
}

func TestEncryptionAlgorithmOutsideTheContractIsInvalid(t *testing.T) {
	cases := []struct{ name, code string }{
		{"empty", ""},
		{"a code outside the contract", "RSA/ECB/NoPadding"},
		{"a contract code in lower case", "rsa/ecb/pkcs1padding"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algorithm := cryptography.EncryptionAlgorithm(tc.code)
			if algorithm.IsValid() {
				t.Errorf("IsValid() = true, want false")
			}
			if label := algorithm.Label(); label != "" {
				t.Errorf("Label() = %q, want empty", label)
			}
		})
	}
}

func TestEncryptionAlgorithmDefinitionMatchesTheContract(t *testing.T) {
	definition := cryptography.EncryptionAlgorithmDefinition(
		cryptography.EncryptionAlgorithmRSAPKCS1V15,
		cryptography.EncryptionAlgorithmRSAOAEPSHA256,
	)

	got, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	assertJSONEqual(t, got, `{
		"uuid": "5e364467-fa95-4253-907b-0c73cdfb2be7",
		"name": "encryptionAlgorithm",
		"description": "Encryption algorithm used to encrypt or decrypt the data",
		"version": 3,
		"type": "data",
		"contentType": "string",
		"schemaVersion": "v3",
		"properties": {
			"label": "Encryption Algorithm",
			"visible": true,
			"required": true,
			"readOnly": false,
			"list": true,
			"multiSelect": false,
			"protectionLevel": "none",
			"extensibleList": false
		},
		"content": [
			{"reference": "RSAES-PKCS1-v1_5", "data": "RSA/ECB/PKCS1Padding", "contentType": "string"},
			{"reference": "RSAES-OAEP with SHA-256", "data": "RSA/ECB/OAEPWithSHA-256AndMGF1Padding", "contentType": "string"}
		]
	}`)
}

func TestEncryptionAlgorithmDefinitionSpellsACaseVariantCanonically(t *testing.T) {
	definition := cryptography.EncryptionAlgorithmDefinition(cryptography.EncryptionAlgorithm("rsa/ecb/oaepwithsha-1andmgf1padding"))

	got, err := json.Marshal(definition.BaseAttributeDtoV3.DataAttributeV3.Content)
	if err != nil {
		t.Fatalf("marshal definition content: %v", err)
	}
	assertJSONEqual(t, got, `[{"reference":"RSAES-OAEP with SHA-1","data":"RSA/ECB/OAEPWithSHA-1AndMGF1Padding","contentType":"string"}]`)
}

func TestEncryptionAlgorithmDefinitionOffersACodeOutsideTheContractUnlabeled(t *testing.T) {
	definition := cryptography.EncryptionAlgorithmDefinition(cryptography.EncryptionAlgorithm("RSA/ECB/NoPadding"))

	got, err := json.Marshal(definition.BaseAttributeDtoV3.DataAttributeV3.Content)
	if err != nil {
		t.Fatalf("marshal definition content: %v", err)
	}
	assertJSONEqual(t, got, `[{"data":"RSA/ECB/NoPadding","contentType":"string"}]`)
}

func TestEncryptionAlgorithmSelectionMatchesTheContract(t *testing.T) {
	selection := cryptography.EncryptionAlgorithmSelection(cryptography.EncryptionAlgorithmRSAOAEPSHA384)

	got, err := json.Marshal(selection)
	if err != nil {
		t.Fatalf("marshal selection: %v", err)
	}
	assertJSONEqual(t, got, encryptionSelectionJSON(
		`[{"reference":"RSAES-OAEP with SHA-384","data":"RSA/ECB/OAEPWithSHA-384AndMGF1Padding","contentType":"string"}]`,
	))
}

const (
	otherCipherAttribute = `{"uuid":"5f0c1c52-2b1e-4a57-9f4e-0c7f4f5b8d11","name":"keyLabel","contentType":"string","version":"v3",` +
		`"content":[{"contentType":"string","data":"rsa-key"}]}`
	noEncryptionSelectionDetail = "Cipher attributes must select one value of the attribute with name 'encryptionAlgorithm' and UUID '5e364467-fa95-4253-907b-0c73cdfb2be7'."
	encryptionRepeatedDetail    = "Cipher attribute with name 'encryptionAlgorithm' and UUID '5e364467-fa95-4253-907b-0c73cdfb2be7' must be supplied once."
	encryptionNotV3Detail       = "Cipher attribute with name 'encryptionAlgorithm' and UUID '5e364467-fa95-4253-907b-0c73cdfb2be7' must be a v3 attribute."
	encryptionNotStringDetail   = "Cipher attribute with name 'encryptionAlgorithm' and UUID '5e364467-fa95-4253-907b-0c73cdfb2be7' must carry a string value."
	oaepSHA256Content           = `[{"contentType":"string","data":"RSA/ECB/OAEPWithSHA-256AndMGF1Padding"}]`
)

func TestSelectedEncryptionAlgorithmReadsEveryContractCode(t *testing.T) {
	for _, want := range contractEncryptionAlgorithms {
		t.Run(want.code, func(t *testing.T) {
			attrs := decodeRequestAttributes(t, `[`+otherCipherAttribute+`,`+
				encryptionSelectionJSON(`[{"contentType":"string","data":"`+want.code+`"}]`)+`]`)

			got, err := cryptography.SelectedEncryptionAlgorithm(attrs)
			if err != nil {
				t.Fatalf("SelectedEncryptionAlgorithm: %v", err)
			}
			if string(got) != want.code {
				t.Errorf("SelectedEncryptionAlgorithm = %q, want %q", got, want.code)
			}
		})
	}
}

func TestSelectedEncryptionAlgorithmIgnoresCase(t *testing.T) {
	cases := []struct{ name, attributes string }{
		{"of the code", `[` + encryptionSelectionJSON(`[{"contentType":"string","data":"rsa/ecb/oaepwithsha-256andmgf1padding"}]`) + `]`},
		{"of the UUID", `[{"uuid":"5E364467-FA95-4253-907B-0C73CDFB2BE7","name":"encryptionAlgorithm","contentType":"string","version":"v3",` +
			`"content":` + oaepSHA256Content + `}]`},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cryptography.SelectedEncryptionAlgorithm(decodeRequestAttributes(t, tc.attributes))
			if err != nil {
				t.Fatalf("SelectedEncryptionAlgorithm: %v", err)
			}
			if got != cryptography.EncryptionAlgorithmRSAOAEPSHA256 {
				t.Errorf("SelectedEncryptionAlgorithm = %q, want %q", got, cryptography.EncryptionAlgorithmRSAOAEPSHA256)
			}
		})
	}
}

func TestSelectedEncryptionAlgorithmRefusesAnInvalidSelection(t *testing.T) {
	selection := encryptionSelectionJSON(oaepSHA256Content)
	cases := []struct {
		name       string
		attributes string
		errorCode  string
		detail     string
	}{
		{"no attributes", `null`, "VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"no selection", `[` + otherCipherAttribute + `]`, "VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"no content", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"encryptionAlgorithm","contentType":"string","version":"v3"}]`,
			"VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"no content under a non-string content type", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"encryptionAlgorithm",` +
			`"contentType":"text","version":"v3","content":[]}]`,
			"VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"an empty value", `[` + encryptionSelectionJSON(`[{"contentType":"string","data":""}]`) + `]`,
			"VALIDATION_FAILED", "Unknown encryption algorithm code."},
		{"two values", `[` + encryptionSelectionJSON(`[{"contentType":"string","data":"RSA/ECB/PKCS1Padding"},`+
			`{"contentType":"string","data":"RSA/ECB/OAEPWithSHA-1AndMGF1Padding"}]`) + `]`,
			"VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"the reserved name under another UUID", `[{"uuid":"00000000-0000-4000-8000-000000000000","name":"encryptionAlgorithm",` +
			`"contentType":"string","version":"v3","content":` + oaepSHA256Content + `}]`,
			"VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"the reserved UUID under another name", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"renamedAlgorithm",` +
			`"contentType":"string","version":"v3","content":` + oaepSHA256Content + `}]`,
			"VALIDATION_FAILED", noEncryptionSelectionDetail},
		{"two attributes", `[` + selection + `,` + selection + `]`,
			"VALIDATION_FAILED", encryptionRepeatedDetail},
		{"another attribute reusing the reserved UUID", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"keyLabel",` +
			`"contentType":"string","version":"v3","content":[{"contentType":"string","data":"rsa-key"}]},` + selection + `]`,
			"VALIDATION_FAILED", encryptionRepeatedDetail},
		{"another attribute reusing the reserved name", `[{"uuid":"5f0c1c52-2b1e-4a57-9f4e-0c7f4f5b8d11","name":"encryptionAlgorithm",` +
			`"contentType":"string","version":"v3","content":[{"contentType":"string","data":"rsa-key"}]},` + selection + `]`,
			"VALIDATION_FAILED", encryptionRepeatedDetail},
		{"a v2 attribute", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"encryptionAlgorithm","contentType":"string","version":"v2"}]`,
			"VALIDATION_FAILED", encryptionNotV3Detail},
		{"an object value", `[` + encryptionSelectionJSON(`[{"contentType":"object","data":{"code":"RSA/ECB/PKCS1Padding"}}]`) + `]`,
			"VALIDATION_FAILED", encryptionNotStringDetail},
		{"a non-string attribute content type", `[{"uuid":"5e364467-fa95-4253-907b-0c73cdfb2be7","name":"encryptionAlgorithm",` +
			`"contentType":"text","version":"v3","content":` + oaepSHA256Content + `}]`,
			"VALIDATION_FAILED", encryptionNotStringDetail},
		{"a code outside the contract", `[` + encryptionSelectionJSON(`[{"contentType":"string","data":"RSA/ECB/NoPadding"}]`) + `]`,
			"VALIDATION_FAILED", "Unknown encryption algorithm code."},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cryptography.SelectedEncryptionAlgorithm(decodeRequestAttributes(t, tc.attributes))

			assertUnprocessable(t, string(got), err, tc.errorCode, tc.detail)
		})
	}
}

func TestSelectedEncryptionAlgorithmRefusesAMislabeledSelection(t *testing.T) {
	cases := []struct {
		name     string
		mislabel func(*mdl.RequestAttributeV3)
		detail   string
	}{
		{"a v3 attribute marked v2", func(s *mdl.RequestAttributeV3) { s.Version = mdl.ATTRIBUTEVERSION_V2 },
			encryptionNotV3Detail},
		{"a string item marked text", func(s *mdl.RequestAttributeV3) {
			s.Content[0].StringAttributeContentV3.ContentType = mdl.ATTRIBUTECONTENTTYPE_TEXT
		}, encryptionNotStringDetail},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			selection := cryptography.EncryptionAlgorithmSelection(cryptography.EncryptionAlgorithmRSAOAEPSHA256)
			tc.mislabel(selection.RequestAttributeV3)

			got, err := cryptography.SelectedEncryptionAlgorithm([]mdl.RequestAttribute{selection})

			assertUnprocessable(t, string(got), err, "VALIDATION_FAILED", tc.detail)
		})
	}
}
