package cryptography_test

import (
	"encoding/json"
	"net/http"
	"reflect"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// contractSignatureAlgorithms is a copy of the Java SignatureAlgorithm enum, in its order.
var contractSignatureAlgorithms = []struct{ code, label string }{
	{"SHA256withRSA", "RSASSA-PKCS_v1.5 using SHA256"},
	{"SHA384withRSA", "RSASSA-PKCS_v1.5 using SHA384"},
	{"SHA512withRSA", "RSASSA-PKCS_v1.5 using SHA512"},
	{"SHA256withRSAandMGF1", "RSASSA-PSS using SHA256"},
	{"SHA384withRSAandMGF1", "RSASSA-PSS using SHA384"},
	{"SHA512withRSAandMGF1", "RSASSA-PSS using SHA512"},
	{"SHA256withECDSA", "ECDSA using SHA256"},
	{"SHA384withECDSA", "ECDSA using SHA384"},
	{"SHA512withECDSA", "ECDSA using SHA512"},
	{"Ed25519", "Pure EdDSA with Edwards25519"},
	{"Ed448", "Pure EdDSA with Edwards448"},
	{"FALCON-1024", "FALCON-1024"},
	{"ML-DSA-44", "ML-DSA-44 (Dilithium)"},
	{"ML-DSA-65", "ML-DSA-65 (Dilithium)"},
	{"ML-DSA-87", "ML-DSA-87 (Dilithium)"},
	{"SLH-DSA-SHA2-128S", "SLH-DSA-SHA2-128S (SPHINCS+)"},
	{"SLH-DSA-SHA2-128F", "SLH-DSA-SHA2-128F (SPHINCS+)"},
	{"SLH-DSA-SHA2-192S", "SLH-DSA-SHA2-192S (SPHINCS+)"},
	{"SLH-DSA-SHA2-192F", "SLH-DSA-SHA2-192F (SPHINCS+)"},
	{"SLH-DSA-SHA2-256S", "SLH-DSA-SHA2-256S (SPHINCS+)"},
	{"SLH-DSA-SHA2-256F", "SLH-DSA-SHA2-256F (SPHINCS+)"},
}

const (
	otherSignAttribute = `{"uuid":"5f0c1c52-2b1e-4a57-9f4e-0c7f4f5b8d11","name":"keyLabel","contentType":"string","version":"v3",` +
		`"content":[{"contentType":"string","data":"tsa-key"}]}`
	noSelectionDetail = "signatureAttributes must select one signatureAlgorithm value"
)

// selectionJSON renders a v3 signatureAlgorithm selection holding content.
func selectionJSON(content string) string {
	return `{"uuid":"9180267f-c82f-4b7b-8160-d2363d813869","name":"signatureAlgorithm","contentType":"string","version":"v3",` +
		`"content":` + content + `}`
}

// decodeSignatureAttributes decodes raw as the sign route does.
func decodeSignatureAttributes(t *testing.T, raw string) []mdl.RequestAttribute {
	t.Helper()
	var attrs []mdl.RequestAttribute
	if err := json.Unmarshal([]byte(raw), &attrs); err != nil {
		t.Fatalf("decode signatureAttributes: %v; body %s", err, raw)
	}
	return attrs
}

func assertJSONEqual(t *testing.T, got []byte, want string) {
	t.Helper()
	var gotValue, wantValue any
	if err := json.Unmarshal(got, &gotValue); err != nil {
		t.Fatalf("decode got: %v; body %s", err, got)
	}
	if err := json.Unmarshal([]byte(want), &wantValue); err != nil {
		t.Fatalf("decode want: %v; body %s", err, want)
	}
	if !reflect.DeepEqual(gotValue, wantValue) {
		t.Errorf("JSON mismatch\n got: %s\nwant: %s", got, want)
	}
}

func TestSignatureAlgorithmsListTheContractCodesAndLabels(t *testing.T) {
	got := cryptography.SignatureAlgorithms()
	if len(got) != len(contractSignatureAlgorithms) {
		t.Fatalf("SignatureAlgorithms() has %d codes, want %d: %v", len(got), len(contractSignatureAlgorithms), got)
	}
	for i, want := range contractSignatureAlgorithms {
		if string(got[i]) != want.code {
			t.Errorf("SignatureAlgorithms()[%d] = %q, want %q", i, got[i], want.code)
		}
		if label := got[i].Label(); label != want.label {
			t.Errorf("%s.Label() = %q, want %q", want.code, label, want.label)
		}
		if !got[i].IsValid() {
			t.Errorf("%s.IsValid() = false, want true", want.code)
		}
	}
}

func TestSignatureAlgorithmOutsideTheContractIsInvalid(t *testing.T) {
	cases := []struct{ name, code string }{
		{"empty", ""},
		{"a code outside the contract", "SHA1withRSA"},
		{"a contract code in lower case", "sha256withrsa"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			algorithm := cryptography.SignatureAlgorithm(tc.code)
			if algorithm.IsValid() {
				t.Errorf("IsValid() = true, want false")
			}
			if label := algorithm.Label(); label != "" {
				t.Errorf("Label() = %q, want empty", label)
			}
		})
	}
}

func TestSignatureAlgorithmDefinitionMatchesTheContract(t *testing.T) {
	definition := cryptography.SignatureAlgorithmDefinition(
		cryptography.SignatureAlgorithmSHA256WithECDSA,
		cryptography.SignatureAlgorithmMLDSA65,
	)

	got, err := json.Marshal(definition)
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	assertJSONEqual(t, got, `{
		"uuid": "9180267f-c82f-4b7b-8160-d2363d813869",
		"name": "signatureAlgorithm",
		"description": "Signature algorithm the signature is produced with",
		"version": 3,
		"type": "data",
		"contentType": "string",
		"schemaVersion": "v3",
		"properties": {
			"label": "Signature Algorithm",
			"visible": true,
			"required": true,
			"readOnly": false,
			"list": true,
			"multiSelect": false,
			"protectionLevel": "none",
			"extensibleList": false
		},
		"content": [
			{"reference": "ECDSA using SHA256", "data": "SHA256withECDSA", "contentType": "string"},
			{"reference": "ML-DSA-65 (Dilithium)", "data": "ML-DSA-65", "contentType": "string"}
		]
	}`)
}

func TestSignatureAlgorithmDefinitionSpellsACaseVariantCanonically(t *testing.T) {
	definition := cryptography.SignatureAlgorithmDefinition(cryptography.SignatureAlgorithm("sha256withecdsa"))

	got, err := json.Marshal(definition.BaseAttributeDtoV3.DataAttributeV3.Content)
	if err != nil {
		t.Fatalf("marshal definition content: %v", err)
	}
	assertJSONEqual(t, got, `[{"reference":"ECDSA using SHA256","data":"SHA256withECDSA","contentType":"string"}]`)
}

func TestSignatureAlgorithmSelectionMatchesTheContract(t *testing.T) {
	selection := cryptography.SignatureAlgorithmSelection(cryptography.SignatureAlgorithmSHA384WithRSAPSS)

	got, err := json.Marshal(selection)
	if err != nil {
		t.Fatalf("marshal selection: %v", err)
	}
	assertJSONEqual(t, got, selectionJSON(
		`[{"reference":"RSASSA-PSS using SHA384","data":"SHA384withRSAandMGF1","contentType":"string"}]`,
	))
}

func TestSelectedSignatureAlgorithmReadsEveryContractCode(t *testing.T) {
	for _, want := range contractSignatureAlgorithms {
		t.Run(want.code, func(t *testing.T) {
			attrs := decodeSignatureAttributes(t, `[`+otherSignAttribute+`,`+
				selectionJSON(`[{"contentType":"string","data":"`+want.code+`"}]`)+`]`)

			got, err := cryptography.SelectedSignatureAlgorithm(attrs)
			if err != nil {
				t.Fatalf("SelectedSignatureAlgorithm: %v", err)
			}
			if string(got) != want.code {
				t.Errorf("SelectedSignatureAlgorithm = %q, want %q", got, want.code)
			}
		})
	}
}

func TestSelectedSignatureAlgorithmIgnoresCase(t *testing.T) {
	attrs := decodeSignatureAttributes(t, `[`+selectionJSON(`[{"contentType":"string","data":"sha256withecdsa"}]`)+`]`)

	got, err := cryptography.SelectedSignatureAlgorithm(attrs)
	if err != nil {
		t.Fatalf("SelectedSignatureAlgorithm: %v", err)
	}
	if got != cryptography.SignatureAlgorithmSHA256WithECDSA {
		t.Errorf("SelectedSignatureAlgorithm = %q, want %q", got, cryptography.SignatureAlgorithmSHA256WithECDSA)
	}
}

func TestSelectedSignatureAlgorithmRefusesAnInvalidSelection(t *testing.T) {
	cases := []struct {
		name       string
		attributes string
		errorCode  string
		detail     string
	}{
		{"no attributes", `null`, "VALIDATION_FAILED", noSelectionDetail},
		{"no selection", `[` + otherSignAttribute + `]`, "VALIDATION_FAILED", noSelectionDetail},
		{"no content", `[{"uuid":"9180267f-c82f-4b7b-8160-d2363d813869","name":"signatureAlgorithm","contentType":"string","version":"v3"}]`,
			"VALIDATION_FAILED", noSelectionDetail},
		{"an empty value", `[` + selectionJSON(`[{"contentType":"string","data":""}]`) + `]`,
			"VALIDATION_FAILED", noSelectionDetail},
		{"two values", `[` + selectionJSON(`[{"contentType":"string","data":"SHA256withRSA"},{"contentType":"string","data":"SHA384withRSA"}]`) + `]`,
			"VALIDATION_FAILED", noSelectionDetail},
		{"two attributes", `[` + selectionJSON(`[{"contentType":"string","data":"SHA256withRSA"}]`) + `,` +
			selectionJSON(`[{"contentType":"string","data":"SHA384withRSA"}]`) + `]`,
			"VALIDATION_FAILED", "signatureAlgorithm must be supplied once"},
		{"a v2 attribute", `[{"uuid":"9180267f-c82f-4b7b-8160-d2363d813869","name":"signatureAlgorithm","contentType":"string","version":"v2"}]`,
			"VALIDATION_FAILED", "signatureAlgorithm must be a v3 attribute"},
		{"an object value", `[` + selectionJSON(`[{"contentType":"object","data":{"code":"SHA256withRSA"}}]`) + `]`,
			"VALIDATION_FAILED", "signatureAlgorithm must carry a string value"},
		{"a code outside the contract", `[` + selectionJSON(`[{"contentType":"string","data":"SHA1withRSA"}]`) + `]`,
			"PARAMETER_UNSUPPORTED", "signature algorithm is not supported by the key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			attrs := decodeSignatureAttributes(t, tc.attributes)

			got, err := cryptography.SelectedSignatureAlgorithm(attrs)

			se, ok := err.(*shared.Error)
			if !ok || se == nil {
				t.Fatalf("SelectedSignatureAlgorithm = (%q, %v), want a *shared.Error", got, err)
			}
			if se.Status != http.StatusUnprocessableEntity {
				t.Errorf("Status = %d, want 422", se.Status)
			}
			if se.ErrorCode != tc.errorCode {
				t.Errorf("ErrorCode = %q, want %q", se.ErrorCode, tc.errorCode)
			}
			if se.Detail != tc.detail {
				t.Errorf("Detail = %q, want %q", se.Detail, tc.detail)
			}
		})
	}
}
