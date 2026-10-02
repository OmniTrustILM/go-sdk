package cryptography_test

import (
	"encoding/json"
	"net/http"
	"testing"

	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// exportableJSON renders a v3 keyExportable attribute holding content.
func exportableJSON(contentType, content string) string {
	return `{"uuid":"9d3f1a26-5d4e-4b6c-8f0a-6c1f2d7e4b83","name":"keyExportable","contentType":"` + contentType +
		`","version":"v3","content":` + content + `}`
}

func TestKeyExportableDefinitionMatchesTheContract(t *testing.T) {
	got, err := json.Marshal(cryptography.KeyExportableDefinition())
	if err != nil {
		t.Fatalf("marshal definition: %v", err)
	}
	assertJSONEqual(t, got, `{
		"uuid": "9d3f1a26-5d4e-4b6c-8f0a-6c1f2d7e4b83",
		"name": "keyExportable",
		"description": "Whether the key may later be exported. It cannot be changed after the key exists.",
		"version": 3,
		"type": "data",
		"contentType": "boolean",
		"schemaVersion": "v3",
		"properties": {
			"label": "Exportable",
			"visible": true,
			"required": true,
			"readOnly": false,
			"list": false,
			"multiSelect": false,
			"protectionLevel": "none",
			"extensibleList": false
		},
		"content": [{"data": false, "contentType": "boolean"}]
	}`)
}

func TestKeyExportableSelectionMatchesTheContract(t *testing.T) {
	for _, exportable := range []bool{true, false} {
		got, err := json.Marshal(cryptography.KeyExportableSelection(exportable))
		if err != nil {
			t.Fatalf("marshal selection: %v", err)
		}
		value := "false"
		if exportable {
			value = "true"
		}
		assertJSONEqual(t, got, exportableJSON("boolean", `[{"contentType":"boolean","data":`+value+`}]`))
	}
}

func TestSelectedKeyExportableReadsTheIntent(t *testing.T) {
	cases := []struct {
		name       string
		attributes string
		want       bool
	}{
		{"no attributes", `null`, false},
		{"only other attributes", `[` + otherSignAttribute + `]`, false},
		{"exportable", `[` + otherSignAttribute + `,` + exportableJSON("boolean", `[{"contentType":"boolean","data":true}]`) + `]`, true},
		{"not exportable", `[` + exportableJSON("boolean", `[{"contentType":"boolean","data":false}]`) + `]`, false},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cryptography.SelectedKeyExportable(decodeRequestAttributes(t, tc.attributes))
			if err != nil {
				t.Fatalf("SelectedKeyExportable: %v", err)
			}
			if got != tc.want {
				t.Errorf("SelectedKeyExportable = %v, want %v", got, tc.want)
			}
		})
	}
}

func TestSelectedKeyExportableRefusesAnUnusableIntent(t *testing.T) {
	cases := []struct {
		name       string
		attributes string
		detail     string
	}{
		{"two attributes", `[` + exportableJSON("boolean", `[{"contentType":"boolean","data":true}]`) + `,` +
			exportableJSON("boolean", `[{"contentType":"boolean","data":false}]`) + `]`, "keyExportable must be supplied at most once"},
		{"a v2 attribute", `[{"uuid":"9d3f1a26-5d4e-4b6c-8f0a-6c1f2d7e4b83","name":"keyExportable","contentType":"boolean","version":"v2"}]`,
			"keyExportable must be a v3 attribute"},
		{"no content", `[` + exportableJSON("boolean", `[]`) + `]`, "keyExportable must carry exactly one content item"},
		{"two values", `[` + exportableJSON("boolean", `[{"contentType":"boolean","data":true},{"contentType":"boolean","data":true}]`) + `]`,
			"keyExportable must carry exactly one content item"},
		{"a string attribute", `[` + exportableJSON("string", `[{"contentType":"boolean","data":true}]`) + `]`,
			"keyExportable must carry boolean content"},
		{"a string value", `[` + exportableJSON("boolean", `[{"contentType":"string","data":"true"}]`) + `]`,
			"keyExportable must carry boolean content"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			got, err := cryptography.SelectedKeyExportable(decodeRequestAttributes(t, tc.attributes))

			se, ok := err.(*shared.Error)
			if !ok || se == nil {
				t.Fatalf("SelectedKeyExportable = (%v, %v), want a *shared.Error", got, err)
			}
			if se.Status != http.StatusUnprocessableEntity || se.ErrorCode != "VALIDATION_FAILED" {
				t.Errorf("error = %d %s, want 422 VALIDATION_FAILED", se.Status, se.ErrorCode)
			}
			if se.Detail != tc.detail {
				t.Errorf("Detail = %q, want %q", se.Detail, tc.detail)
			}
		})
	}
}
