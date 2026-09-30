package cryptography_test

import (
	"net/http"
	"net/http/httptest"
	"testing"

	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// The key import and export sentinels render the contract's codes, the
// cryptography ones under the interface's own problem types.
func TestKeyTransferSentinelsRenderTheContractCodes(t *testing.T) {
	cases := []struct {
		err      *shared.Error
		status   int
		code     string
		typeName string
	}{
		{cryptography.ErrKeyImportConflict, http.StatusConflict, "RESOURCE_ALREADY_EXISTS", "https://docs.otilm.com/problems/common/RESOURCE_ALREADY_EXISTS"},
		{cryptography.ErrKeyTypeNotImportable, http.StatusUnprocessableEntity, "KEY_TYPE_NOT_IMPORTABLE", "https://docs.otilm.com/problems/connector/cryptography/KEY_TYPE_NOT_IMPORTABLE"},
		{cryptography.ErrKeyMaterialMismatch, http.StatusUnprocessableEntity, "KEY_MATERIAL_MISMATCH", "https://docs.otilm.com/problems/connector/cryptography/KEY_MATERIAL_MISMATCH"},
		{cryptography.ErrKeyDecryptionFailed, http.StatusUnprocessableEntity, "KEY_DECRYPTION_FAILED", "https://docs.otilm.com/problems/connector/cryptography/KEY_DECRYPTION_FAILED"},
		{cryptography.ErrExportableNotSupported, http.StatusUnprocessableEntity, "EXPORTABLE_NOT_SUPPORTED", "https://docs.otilm.com/problems/connector/cryptography/EXPORTABLE_NOT_SUPPORTED"},
		{cryptography.ErrKeyNotExportable, http.StatusUnprocessableEntity, "KEY_NOT_EXPORTABLE", "https://docs.otilm.com/problems/connector/cryptography/KEY_NOT_EXPORTABLE"},
		{cryptography.ErrKeyTypeNotExportable, http.StatusUnprocessableEntity, "KEY_TYPE_NOT_EXPORTABLE", "https://docs.otilm.com/problems/connector/cryptography/KEY_TYPE_NOT_EXPORTABLE"},
	}
	for _, tc := range cases {
		t.Run(tc.code, func(t *testing.T) {
			rec := httptest.NewRecorder()
			shared.WriteProblem(rec, httptest.NewRequest(http.MethodPost, "/", nil), tc.err)

			problem := assertProblem(t, rec, tc.status, tc.code)
			if problem.Type != tc.typeName {
				t.Errorf("type = %q, want %q", problem.Type, tc.typeName)
			}
		})
	}
}
