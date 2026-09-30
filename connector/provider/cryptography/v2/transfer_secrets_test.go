package cryptography_test

import (
	"bytes"
	"encoding/base64"
	"log/slog"
	"net/http"
	"strings"
	"testing"

	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// transferPhrase is the passphrase every transfer request below carries.
const transferPhrase = "a phrase no log may show"

// newLoggingServer mounts a Handler with opt on a connector that writes every
// log record, whatever its level, to logs.
func newLoggingServer(t *testing.T, logs *bytes.Buffer, opt cryptography.Option) http.Handler {
	t.Helper()
	h, err := cryptography.NewHandler(&stubProvider{}, opt)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "a", Name: "a", Version: "0.0.1"}),
		shared.WithLogger(slog.New(shared.NewLogHandler(logs, &shared.LogHandlerOptions{Level: slog.LevelDebug}))),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	return c.Handler()
}

// A completed export's body is not checked: it carries the material, as it
// must.
func TestKeyTransfersKeepThePassphraseAndMaterialOutOfProblemsAndLogs(t *testing.T) {
	phrase := `"` + transferPhrase + `"`
	outside := base64.StdEncoding.EncodeToString([]byte("not an envelope"))
	outsideExport := publicKeyExport()
	outsideExport.Material.EncryptedPrivateKeyInfo = outside
	cases := []struct {
		name     string
		opt      cryptography.Option
		path     string
		body     string
		material string
		status   int
	}{
		{"a completed import", cryptography.WithKeyImport(&stubKeyImport{importResp: secretKeyCreationResponse()}), importKeyPath,
			importKeyBody(map[string]string{"passphrase": phrase}), inProfileEnvelope, http.StatusOK},
		{"an import its guards refuse", cryptography.WithKeyImport(&stubKeyImport{}), importKeyPath,
			importKeyBody(map[string]string{"passphrase": phrase, "keyImportId": `" "`}), inProfileEnvelope, http.StatusUnprocessableEntity},
		{"an import of material outside the profile", cryptography.WithKeyImport(&stubKeyImport{}), importKeyPath,
			importKeyBody(map[string]string{"passphrase": phrase, "material": `{"encryptedPrivateKeyInfo":"` + outside + `"}`}), outside,
			http.StatusUnprocessableEntity},
		{"an import that does not decode", cryptography.WithKeyImport(&stubKeyImport{}), importKeyPath,
			importKeyBody(map[string]string{"passphrase": phrase, "exportable": `"yes"`}), inProfileEnvelope, http.StatusUnprocessableEntity},
		{"an import the provider refuses", cryptography.WithKeyImport(&stubKeyImport{importErr: cryptography.ErrKeyDecryptionFailed}),
			importKeyPath, importKeyBody(map[string]string{"passphrase": phrase}), inProfileEnvelope, http.StatusUnprocessableEntity},
		{"an import answered outside the contract", cryptography.WithKeyImport(&stubKeyImport{}), importKeyPath,
			importKeyBody(map[string]string{"passphrase": phrase}), inProfileEnvelope, http.StatusInternalServerError},
		{"a completed export", cryptography.WithKeyExport(&stubKeyExport{export: publicKeyExport()}), exportKeyPath,
			exportKeyBody(map[string]string{"passphrase": phrase}), inProfileEnvelope, http.StatusOK},
		{"an export the provider refuses", cryptography.WithKeyExport(&stubKeyExport{exportErr: cryptography.ErrKeyNotExportable}),
			exportKeyPath, exportKeyBody(map[string]string{"passphrase": phrase}), "", http.StatusUnprocessableEntity},
		{"an export answered with material outside the profile", cryptography.WithKeyExport(&stubKeyExport{export: outsideExport}),
			exportKeyPath, exportKeyBody(map[string]string{"passphrase": phrase}), outside, http.StatusInternalServerError},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var logs bytes.Buffer
			rec := post(t, newLoggingServer(t, &logs, tc.opt), tc.path, tc.body)

			if rec.Code != tc.status {
				t.Fatalf("status = %d, want %d; body %s", rec.Code, tc.status, rec.Body.String())
			}
			if !strings.Contains(logs.String(), "request completed") {
				t.Fatalf("the connector logged no request; logs %s", logs.String())
			}
			surfaces := map[string]string{"the log": logs.String()}
			if rec.Code >= http.StatusBadRequest {
				surfaces["the problem detail"] = rec.Body.String()
			}
			secrets := map[string]string{"the passphrase": transferPhrase}
			if tc.material != "" {
				secrets["the material"] = tc.material
			}
			for surface, text := range surfaces {
				for secret, value := range secrets {
					if strings.Contains(text, value) {
						t.Errorf("%s shows %s: %s", surface, secret, text)
					}
				}
			}
		})
	}
}
