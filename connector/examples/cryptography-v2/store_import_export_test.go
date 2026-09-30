package main

import (
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"encoding/base64"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// importExportable imports a fresh P-256 key as exportable and returns its
// private key handle with the key itself.
func importExportable(t *testing.T, store *Store) ([]mdl.MetadataAttribute, *ecdsa.PrivateKey) {
	t.Helper()
	key, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		t.Fatalf("generate key: %v", err)
	}
	pkcs8, err := x509.MarshalPKCS8PrivateKey(key)
	if err != nil {
		t.Fatalf("marshal key: %v", err)
	}
	material, err := cryptography.ProtectKeyMaterial(pkcs8, "phrase")
	if err != nil {
		t.Fatalf("protect key: %v", err)
	}
	imported, _, err := store.ImportKey(context.Background(), &mdl.ImportKeyRequestV2Dto{
		KeyImportId:    "import-1",
		KeyReference:   "0f8c3a4e-8d8e-4c8a-9d6b-2a6b3c1d4e5f",
		ExecutionMode:  mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		Material:       material,
		Passphrase:     "phrase",
		Exportable:     true,
	})
	if err != nil {
		t.Fatalf("ImportKey: %v", err)
	}
	return imported.KeyPairDataResponseV2Dto.PrivateKeyData.KeyMeta, key
}

// A destroyed key keeps its record for replays, but not the private key an
// exportable import brought in.
func TestDestroyingAnImportedKeyDropsItsPrivateKey(t *testing.T) {
	for _, mode := range []mdl.OperationExecutionMode{mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS} {
		t.Run(string(mode), func(t *testing.T) {
			store := NewStore(defaultAsyncOperationDelay)
			keyMeta, _ := importExportable(t, store)

			if _, _, err := store.DestroyKey(context.Background(), &mdl.DestroyKeyRequestV2Dto{KeyMeta: keyMeta, ExecutionMode: mode}); err != nil {
				t.Fatalf("DestroyKey: %v", err)
			}

			keyID, _ := metaID(keyMeta)
			if store.keys[keyID].privateKeyInfo != nil {
				t.Error("a destroyed key still holds its private key")
			}
		})
	}
}

// An export describes the key it returns from that key itself, not from the
// record, so Core's comparison with its own record can catch a wrong key.
func TestExportDescribesTheKeyItReturns(t *testing.T) {
	store := NewStore(defaultAsyncOperationDelay)
	keyMeta, key := importExportable(t, store)
	keyID, _ := metaID(keyMeta)
	store.keys[keyID].spki = spkiFor("another key")

	out, err := store.ExportKey(context.Background(), &mdl.ExportKeyRequestV2Dto{
		KeyMeta:        keyMeta,
		KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR,
		Passphrase:     "export phrase",
	})
	if err != nil {
		t.Fatalf("ExportKey: %v", err)
	}

	spki, err := x509.MarshalPKIXPublicKey(&key.PublicKey)
	if err != nil {
		t.Fatalf("marshal SPKI: %v", err)
	}
	if out.KeyData.PublicKeyDataV2Dto == nil || out.KeyData.PublicKeyDataV2Dto.PublicKeySpki != base64.StdEncoding.EncodeToString(spki) {
		t.Errorf("keyData = %+v, want the exported key's public key", out.KeyData)
	}
}
