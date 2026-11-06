package main

import (
	"context"
	"crypto/sha512"
	"encoding/base64"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

var sha384WithRSAPSS = []mdl.RequestAttribute{
	cryptography.SignatureAlgorithmSelection(cryptography.SignatureAlgorithmSHA384WithRSAPSS),
}

func rsaKeyMeta(t *testing.T, store *Store) []mdl.MetadataAttribute {
	t.Helper()
	created, _, err := store.CreateKey(context.Background(), keyPairRequest("creation-1", mdl.KEYALGORITHM_RSA))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return created.KeyPairDataResponseV2Dto.KeyPairMeta
}

func signRequestFor(keyMeta []mdl.MetadataAttribute, mode mdl.OperationExecutionMode, item []byte) *mdl.SignDataRequestV2Dto {
	return &mdl.SignDataRequestV2Dto{
		KeyMeta:             keyMeta,
		ExecutionMode:       mode,
		SignatureAttributes: sha384WithRSAPSS,
		Data:                []mdl.SignatureDataV2Dto{{Identifier: "1", Data: base64.StdEncoding.EncodeToString(item)}},
	}
}

func onlySignature(t *testing.T, resp *mdl.SignDataResponseV2Dto, err error) string {
	t.Helper()
	if err != nil {
		t.Fatalf("sign: %v", err)
	}
	if len(resp.Signatures) != 1 {
		t.Fatalf("signatures = %+v, want one", resp.Signatures)
	}
	return resp.Signatures[0].Data
}

func TestPrehashedSignatureVerifiesAgainstTheMessage(t *testing.T) {
	store := NewStore(defaultAsyncOperationDelay)
	ctx := context.Background()
	keyMeta := rsaKeyMeta(t, store)
	message := []byte("sign-me")
	digest := sha512.Sum384(message)

	resp, _, err := store.SignPrehashed(ctx, signRequestFor(keyMeta, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, digest[:]))
	signature := onlySignature(t, resp, err)

	verified, err := store.VerifyData(ctx, &mdl.VerifyDataRequestV2Dto{
		KeyMeta:             keyMeta,
		SignatureAttributes: sha384WithRSAPSS,
		Data:                []mdl.SignatureDataV2Dto{{Identifier: "1", Data: base64.StdEncoding.EncodeToString(message)}},
		Signatures:          []mdl.SignatureDataV2Dto{{Identifier: "1", Data: signature}},
	})
	if err != nil {
		t.Fatalf("VerifyData: %v", err)
	}
	if !verified.Verifications[0].Result {
		t.Error("a signature over the message's digest does not verify against the message")
	}
}

func TestEveryModeSignsTheMessagesDigest(t *testing.T) {
	store := NewStore(0)
	ctx := context.Background()
	keyMeta := rsaKeyMeta(t, store)
	message := []byte("sign-me")
	digest := sha512.Sum384(message)

	resp, _, err := store.SignPrehashed(ctx, signRequestFor(keyMeta, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, digest[:]))
	prehashed := onlySignature(t, resp, err)
	resp, _, err = store.SignData(ctx, signRequestFor(keyMeta, mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, message))
	synchronous := onlySignature(t, resp, err)
	accepted, _, err := store.SignData(ctx, signRequestFor(keyMeta, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS, message))
	if err != nil {
		t.Fatalf("asynchronous SignData: %v", err)
	}
	status, err := store.SignDataStatus(ctx, &mdl.OperationTrackingRequestV2Dto{OperationMeta: accepted.OperationMeta})
	if err != nil {
		t.Fatalf("SignDataStatus: %v", err)
	}

	if synchronous != prehashed {
		t.Errorf("data mode signed %q, prehashed mode %q: both must sign the message's digest", synchronous, prehashed)
	}
	if got := status.Items[0].Signature; got == nil {
		t.Error("asynchronous data mode completed without a signature")
	} else if *got != prehashed {
		t.Errorf("asynchronous data mode signed %q, want %q", *got, prehashed)
	}
}

func TestDataModeRefusesAnItemThatIsNotBase64(t *testing.T) {
	store := NewStore(defaultAsyncOperationDelay)
	req := signRequestFor(rsaKeyMeta(t, store), mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS, []byte("sign-me"))
	req.Data[0].Data = "not base64!"

	if _, _, err := store.SignData(context.Background(), req); err == nil {
		t.Fatal("SignData accepted an item that is not base64")
	}
}
