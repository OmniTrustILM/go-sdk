package main

import (
	"context"
	"strconv"
	"sync"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// TestStoreConcurrentVerifyEncryptDecryptVsDestroy runs VerifyData,
// EncryptData and DecryptData against a key another goroutine destroys
// concurrently, guarding the requirement that rec.destroyed is read under
// s.mu. Each call must return exactly one of a response or an error, and the
// race detector must stay silent.
func TestStoreConcurrentVerifyEncryptDecryptVsDestroy(t *testing.T) {
	const iterations = 50
	const readersPerIteration = 8

	for iter := 0; iter < iterations; iter++ {
		store := NewStore(defaultAsyncOperationDelay)
		ctx := context.Background()

		createResp, _, err := store.CreateKey(ctx, &mdl.CreateKeyRequestV2Dto{
			KeyCreationId:  "creation-" + strconv.Itoa(iter),
			KeyRequestType: mdl.KEYREQUESTTYPE_SECRET,
			ExecutionMode:  mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
		})
		if err != nil {
			t.Fatalf("iteration %d: CreateKey: %v", iter, err)
		}
		keyMeta := createResp.SecretKeyDataResponseV2Dto.KeyMeta

		plaintext := "hello world"
		signature := fakeSignForTest(keyMeta, plaintext)

		var wg sync.WaitGroup
		wg.Add(readersPerIteration + 1)

		// Release every goroutine at once so the accesses overlap.
		start := make(chan struct{})

		go func() {
			defer wg.Done()
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("DestroyKey panicked: %v", r)
				}
			}()
			<-start
			// The sole destroy in flight, so it must succeed and perform the
			// write this test races against.
			if _, _, err := store.DestroyKey(ctx, &mdl.DestroyKeyRequestV2Dto{
				KeyMeta:       keyMeta,
				ExecutionMode: mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
			}); err != nil {
				t.Errorf("iteration %d: DestroyKey: %v", iter, err)
			}
		}()

		for i := 0; i < readersPerIteration; i++ {
			op := i % 3
			go func(op int) {
				defer wg.Done()
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("operation panicked: %v", r)
					}
				}()
				<-start

				switch op {
				case 0:
					resp, err := store.VerifyData(ctx, &mdl.VerifyDataRequestV2Dto{
						KeyMeta:    keyMeta,
						Data:       []mdl.SignatureDataV2Dto{{Identifier: "1", Data: plaintext}},
						Signatures: []mdl.SignatureDataV2Dto{{Identifier: "1", Data: signature}},
					})
					if (resp == nil) == (err == nil) {
						t.Errorf("VerifyData: expected exactly one of (resp, err) to be nil, got resp=%v err=%v", resp, err)
					}
				case 1:
					resp, err := store.EncryptData(ctx, &mdl.CipherDataRequestV2Dto{
						KeyMeta:    keyMeta,
						CipherData: []mdl.CipherDataV2Dto{{Identifier: "1", Data: plaintext}},
					})
					if (resp == nil) == (err == nil) {
						t.Errorf("EncryptData: expected exactly one of (resp, err) to be nil, got resp=%v err=%v", resp, err)
					}
				case 2:
					resp, err := store.DecryptData(ctx, &mdl.CipherDataRequestV2Dto{
						KeyMeta:    keyMeta,
						CipherData: []mdl.CipherDataV2Dto{{Identifier: "1", Data: fakeEncrypt(mustKeyID(keyMeta), plaintext)}},
					})
					if (resp == nil) == (err == nil) {
						t.Errorf("DecryptData: expected exactly one of (resp, err) to be nil, got resp=%v err=%v", resp, err)
					}
				}
			}(op)
		}

		close(start)
		wg.Wait()
	}
}

// fakeSignForTest computes the signature a live key would produce for data.
func fakeSignForTest(keyMeta []mdl.MetadataAttribute, data string) string {
	return fakeSign(mustKeyID(keyMeta), data)
}

// mustKeyID extracts the handle a Store attached to keyMeta.
func mustKeyID(keyMeta []mdl.MetadataAttribute) string {
	id, ok := metaID(keyMeta)
	if !ok {
		panic("mustKeyID: no handle in keyMeta")
	}
	return id
}
