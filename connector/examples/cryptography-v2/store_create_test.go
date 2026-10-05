package main

import (
	"context"
	"errors"
	"sync"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

func keyAlgorithmAttribute(algorithm mdl.KeyAlgorithm) mdl.RequestAttribute {
	selection := mdl.NewRequestAttributeV3(keyAlgorithmAttributeUUID, keyAlgorithmAttributeName,
		mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V3)
	selection.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(
		mdl.NewStringAttributeContentV3(string(algorithm), mdl.ATTRIBUTECONTENTTYPE_STRING))}
	return mdl.RequestAttributeV3AsRequestAttribute(selection)
}

func keyPairRequest(creationID string, algorithm mdl.KeyAlgorithm) *mdl.CreateKeyRequestV2Dto {
	return &mdl.CreateKeyRequestV2Dto{
		KeyCreationId:       creationID,
		KeyRequestType:      mdl.KEYREQUESTTYPE_KEY_PAIR,
		ExecutionMode:       mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
		CreateKeyAttributes: []mdl.RequestAttribute{keyAlgorithmAttribute(algorithm)},
	}
}

func TestCreateKeyReplaysAnRSAPair(t *testing.T) {
	store := NewStore(defaultAsyncOperationDelay)
	ctx := context.Background()
	first, _, err := store.CreateKey(ctx, keyPairRequest("creation-1", mdl.KEYALGORITHM_RSA))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	replay, _, err := store.CreateKey(ctx, keyPairRequest("creation-1", mdl.KEYALGORITHM_RSA))
	if err != nil {
		t.Fatalf("replayed CreateKey: %v", err)
	}
	if got, want := mustKeyID(replay.KeyPairDataResponseV2Dto.KeyPairMeta), mustKeyID(first.KeyPairDataResponseV2Dto.KeyPairMeta); got != want {
		t.Errorf("the replay answered key %s, want %s", got, want)
	}
	if replay.KeyPairDataResponseV2Dto.PublicKeyData.KeyData.PublicKeySpki != first.KeyPairDataResponseV2Dto.PublicKeyData.KeyData.PublicKeySpki {
		t.Error("the replay answered another public key")
	}

	_, _, err = store.CreateKey(ctx, keyPairRequest("creation-1", mdl.KEYALGORITHM_ECDSA))
	var refusal *shared.Error
	if !errors.As(err, &refusal) || refusal.ErrorCode != "RESOURCE_ALREADY_EXISTS" {
		t.Errorf("reusing the keyCreationId for an ECDSA pair returned %v, want RESOURCE_ALREADY_EXISTS", err)
	}
	if len(store.keys) != 1 {
		t.Errorf("the store holds %d keys, want 1", len(store.keys))
	}
}

func TestConcurrentCreateKeysWithOneKeyCreationIdCreateOneKey(t *testing.T) {
	const requests = 4
	store := NewStore(defaultAsyncOperationDelay)

	keyIDs := make([]string, requests)
	var wg sync.WaitGroup
	wg.Add(requests)
	start := make(chan struct{})
	for i := range requests {
		go func() {
			defer wg.Done()
			<-start
			resp, _, err := store.CreateKey(context.Background(), keyPairRequest("creation-1", mdl.KEYALGORITHM_RSA))
			if err != nil {
				t.Errorf("CreateKey: %v", err)
				return
			}
			keyIDs[i] = mustKeyID(resp.KeyPairDataResponseV2Dto.KeyPairMeta)
		}()
	}
	close(start)
	wg.Wait()

	for _, keyID := range keyIDs[1:] {
		if keyID != keyIDs[0] {
			t.Errorf("the requests answered keys %v, want one key", keyIDs)
			break
		}
	}
	if len(store.keys) != 1 {
		t.Errorf("the store holds %d keys, want 1", len(store.keys))
	}
}
