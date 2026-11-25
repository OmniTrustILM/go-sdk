package main

import (
	"context"
	"errors"
	"strconv"
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

const (
	rsaEncryptionIdentifier = "MA0GCSqGSIb3DQEBAQUA"
	p256Identifier          = "MBMGByqGSM49AgEGCCqGSM49AwEH"
)

// A pair's private half carries the SPKI's AlgorithmIdentifier and a length
// only for RSA. The RSA identifier leaves the modulus size out.
func TestCreateKeyDescribesThePrivateKeyParameters(t *testing.T) {
	cases := map[mdl.KeyAlgorithm]struct {
		identifier string
		length     string
	}{
		mdl.KEYALGORITHM_RSA:   {rsaEncryptionIdentifier, "2048"},
		mdl.KEYALGORITHM_ECDSA: {p256Identifier, "absent"},
	}
	for algorithm, want := range cases {
		for response, privateDescriptor := range privateDescriptorReaders {
			t.Run(string(algorithm)+"/"+response, func(t *testing.T) {
				private := privateDescriptor(t, NewStore(0), algorithm)
				if got := private.GetAlgorithmIdentifier(); got != want.identifier {
					t.Errorf("private algorithmIdentifier = %q, want %q", got, want.identifier)
				}
				if got := statedLength(private.Length); got != want.length {
					t.Errorf("private length = %s, want %s", got, want.length)
				}
			})
		}
	}
}

var privateDescriptorReaders = map[string]func(*testing.T, *Store, mdl.KeyAlgorithm) mdl.PrivateKeyDataV2Dto{
	"CreateKey": func(t *testing.T, s *Store, algorithm mdl.KeyAlgorithm) mdl.PrivateKeyDataV2Dto {
		return createdPair(t, s, algorithm).PrivateKeyData.KeyData
	},
	"CreateKeyStatus": func(t *testing.T, s *Store, algorithm mdl.KeyAlgorithm) mdl.PrivateKeyDataV2Dto {
		req := keyPairRequest("creation-1", algorithm)
		req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
		accepted, _, err := s.CreateKey(context.Background(), req)
		if err != nil {
			t.Fatalf("CreateKey: %v", err)
		}
		status, err := s.CreateKeyStatus(context.Background(), &mdl.OperationTrackingRequestV2Dto{
			OperationMeta: accepted.KeyPairDataResponseV2Dto.OperationMeta,
		})
		if err != nil {
			t.Fatalf("CreateKeyStatus: %v", err)
		}
		result := status.KeyPairOperationStatusResponseV2Dto.Result
		if result == nil {
			t.Fatalf("status %s carries no result", status.KeyPairOperationStatusResponseV2Dto.Status)
		}
		return result.PrivateKeyData.KeyData
	},
	"ListKeys": func(t *testing.T, s *Store, algorithm mdl.KeyAlgorithm) mdl.PrivateKeyDataV2Dto {
		createdPair(t, s, algorithm)
		page, err := s.ListKeys(context.Background(), pairListing(0, 10))
		if err != nil {
			t.Fatalf("ListKeys: %v", err)
		}
		if len(page.Items) != 1 {
			t.Fatalf("ListKeys listed %d pairs, want 1", len(page.Items))
		}
		return page.Items[0].Key.ListedKeyPairV2Dto.PrivateKeyData.KeyData
	},
	"ResolveKeys": func(t *testing.T, s *Store, algorithm mdl.KeyAlgorithm) mdl.PrivateKeyDataV2Dto {
		created := createdPair(t, s, algorithm)
		out, err := s.ResolveKeys(context.Background(), resolution(mdl.KeyHandleV2Dto{Identifier: "a", KeyMeta: created.KeyPairMeta}))
		if err != nil {
			t.Fatalf("ResolveKeys: %v", err)
		}
		if len(out.Results) != 1 || out.Results[0].Key == nil {
			t.Fatalf("results = %+v, want one found pair", out.Results)
		}
		return out.Results[0].Key.ListedKeyPairV2Dto.PrivateKeyData.KeyData
	},
}

func createdPair(t *testing.T, s *Store, algorithm mdl.KeyAlgorithm) *mdl.KeyPairDataResponseV2Dto {
	t.Helper()
	out, _, err := s.CreateKey(context.Background(), keyPairRequest("creation-1", algorithm))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return out.KeyPairDataResponseV2Dto
}

func statedLength(length *int32) string {
	if length == nil {
		return "absent"
	}
	return strconv.Itoa(int(*length))
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
