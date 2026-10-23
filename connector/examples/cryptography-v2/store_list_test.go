package main

import (
	"context"
	"errors"
	"math"
	"reflect"
	"slices"
	"testing"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

func createKeyPair(t *testing.T, s *Store, creationID string) string {
	t.Helper()
	resp, _, err := s.CreateKey(context.Background(), keyPairRequest(creationID, mdl.KEYALGORITHM_ECDSA))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return mustKeyID(resp.KeyPairDataResponseV2Dto.KeyPairMeta)
}

func listedPairIDs(page *mdl.ListKeysResponseV2Dto) []string {
	ids := make([]string, 0, len(page.Items))
	for _, key := range page.Items {
		id, _ := pairIDOf(key.ListedKeyPairV2Dto.KeyPairMeta)
		ids = append(ids, id)
	}
	return ids
}

func pairListing(offset, limit int32) *mdl.ListKeysRequestV2Dto {
	return &mdl.ListKeysRequestV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Offset: offset, Limit: limit}
}

func TestListKeysPagesTheStoredKeyPairs(t *testing.T) {
	s := NewStore(0)
	want := []string{createKeyPair(t, s, "create-1"), createKeyPair(t, s, "create-2"), createKeyPair(t, s, "create-3")}
	slices.Sort(want)

	first, err := s.ListKeys(context.Background(), pairListing(0, 2))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	second, err := s.ListKeys(context.Background(), pairListing(2, 2))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	if first.TotalItems != 3 || len(first.Items) != 2 || len(second.Items) != 1 {
		t.Fatalf("pages hold %d and %d of %d, want 2 and 1 of 3", len(first.Items), len(second.Items), first.TotalItems)
	}
	if got := append(listedPairIDs(first), listedPairIDs(second)...); !slices.Equal(got, want) {
		t.Errorf("pages list %v, want %v", got, want)
	}
	if first.Items[0].ListedKeyPairV2Dto.PublicKeyData == nil {
		t.Errorf("listed key pair PublicKeyData = nil, want the public key")
	}
}

func TestListKeysAnswersAnEmptyPageForTheLargestOffset(t *testing.T) {
	s := NewStore(0)
	createKeyPair(t, s, "create-1")

	page, err := s.ListKeys(context.Background(), pairListing(math.MaxInt32, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	if page.TotalItems != 1 || len(page.Items) != 0 {
		t.Errorf("page holds %d of %d, want 0 of 1", len(page.Items), page.TotalItems)
	}
}

func TestListKeysGivesEachPairDistinctHandleData(t *testing.T) {
	s := NewStore(0)
	createKeyPair(t, s, "create-1")
	createKeyPair(t, s, "create-2")

	page, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	first, _ := pairIDOf(page.Items[0].ListedKeyPairV2Dto.KeyPairMeta)
	second, _ := pairIDOf(page.Items[1].ListedKeyPairV2Dto.KeyPairMeta)
	if first == "" || first == second {
		t.Errorf("listed pairs carry data %q and %q, want two distinct pair IDs", first, second)
	}
}

func TestListKeysLeavesOutPendingAndCancelledCreations(t *testing.T) {
	s := NewStore(time.Hour)
	req := keyPairRequest("create-async", mdl.KEYALGORITHM_ECDSA)
	req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
	accepted, _, err := s.CreateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	pending, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if err := s.CancelCreateKey(context.Background(), &mdl.OperationTrackingRequestV2Dto{
		OperationMeta: accepted.KeyPairDataResponseV2Dto.OperationMeta,
	}); err != nil {
		t.Fatalf("CancelCreateKey: %v", err)
	}
	cancelled, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	if pending.TotalItems != 0 || cancelled.TotalItems != 0 {
		t.Errorf("listed %d pending and %d cancelled key pairs, want none", pending.TotalItems, cancelled.TotalItems)
	}
}

func TestListKeysLeavesOutPendingAndCancelledImports(t *testing.T) {
	s := NewStore(time.Hour)
	accepted, _ := importP256Key(t, s, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS)

	pending, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}
	if err := s.CancelImportKey(context.Background(), &mdl.OperationTrackingRequestV2Dto{
		OperationMeta: accepted.KeyPairDataResponseV2Dto.OperationMeta,
	}); err != nil {
		t.Fatalf("CancelImportKey: %v", err)
	}
	cancelled, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	if pending.TotalItems != 0 || cancelled.TotalItems != 0 {
		t.Errorf("listed %d pending and %d cancelled imports, want none", pending.TotalItems, cancelled.TotalItems)
	}
}

func TestListKeysListsACompletedAsynchronousCreation(t *testing.T) {
	s := NewStore(0)
	req := keyPairRequest("create-async", mdl.KEYALGORITHM_ECDSA)
	req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
	if _, _, err := s.CreateKey(context.Background(), req); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	page, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	if page.TotalItems != 1 || len(page.Items) != 1 {
		t.Errorf("page holds %d of %d, want the completed key pair", len(page.Items), page.TotalItems)
	}
}

func TestListKeysRefusesSecretKeys(t *testing.T) {
	s := NewStore(0)
	req := pairListing(0, 10)
	req.KeyRequestType = mdl.KEYREQUESTTYPE_SECRET

	_, err := s.ListKeys(context.Background(), req)

	if !errors.Is(err, cryptography.ErrKeyTypeNotListable) {
		t.Errorf("ListKeys error = %v, want ErrKeyTypeNotListable", err)
	}
}

func resolution(handles ...mdl.KeyHandleV2Dto) *mdl.ResolveKeysRequestV2Dto {
	return &mdl.ResolveKeysRequestV2Dto{KeyRequestType: mdl.KEYREQUESTTYPE_KEY_PAIR, Keys: handles}
}

func keyHandle(identifier, pairID string) mdl.KeyHandleV2Dto {
	return mdl.KeyHandleV2Dto{Identifier: identifier, KeyMeta: pairHandle(pairID)}
}

func TestResolveKeysFindsAStoredKeyPair(t *testing.T) {
	s := NewStore(0)
	pairID := createKeyPair(t, s, "create-1")
	page, err := s.ListKeys(context.Background(), pairListing(0, 10))
	if err != nil {
		t.Fatalf("ListKeys: %v", err)
	}

	out, err := s.ResolveKeys(context.Background(), resolution(keyHandle("a", pairID)))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if len(out.Results) != 1 || out.Results[0].Outcome != mdl.KEYRESOLUTIONOUTCOME_FOUND || out.Results[0].Key == nil {
		t.Fatalf("results = %+v, want one found key pair", out.Results)
	}
	if !reflect.DeepEqual(*out.Results[0].Key, page.Items[0]) {
		t.Errorf("resolved key = %+v, want the listed pair %+v", *out.Results[0].Key, page.Items[0])
	}
}

func TestResolveKeysFindsAKeyPairByTheHandleCreateKeyReturned(t *testing.T) {
	s := NewStore(0)
	created, _, err := s.CreateKey(context.Background(), keyPairRequest("create-1", mdl.KEYALGORITHM_ECDSA))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	handle := mdl.KeyHandleV2Dto{Identifier: "a", KeyMeta: created.KeyPairDataResponseV2Dto.KeyPairMeta}

	out, err := s.ResolveKeys(context.Background(), resolution(handle))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if len(out.Results) != 1 || out.Results[0].Outcome != mdl.KEYRESOLUTIONOUTCOME_FOUND {
		t.Errorf("results = %+v, want one found key pair", out.Results)
	}
}

func TestResolveKeysAnswersEachHandleUnderItsIdentifier(t *testing.T) {
	s := NewStore(0)
	first := createKeyPair(t, s, "create-1")
	second := createKeyPair(t, s, "create-2")

	out, err := s.ResolveKeys(context.Background(), resolution(keyHandle("a", second), keyHandle("b", first)))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if len(out.Results) != 2 {
		t.Fatalf("got %d results, want 2", len(out.Results))
	}
	for i, want := range []struct{ identifier, pairID string }{{"a", second}, {"b", first}} {
		got := out.Results[i]
		if id, _ := pairIDOf(got.Key.ListedKeyPairV2Dto.KeyPairMeta); got.Identifier != want.identifier || id != want.pairID {
			t.Errorf("result %d = %q for pair %q, want %q for pair %q", i, got.Identifier, id, want.identifier, want.pairID)
		}
	}
}

func TestResolveKeysAnswersNotFoundForADestroyedKeyPair(t *testing.T) {
	s := NewStore(0)
	pairID := createKeyPair(t, s, "create-1")
	if _, _, err := s.DestroyKey(context.Background(), &mdl.DestroyKeyRequestV2Dto{
		KeyMeta:       []mdl.MetadataAttribute{metaAttr(pairID, "keyId", "Key ID")},
		ExecutionMode: mdl.OPERATIONEXECUTIONMODE_SYNCHRONOUS,
	}); err != nil {
		t.Fatalf("DestroyKey: %v", err)
	}

	out, err := s.ResolveKeys(context.Background(), resolution(keyHandle("a", pairID)))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if got := out.Results[0]; got.Outcome != mdl.KEYRESOLUTIONOUTCOME_NOT_FOUND || got.Key != nil {
		t.Errorf("result = %+v, want not found without a key", got)
	}
}

func TestResolveKeysAnswersNotFoundForAPendingCreation(t *testing.T) {
	s := NewStore(time.Hour)
	req := keyPairRequest("create-async", mdl.KEYALGORITHM_ECDSA)
	req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
	if _, _, err := s.CreateKey(context.Background(), req); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	var pairID string
	for _, op := range s.asyncCreates {
		pairID = op.keyID
	}

	out, err := s.ResolveKeys(context.Background(), resolution(keyHandle("a", pairID)))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if got := out.Results[0]; got.Outcome != mdl.KEYRESOLUTIONOUTCOME_NOT_FOUND || got.Key != nil {
		t.Errorf("result = %+v, want not found without a key", got)
	}
}

func TestResolveKeysAnswersInvalidHandleForAForeignHandle(t *testing.T) {
	s := NewStore(0)
	pairID := createKeyPair(t, s, "create-1")
	foreign := keyHandle("a", pairID)
	foreign.KeyMeta = append(foreign.KeyMeta, metaAttr("other", "extra", "Extra"))

	out, err := s.ResolveKeys(context.Background(), resolution(foreign))
	if err != nil {
		t.Fatalf("ResolveKeys: %v", err)
	}

	if got := out.Results[0]; got.Outcome != mdl.KEYRESOLUTIONOUTCOME_INVALID_HANDLE || got.Key != nil {
		t.Errorf("result = %+v, want an invalid handle without a key", got)
	}
}

func TestResolveKeysRefusesSecretKeys(t *testing.T) {
	s := NewStore(0)
	req := resolution(keyHandle("a", "p"))
	req.KeyRequestType = mdl.KEYREQUESTTYPE_SECRET

	_, err := s.ResolveKeys(context.Background(), req)

	if !errors.Is(err, cryptography.ErrKeyTypeNotListable) {
		t.Errorf("ResolveKeys error = %v, want ErrKeyTypeNotListable", err)
	}
}
