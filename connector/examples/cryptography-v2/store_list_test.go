package main

import (
	"context"
	"slices"
	"testing"
	"time"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

func createKeyPair(t *testing.T, s *Store, creationID string) string {
	t.Helper()
	resp, _, err := s.CreateKey(context.Background(), keyPairRequest(creationID, mdl.KEYALGORITHM_ECDSA))
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}
	return mustKeyID(resp.KeyPairDataResponseV2Dto.KeyPairMeta)
}

func listedPairIDs(page *mdl.ListKeyPairsResponseV2Dto) []string {
	ids := make([]string, 0, len(page.Items))
	for _, pair := range page.Items {
		id, _ := listedPairID(pair.KeyPairMeta)
		ids = append(ids, id)
	}
	return ids
}

func TestListKeyPairsPagesTheStoredKeyPairs(t *testing.T) {
	s := NewStore(0)
	want := []string{createKeyPair(t, s, "create-1"), createKeyPair(t, s, "create-2"), createKeyPair(t, s, "create-3")}
	slices.Sort(want)

	first, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 2})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	second, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 2, Limit: 2})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if first.TotalItems != 3 || len(first.Items) != 2 || len(second.Items) != 1 {
		t.Fatalf("pages hold %d and %d of %d, want 2 and 1 of 3", len(first.Items), len(second.Items), first.TotalItems)
	}
	if got := append(listedPairIDs(first), listedPairIDs(second)...); !slices.Equal(got, want) {
		t.Errorf("pages list %v, want %v", got, want)
	}
	if first.Items[0].PublicKeyData == nil {
		t.Errorf("listed key pair PublicKeyData = nil, want the public key")
	}
}

func TestListKeyPairsReturnsOnlyTheKeyPairsTheFilterNames(t *testing.T) {
	s := NewStore(0)
	createKeyPair(t, s, "create-1")
	wanted := createKeyPair(t, s, "create-2")

	page, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{
		Offset:            0,
		Limit:             10,
		KeyPairMetaFilter: [][]mdl.MetadataAttribute{listedPairMeta(wanted)},
	})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if page.TotalItems != 1 || len(page.Items) != 1 {
		t.Fatalf("page holds %d of %d, want 1 of 1", len(page.Items), page.TotalItems)
	}
	if got, _ := listedPairID(page.Items[0].KeyPairMeta); got != wanted {
		t.Errorf("listed %q, want %q", got, wanted)
	}
}

func TestListKeyPairsListsNothingForAFilterHandleWithAnExtraAttribute(t *testing.T) {
	s := NewStore(0)
	pairID := createKeyPair(t, s, "create-1")
	handle := append(listedPairMeta(pairID), metaAttr(pairID, "keyPairLabel", "Key pair label"))

	page, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{
		Offset:            0,
		Limit:             10,
		KeyPairMetaFilter: [][]mdl.MetadataAttribute{handle},
	})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if page.TotalItems != 0 || len(page.Items) != 0 {
		t.Errorf("page holds %d of %d, want none", len(page.Items), page.TotalItems)
	}
}

func TestListKeyPairsGivesEachPairDistinctHandleData(t *testing.T) {
	s := NewStore(0)
	createKeyPair(t, s, "create-1")
	createKeyPair(t, s, "create-2")

	page, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	first, _ := listedPairID(page.Items[0].KeyPairMeta)
	second, _ := listedPairID(page.Items[1].KeyPairMeta)
	if first == "" || first == second {
		t.Errorf("listed pairs carry data %q and %q, want two distinct pair IDs", first, second)
	}
}

func TestListKeyPairsLeavesOutPendingAndCancelledCreations(t *testing.T) {
	s := NewStore(time.Hour)
	req := keyPairRequest("create-async", mdl.KEYALGORITHM_ECDSA)
	req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
	accepted, _, err := s.CreateKey(context.Background(), req)
	if err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	pending, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	if err := s.CancelCreateKey(context.Background(), &mdl.OperationTrackingRequestV2Dto{
		OperationMeta: accepted.KeyPairDataResponseV2Dto.OperationMeta,
	}); err != nil {
		t.Fatalf("CancelCreateKey: %v", err)
	}
	cancelled, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if pending.TotalItems != 0 || cancelled.TotalItems != 0 {
		t.Errorf("listed %d pending and %d cancelled key pairs, want none", pending.TotalItems, cancelled.TotalItems)
	}
}

func TestListKeyPairsLeavesOutPendingAndCancelledImports(t *testing.T) {
	s := NewStore(time.Hour)
	accepted, _ := importP256Key(t, s, mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS)

	pending, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}
	if err := s.CancelImportKey(context.Background(), &mdl.OperationTrackingRequestV2Dto{
		OperationMeta: accepted.KeyPairDataResponseV2Dto.OperationMeta,
	}); err != nil {
		t.Fatalf("CancelImportKey: %v", err)
	}
	cancelled, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if pending.TotalItems != 0 || cancelled.TotalItems != 0 {
		t.Errorf("listed %d pending and %d cancelled imports, want none", pending.TotalItems, cancelled.TotalItems)
	}
}

func TestListKeyPairsListsACompletedAsynchronousCreation(t *testing.T) {
	s := NewStore(0)
	req := keyPairRequest("create-async", mdl.KEYALGORITHM_ECDSA)
	req.ExecutionMode = mdl.OPERATIONEXECUTIONMODE_ASYNCHRONOUS
	if _, _, err := s.CreateKey(context.Background(), req); err != nil {
		t.Fatalf("CreateKey: %v", err)
	}

	page, err := s.ListKeyPairs(context.Background(), &mdl.ListKeyPairsRequestV2Dto{Offset: 0, Limit: 10})
	if err != nil {
		t.Fatalf("ListKeyPairs: %v", err)
	}

	if page.TotalItems != 1 || len(page.Items) != 1 {
		t.Errorf("page holds %d of %d, want the completed key pair", len(page.Items), page.TotalItems)
	}
}
