package main

import (
	"context"
	"slices"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// listedPairMetaName marks the metadata carrying a listed pair's ID.
const listedPairMetaName = "keyPairHandle"

// ListKeyPairs pages in pair ID order to keep a page stable while the store
// is unchanged.
func (s *Store) ListKeyPairs(ctx context.Context, req *mdl.ListKeyPairsRequestV2Dto) (*mdl.ListKeyPairsResponseV2Dto, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	pairIDs := s.liveKeyPairIDs(req.KeyPairMetaFilter)
	page := pageOf(pairIDs, req.Offset, req.Limit)
	items := make([]mdl.ListedKeyPairV2Dto, 0, len(page))
	for _, pairID := range page {
		rec := s.keys[pairID]
		pair := buildKeyPairPayload(pairID, rec.algorithm, rec.length, rec.spki)
		items = append(items, mdl.ListedKeyPairV2Dto{
			KeyPairMeta:    listedPairMeta(pairID),
			PrivateKeyData: *pair.PrivateKeyData,
			PublicKeyData:  pair.PublicKeyData,
		})
	}
	return &mdl.ListKeyPairsResponseV2Dto{Items: items, TotalItems: int64(len(pairIDs))}, nil
}

// liveKeyPairIDs returns the sorted IDs of the live key pairs. A filter
// narrows them to the pairs it names.
func (s *Store) liveKeyPairIDs(filter [][]mdl.MetadataAttribute) []string {
	named := make(map[string]bool, len(filter))
	for _, keyPairMeta := range filter {
		if pairID, ok := listedPairID(keyPairMeta); ok {
			named[pairID] = true
		}
	}
	pending := s.pendingKeyIDs()
	pairIDs := make([]string, 0, len(s.keys))
	for pairID, rec := range s.keys {
		if rec.destroyed || !rec.isKeyPair() || pending[pairID] || (filter != nil && !named[pairID]) {
			continue
		}
		pairIDs = append(pairIDs, pairID)
	}
	slices.Sort(pairIDs)
	return pairIDs
}

// pendingKeyIDs names the keys whose creation or import can still be cancelled.
func (s *Store) pendingKeyIDs() map[string]bool {
	pending := make(map[string]bool)
	for _, op := range s.asyncCreates {
		if op.status(s.asyncDelay) == mdl.OPERATIONSTATUS_IN_PROGRESS {
			pending[op.keyID] = true
		}
	}
	for _, rec := range s.importHandles {
		if rec.status(s.asyncDelay) == mdl.OPERATIONSTATUS_IN_PROGRESS {
			pending[rec.keyID] = true
		}
	}
	return pending
}

// pageOf yields an empty page for an offset past the end.
func pageOf(ids []string, offset, limit int32) []string {
	start := min(int(offset), len(ids))
	end := min(int(offset)+int(limit), len(ids))
	return ids[start:end]
}

// listedPairMeta carries the pair ID as content data. A filter tells handles
// apart by their names and data.
func listedPairMeta(pairID string) []mdl.MetadataAttribute {
	meta := metaAttr(pairID, listedPairMetaName, "Key pair handle")
	meta.MetadataAttributeV2.Content = []mdl.BaseAttributeContentDtoV2{
		mdl.StringAttributeContentV2AsBaseAttributeContentDtoV2(mdl.NewStringAttributeContentV2(pairID)),
	}
	return []mdl.MetadataAttribute{meta}
}

// listedPairID reads back the pair ID from exactly the handle listedPairMeta
// wrote. A filter names a pair by its whole handle.
func listedPairID(keyPairMeta []mdl.MetadataAttribute) (string, bool) {
	if len(keyPairMeta) != 1 {
		return "", false
	}
	v2 := keyPairMeta[0].MetadataAttributeV2
	if v2 == nil || v2.Name != listedPairMetaName || len(v2.Content) != 1 || v2.Content[0].StringAttributeContentV2 == nil {
		return "", false
	}
	return v2.Content[0].StringAttributeContentV2.Data, true
}
