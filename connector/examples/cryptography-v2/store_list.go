package main

import (
	"context"
	"slices"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
	cryptography "github.com/OmniTrustILM/go-sdk/connector/provider/cryptography/v2"
)

// pairHandleName marks the metadata carrying a pair's ID.
const pairHandleName = "keyPairHandle"

// ListKeys lists key pairs only and pages them in pair ID order to keep a
// page stable while the store is unchanged.
func (s *Store) ListKeys(ctx context.Context, req *mdl.ListKeysRequestV2Dto) (*mdl.ListKeysResponseV2Dto, error) {
	if req.KeyRequestType != mdl.KEYREQUESTTYPE_KEY_PAIR {
		return nil, cryptography.ErrKeyTypeNotListable
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	pairIDs := s.liveKeyPairIDs()
	page := pageOf(pairIDs, req.Offset, req.Limit)
	items := make([]mdl.ListedKeyV2, 0, len(page))
	for _, pairID := range page {
		items = append(items, s.listedPair(pairID))
	}
	return &mdl.ListKeysResponseV2Dto{Items: items, TotalItems: int64(len(pairIDs))}, nil
}

// ResolveKeys answers each handle with the key pair ListKeys would list for it.
func (s *Store) ResolveKeys(ctx context.Context, req *mdl.ResolveKeysRequestV2Dto) (*mdl.ResolveKeysResponseV2Dto, error) {
	if req.KeyRequestType != mdl.KEYREQUESTTYPE_KEY_PAIR {
		return nil, cryptography.ErrKeyTypeNotListable
	}
	s.mu.Lock()
	defer s.mu.Unlock()

	live := make(map[string]bool)
	for _, pairID := range s.liveKeyPairIDs() {
		live[pairID] = true
	}
	results := make([]mdl.KeyResolutionV2Dto, 0, len(req.Keys))
	for _, handle := range req.Keys {
		pairID, ok := pairIDOf(handle.KeyMeta)
		switch {
		case !ok:
			results = append(results, *mdl.NewKeyResolutionV2Dto(handle.Identifier, mdl.KEYRESOLUTIONOUTCOME_INVALID_HANDLE))
		case !live[pairID]:
			results = append(results, *mdl.NewKeyResolutionV2Dto(handle.Identifier, mdl.KEYRESOLUTIONOUTCOME_NOT_FOUND))
		default:
			found := mdl.NewKeyResolutionV2Dto(handle.Identifier, mdl.KEYRESOLUTIONOUTCOME_FOUND)
			listed := s.listedPair(pairID)
			found.Key = &listed
			results = append(results, *found)
		}
	}
	return &mdl.ResolveKeysResponseV2Dto{Results: results}, nil
}

// listedPair is the entry of a live key pair, as ListKeys and ResolveKeys list it.
func (s *Store) listedPair(pairID string) mdl.ListedKeyV2 {
	rec := s.keys[pairID]
	pair := buildKeyPairPayload(pairID, rec.algorithm, rec.length, rec.spki)
	listed := mdl.NewListedKeyPairV2Dto(pair.KeyPairMeta, *pair.PrivateKeyData)
	listed.PublicKeyData = pair.PublicKeyData
	return mdl.ListedKeyPairV2DtoAsListedKeyV2(listed)
}

// liveKeyPairIDs returns the sorted IDs of the live key pairs.
func (s *Store) liveKeyPairIDs() []string {
	pending := s.pendingKeyIDs()
	pairIDs := make([]string, 0, len(s.keys))
	for pairID, rec := range s.keys {
		if rec.destroyed || !rec.isKeyPair() || pending[pairID] {
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
	end := start + min(int(limit), len(ids)-start)
	return ids[start:end]
}

// pairHandle carries the pair ID as content data, since handles are told apart
// by their names and data. Version 3 content names its type, so a client can
// decode it.
func pairHandle(pairID string) []mdl.MetadataAttribute {
	meta := mdl.NewMetadataAttributeV3(pairID, pairHandleName, attributeV3Version, mdl.ATTRIBUTETYPE_META, mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewMetadataAttributeProperties("Key pair handle", true), mdl.ATTRIBUTEVERSION_V3)
	meta.Content = []mdl.BaseAttributeContentDtoV3{
		mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(mdl.NewStringAttributeContentV3(pairID, mdl.ATTRIBUTECONTENTTYPE_STRING)),
	}
	return []mdl.MetadataAttribute{mdl.MetadataAttributeV3AsMetadataAttribute(meta)}
}

// pairIDOf reads back the pair ID from exactly the handle pairHandle wrote.
// Any other shape is a handle this store did not write.
func pairIDOf(keyPairMeta []mdl.MetadataAttribute) (string, bool) {
	if len(keyPairMeta) != 1 {
		return "", false
	}
	v3 := keyPairMeta[0].MetadataAttributeV3
	if v3 == nil || v3.Name != pairHandleName || len(v3.Content) != 1 || v3.Content[0].StringAttributeContentV3 == nil {
		return "", false
	}
	return v3.Content[0].StringAttributeContentV3.Data, true
}
