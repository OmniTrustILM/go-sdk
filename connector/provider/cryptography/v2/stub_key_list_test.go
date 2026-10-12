package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubKeyList implements cryptography.KeyListProvider.
type stubKeyList struct {
	page   *mdl.ListKeyPairsResponseV2Dto
	err    error
	listed *mdl.ListKeyPairsRequestV2Dto
}

func (s *stubKeyList) ListKeyPairs(ctx context.Context, req *mdl.ListKeyPairsRequestV2Dto) (*mdl.ListKeyPairsResponseV2Dto, error) {
	s.listed = req
	return s.page, s.err
}
