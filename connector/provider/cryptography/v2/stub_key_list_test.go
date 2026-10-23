package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubKeyList implements cryptography.KeyListProvider.
type stubKeyList struct {
	page   *mdl.ListKeysResponseV2Dto
	err    error
	listed *mdl.ListKeysRequestV2Dto

	results    *mdl.ResolveKeysResponseV2Dto
	resolveErr error
	resolved   *mdl.ResolveKeysRequestV2Dto
}

func (s *stubKeyList) ListKeys(ctx context.Context, req *mdl.ListKeysRequestV2Dto) (*mdl.ListKeysResponseV2Dto, error) {
	s.listed = req
	return s.page, s.err
}

func (s *stubKeyList) ResolveKeys(ctx context.Context, req *mdl.ResolveKeysRequestV2Dto) (*mdl.ResolveKeysResponseV2Dto, error) {
	s.resolved = req
	return s.results, s.resolveErr
}
