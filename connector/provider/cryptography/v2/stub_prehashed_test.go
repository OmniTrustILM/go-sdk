package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubPrehashed implements cryptography.PrehashedSignProvider.
type stubPrehashed struct {
	resp     *mdl.SignDataResponseV2Dto
	accepted bool
	err      error
	got      *mdl.SignDataRequestV2Dto
}

func (s *stubPrehashed) SignPrehashed(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	s.got = req
	return s.resp, s.accepted, s.err
}
