package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubDataDigest implements cryptography.DataDigestSignProvider.
type stubDataDigest struct {
	resp     *mdl.SignDataResponseV2Dto
	accepted bool
	err      error
	got      *mdl.SignDataRequestV2Dto
}

func (s *stubDataDigest) SignDataDigest(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	s.got = req
	return s.resp, s.accepted, s.err
}
