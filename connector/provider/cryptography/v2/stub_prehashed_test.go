package cryptography_test

import (
	"context"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// stubPrehashed implements cryptography.PrehashedSignProvider.
type stubPrehashed struct {
	resp *mdl.SignDataResponseV2Dto
	got  *mdl.SignDataRequestV2Dto
}

func (s *stubPrehashed) SignPrehashed(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	s.got = req
	return s.resp, false, nil
}

// countingProvider counts the SignData calls that reach the base provider.
type countingProvider struct {
	stubProvider
	signCalls int
}

func (c *countingProvider) SignData(ctx context.Context, req *mdl.SignDataRequestV2Dto) (*mdl.SignDataResponseV2Dto, bool, error) {
	c.signCalls++
	return c.stubProvider.SignData(ctx, req)
}
