package cryptography_test

import mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"

func newPrivateKeyData(algorithm mdl.KeyAlgorithm, length int32) *mdl.PrivateKeyDataV2Dto {
	d := mdl.NewPrivateKeyDataV2Dto(algorithm)
	d.SetLength(length)
	return d
}
