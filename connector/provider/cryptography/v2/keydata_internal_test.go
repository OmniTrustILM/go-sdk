package cryptography

import mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"

// The spec makes the key descriptors' length optional (required only for RSA,
// ECDSA and AES), so the generated constructors no longer take it; these
// builders restore the common "descriptor with a length" shape for fixtures.

func newSecretKeyData(algorithm mdl.KeyAlgorithm, length int32) *mdl.SecretKeyDataV2Dto {
	d := mdl.NewSecretKeyDataV2Dto(algorithm)
	d.SetLength(length)
	return d
}

func newPublicKeyData(algorithm mdl.KeyAlgorithm, length int32, spki string) *mdl.PublicKeyDataV2Dto {
	d := mdl.NewPublicKeyDataV2Dto(algorithm, spki)
	d.SetLength(length)
	return d
}

func newPrivateKeyData(algorithm mdl.KeyAlgorithm, length int32) *mdl.PrivateKeyDataV2Dto {
	d := mdl.NewPrivateKeyDataV2Dto(algorithm)
	d.SetLength(length)
	return d
}
