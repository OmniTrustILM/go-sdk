package cryptography

import (
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// p256Identifier is the DER AlgorithmIdentifier {id-ecPublicKey, prime256v1}, in base64.
const p256Identifier = "MBMGByqGSM49AgEGCCqGSM49AwEH"

func TestValidatePrivateDescriptor(t *testing.T) {
	const notPositive = "keyData must carry a positive key length"
	cases := map[string]struct {
		algorithm  mdl.KeyAlgorithm
		length     *int32
		wantDetail string
	}{
		"RSA with a length":       {mdl.KEYALGORITHM_RSA, new(int32(2048)), ""},
		"RSA without a length":    {mdl.KEYALGORITHM_RSA, nil, ""},
		"ECDSA with a length":     {mdl.KEYALGORITHM_ECDSA, new(int32(256)), ""},
		"ML-DSA without a length": {mdl.KEYALGORITHM_ML_DSA, nil, ""},
		"zero length":             {mdl.KEYALGORITHM_RSA, new(int32(0)), notPositive},
		"negative length":         {mdl.KEYALGORITHM_ECDSA, new(int32(-1)), notPositive},
		"a symmetric algorithm":   {mdl.KEYALGORITHM_AES, new(int32(256)), "keyData must carry an algorithm of key type Private"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			d := mdl.NewPrivateKeyDataV2Dto(tc.algorithm)
			d.Length = tc.length
			err := validatePrivateDescriptor(d, "keyData")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

func TestValidateSecretDescriptor(t *testing.T) {
	const notPositive = "keyData must carry a positive key length"
	cases := map[string]struct {
		algorithm  mdl.KeyAlgorithm
		length     int32
		wantDetail string
	}{
		"AES of 256 bits":      {mdl.KEYALGORITHM_AES, 256, ""},
		"AES of 512 bits":      {mdl.KEYALGORITHM_AES, 512, ""},
		"Unknown of 320 bits":  {mdl.KEYALGORITHM_UNKNOWN, 320, ""},
		"zero length":          {mdl.KEYALGORITHM_AES, 0, notPositive},
		"negative length":      {mdl.KEYALGORITHM_UNKNOWN, -1, notPositive},
		"a key pair algorithm": {mdl.KEYALGORITHM_ECDSA, 256, "keyData must carry an algorithm of key type Secret"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateSecretDescriptor(mdl.NewSecretKeyDataV2Dto(tc.algorithm, tc.length), "keyData")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}

func TestValidateAlgorithmIdentifierEncoding(t *testing.T) {
	const notBase64 = "keyData must carry a base64-encoded algorithmIdentifier"
	cases := map[string]struct {
		identifier *string
		wantDetail string
	}{
		"absent":           {nil, ""},
		"base64":           {strPtr(p256Identifier), ""},
		"empty":            {strPtr(""), notBase64},
		"not base64":       {strPtr("not base64!"), notBase64},
		"unpadded base64":  {strPtr("MBMGByqGSM49AgEGCCqGSM49AwE"), notBase64},
		"base64url digits": {strPtr("MBMGByqGSM49AgEGCCqGSM49AwE_"), notBase64},
		"line feed":        {strPtr("MBMGByqGSM49\nAgEGCCqGSM49AwEH"), notBase64},
		"carriage return":  {strPtr("MBMGByqGSM49AgEGCCqGSM49AwEH\r"), notBase64},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			err := validateAlgorithmIdentifierEncoding(tc.identifier, "keyData")
			if tc.wantDetail == "" {
				wantNoError(t, err)
				return
			}
			wantResponseShapeError(t, err, tc.wantDetail)
		})
	}
}
