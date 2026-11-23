package cryptography

import (
	"encoding/base64"
	"strings"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

func validatePrivateDescriptor(d *mdl.PrivateKeyDataV2Dto, field string) error {
	return firstError(
		validateKeyDescriptor(d.Type, keyTypePrivate, d.Algorithm, field),
		validateStatedKeyLength(d.Length, field),
		validateAlgorithmIdentifierEncoding(d.AlgorithmIdentifier, field),
	)
}

func validateSecretDescriptor(d *mdl.SecretKeyDataV2Dto, field string) error {
	return firstError(
		validateKeyDescriptor(d.Type, keyTypeSecret, d.Algorithm, field),
		validateStatedKeyLength(&d.Length, field),
	)
}

func validateStatedKeyLength(length *int32, field string) error {
	if length != nil && *length <= 0 {
		return errResponseShape(field + " must carry a positive key length")
	}
	return nil
}

// validateAlgorithmIdentifierEncoding leaves the DER and key-pair checks to Core.
func validateAlgorithmIdentifierEncoding(identifier *string, field string) error {
	if identifier == nil {
		return nil
	}
	der, err := base64.StdEncoding.DecodeString(*identifier)
	if err != nil || len(der) == 0 || strings.ContainsAny(*identifier, "\r\n") {
		return errResponseShape(field + " must carry a base64-encoded algorithmIdentifier")
	}
	return nil
}
