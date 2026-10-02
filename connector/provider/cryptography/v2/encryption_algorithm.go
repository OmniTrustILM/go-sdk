package cryptography

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// EncryptionAlgorithm is a code of the contract's EncryptionAlgorithm enum: a
// JCA transformation name. OAEP uses MGF1 with the OAEP hash and an empty label.
type EncryptionAlgorithm string

const (
	EncryptionAlgorithmRSAPKCS1V15   EncryptionAlgorithm = "RSA/ECB/PKCS1Padding"
	EncryptionAlgorithmRSAOAEPSHA1   EncryptionAlgorithm = "RSA/ECB/OAEPWithSHA-1AndMGF1Padding"
	EncryptionAlgorithmRSAOAEPSHA256 EncryptionAlgorithm = "RSA/ECB/OAEPWithSHA-256AndMGF1Padding"
	EncryptionAlgorithmRSAOAEPSHA384 EncryptionAlgorithm = "RSA/ECB/OAEPWithSHA-384AndMGF1Padding"
	EncryptionAlgorithmRSAOAEPSHA512 EncryptionAlgorithm = "RSA/ECB/OAEPWithSHA-512AndMGF1Padding"
)

// The cipher attribute the contract reserves for the encryption algorithm.
const (
	EncryptionAlgorithmAttributeName = "encryptionAlgorithm"
	EncryptionAlgorithmAttributeUUID = "5e364467-fa95-4253-907b-0c73cdfb2be7"
)

var encryptionAlgorithmAttribute = algorithmAttribute[EncryptionAlgorithm]{
	uuid:        EncryptionAlgorithmAttributeUUID,
	name:        EncryptionAlgorithmAttributeName,
	label:       "Encryption Algorithm",
	description: "Encryption algorithm used to encrypt or decrypt the data",
	codes: []labeledCode[EncryptionAlgorithm]{
		{EncryptionAlgorithmRSAPKCS1V15, "RSAES-PKCS1-v1_5"},
		{EncryptionAlgorithmRSAOAEPSHA1, "RSAES-OAEP with SHA-1"},
		{EncryptionAlgorithmRSAOAEPSHA256, "RSAES-OAEP with SHA-256"},
		{EncryptionAlgorithmRSAOAEPSHA384, "RSAES-OAEP with SHA-384"},
		{EncryptionAlgorithmRSAOAEPSHA512, "RSAES-OAEP with SHA-512"},
	},
	selectionErrors: selectionErrorsFor("Cipher", EncryptionAlgorithmAttributeName, EncryptionAlgorithmAttributeUUID),
	unknown:         errValidationFailed("Unknown encryption algorithm code."),
}

// EncryptionAlgorithms returns every contract code.
func EncryptionAlgorithms() []EncryptionAlgorithm {
	return encryptionAlgorithmAttribute.all()
}

// Label is the display name of a contract code in its canonical spelling. Any
// other spelling has an empty label.
func (a EncryptionAlgorithm) Label() string {
	return encryptionAlgorithmAttribute.labelOf(a)
}

// IsValid reports whether a is a contract code in its canonical spelling.
func (a EncryptionAlgorithm) IsValid() bool {
	return encryptionAlgorithmAttribute.contains(a)
}

// EncryptionAlgorithmDefinition builds the required single-select v3
// encryptionAlgorithm definition from the profiles the key supports.
func EncryptionAlgorithmDefinition(supported ...EncryptionAlgorithm) mdl.BaseAttributeDto {
	return encryptionAlgorithmAttribute.definition(supported)
}

// EncryptionAlgorithmSelection is the cipherAttributes entry Core sends to select algorithm.
func EncryptionAlgorithmSelection(algorithm EncryptionAlgorithm) mdl.RequestAttribute {
	return encryptionAlgorithmAttribute.selection(algorithm)
}

// SelectedEncryptionAlgorithm reads the canonical code from the one v3
// attribute carrying the reserved UUID and name. It matches the code ignoring
// case and refuses any other attribute carrying either identifier.
func SelectedEncryptionAlgorithm(cipherAttributes []mdl.RequestAttribute) (EncryptionAlgorithm, error) {
	return encryptionAlgorithmAttribute.selected(cipherAttributes)
}
