package cryptography

import (
	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// SignatureAlgorithm is a code of the contract's SignatureAlgorithm enum.
type SignatureAlgorithm string

const (
	SignatureAlgorithmSHA256WithRSA    SignatureAlgorithm = "SHA256withRSA"
	SignatureAlgorithmSHA384WithRSA    SignatureAlgorithm = "SHA384withRSA"
	SignatureAlgorithmSHA512WithRSA    SignatureAlgorithm = "SHA512withRSA"
	SignatureAlgorithmSHA256WithRSAPSS SignatureAlgorithm = "SHA256withRSAandMGF1"
	SignatureAlgorithmSHA384WithRSAPSS SignatureAlgorithm = "SHA384withRSAandMGF1"
	SignatureAlgorithmSHA512WithRSAPSS SignatureAlgorithm = "SHA512withRSAandMGF1"
	SignatureAlgorithmSHA256WithECDSA  SignatureAlgorithm = "SHA256withECDSA"
	SignatureAlgorithmSHA384WithECDSA  SignatureAlgorithm = "SHA384withECDSA"
	SignatureAlgorithmSHA512WithECDSA  SignatureAlgorithm = "SHA512withECDSA"
	SignatureAlgorithmEd25519          SignatureAlgorithm = "Ed25519"
	SignatureAlgorithmEd448            SignatureAlgorithm = "Ed448"
	SignatureAlgorithmFalcon1024       SignatureAlgorithm = "FALCON-1024"
	SignatureAlgorithmMLDSA44          SignatureAlgorithm = "ML-DSA-44"
	SignatureAlgorithmMLDSA65          SignatureAlgorithm = "ML-DSA-65"
	SignatureAlgorithmMLDSA87          SignatureAlgorithm = "ML-DSA-87"
	SignatureAlgorithmSLHDSASHA2128S   SignatureAlgorithm = "SLH-DSA-SHA2-128S"
	SignatureAlgorithmSLHDSASHA2128F   SignatureAlgorithm = "SLH-DSA-SHA2-128F"
	SignatureAlgorithmSLHDSASHA2192S   SignatureAlgorithm = "SLH-DSA-SHA2-192S"
	SignatureAlgorithmSLHDSASHA2192F   SignatureAlgorithm = "SLH-DSA-SHA2-192F"
	SignatureAlgorithmSLHDSASHA2256S   SignatureAlgorithm = "SLH-DSA-SHA2-256S"
	SignatureAlgorithmSLHDSASHA2256F   SignatureAlgorithm = "SLH-DSA-SHA2-256F"
)

// The sign attribute the contract reserves for the signature algorithm.
const (
	SignatureAlgorithmAttributeName = "signatureAlgorithm"
	SignatureAlgorithmAttributeUUID = "9180267f-c82f-4b7b-8160-d2363d813869"
)

var signatureAlgorithmAttribute = algorithmAttribute[SignatureAlgorithm]{
	uuid:        SignatureAlgorithmAttributeUUID,
	name:        SignatureAlgorithmAttributeName,
	label:       "Signature Algorithm",
	description: "Signature algorithm the signature is produced with",
	codes: []labeledCode[SignatureAlgorithm]{
		{SignatureAlgorithmSHA256WithRSA, "RSASSA-PKCS_v1.5 using SHA256"},
		{SignatureAlgorithmSHA384WithRSA, "RSASSA-PKCS_v1.5 using SHA384"},
		{SignatureAlgorithmSHA512WithRSA, "RSASSA-PKCS_v1.5 using SHA512"},
		{SignatureAlgorithmSHA256WithRSAPSS, "RSASSA-PSS using SHA256"},
		{SignatureAlgorithmSHA384WithRSAPSS, "RSASSA-PSS using SHA384"},
		{SignatureAlgorithmSHA512WithRSAPSS, "RSASSA-PSS using SHA512"},
		{SignatureAlgorithmSHA256WithECDSA, "ECDSA using SHA256"},
		{SignatureAlgorithmSHA384WithECDSA, "ECDSA using SHA384"},
		{SignatureAlgorithmSHA512WithECDSA, "ECDSA using SHA512"},
		{SignatureAlgorithmEd25519, "Pure EdDSA with Edwards25519"},
		{SignatureAlgorithmEd448, "Pure EdDSA with Edwards448"},
		{SignatureAlgorithmFalcon1024, "FALCON-1024"},
		{SignatureAlgorithmMLDSA44, "ML-DSA-44 (Dilithium)"},
		{SignatureAlgorithmMLDSA65, "ML-DSA-65 (Dilithium)"},
		{SignatureAlgorithmMLDSA87, "ML-DSA-87 (Dilithium)"},
		{SignatureAlgorithmSLHDSASHA2128S, "SLH-DSA-SHA2-128S (SPHINCS+)"},
		{SignatureAlgorithmSLHDSASHA2128F, "SLH-DSA-SHA2-128F (SPHINCS+)"},
		{SignatureAlgorithmSLHDSASHA2192S, "SLH-DSA-SHA2-192S (SPHINCS+)"},
		{SignatureAlgorithmSLHDSASHA2192F, "SLH-DSA-SHA2-192F (SPHINCS+)"},
		{SignatureAlgorithmSLHDSASHA2256S, "SLH-DSA-SHA2-256S (SPHINCS+)"},
		{SignatureAlgorithmSLHDSASHA2256F, "SLH-DSA-SHA2-256F (SPHINCS+)"},
	},
	selectionErrors: selectionErrorsFor("Signature", SignatureAlgorithmAttributeName, SignatureAlgorithmAttributeUUID),
	unknown:         errValidationFailed("Unknown signature algorithm code."),
}

// SignatureAlgorithms returns every contract code.
func SignatureAlgorithms() []SignatureAlgorithm {
	return signatureAlgorithmAttribute.all()
}

// Label is the display name of a contract code in its canonical spelling. Any
// other spelling has an empty label.
func (a SignatureAlgorithm) Label() string {
	return signatureAlgorithmAttribute.labelOf(a)
}

// IsValid reports whether a is a contract code in its canonical spelling.
func (a SignatureAlgorithm) IsValid() bool {
	return signatureAlgorithmAttribute.contains(a)
}

// SignatureAlgorithmDefinition builds the required single-select v3 signatureAlgorithm definition from supported.
func SignatureAlgorithmDefinition(supported ...SignatureAlgorithm) mdl.BaseAttributeDto {
	return signatureAlgorithmAttribute.definition(supported)
}

// SignatureAlgorithmSelection is the signatureAttributes entry Core sends to select algorithm.
func SignatureAlgorithmSelection(algorithm SignatureAlgorithm) mdl.RequestAttribute {
	return signatureAlgorithmAttribute.selection(algorithm)
}

// SelectedSignatureAlgorithm reads the canonical code from the one v3
// attribute carrying the reserved UUID and name. It matches the code ignoring
// case and refuses any other attribute carrying either identifier.
func SelectedSignatureAlgorithm(signatureAttributes []mdl.RequestAttribute) (SignatureAlgorithm, error) {
	return signatureAlgorithmAttribute.selected(signatureAttributes)
}
