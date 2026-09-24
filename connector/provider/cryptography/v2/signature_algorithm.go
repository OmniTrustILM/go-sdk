package cryptography

import (
	"strings"

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

const dataAttributeV3Version = 3

// signatureAlgorithmLabels keeps the contract's order and display labels.
var signatureAlgorithmLabels = []struct {
	algorithm SignatureAlgorithm
	label     string
}{
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
}

var (
	errSignatureAlgorithmNotSelected = errValidationFailed("signatureAttributes must select one signatureAlgorithm value")
	errSignatureAlgorithmRepeated    = errValidationFailed("signatureAlgorithm must be supplied once")
	errSignatureAlgorithmNotV3       = errValidationFailed("signatureAlgorithm must be a v3 attribute")
	errSignatureAlgorithmNotString   = errValidationFailed("signatureAlgorithm must carry a string value")
)

// SignatureAlgorithms returns every contract code.
func SignatureAlgorithms() []SignatureAlgorithm {
	out := make([]SignatureAlgorithm, len(signatureAlgorithmLabels))
	for i, entry := range signatureAlgorithmLabels {
		out[i] = entry.algorithm
	}
	return out
}

// Label is the display name the definition shows for a signature algorithm.
func (a SignatureAlgorithm) Label() string {
	for _, entry := range signatureAlgorithmLabels {
		if entry.algorithm == a {
			return entry.label
		}
	}
	return ""
}

// IsValid reports whether a is a contract code in its canonical spelling.
func (a SignatureAlgorithm) IsValid() bool {
	return a.Label() != ""
}

// SignatureAlgorithmDefinition builds the required single-select v3 signatureAlgorithm definition from supported.
func SignatureAlgorithmDefinition(supported ...SignatureAlgorithm) mdl.BaseAttributeDto {
	properties := mdl.DataAttributeProperties{
		Label:           "Signature Algorithm",
		Visible:         true,
		Required:        true,
		List:            true,
		ProtectionLevel: mdl.PROTECTIONLEVEL_NONE.Ptr(),
	}
	definition := mdl.NewDataAttributeV3(SignatureAlgorithmAttributeUUID, SignatureAlgorithmAttributeName,
		dataAttributeV3Version, mdl.ATTRIBUTETYPE_DATA, mdl.ATTRIBUTECONTENTTYPE_STRING, properties, mdl.ATTRIBUTEVERSION_V3)
	description := "Signature algorithm the signature is produced with"
	definition.Description = &description
	definition.Content = make([]mdl.BaseAttributeContentDtoV3, len(supported))
	for i, algorithm := range supported {
		definition.Content[i] = algorithm.content()
	}
	wrapped := mdl.DataAttributeV3AsBaseAttributeDtoV3(definition)
	return mdl.BaseAttributeDtoV3AsBaseAttributeDto(&wrapped)
}

// SignatureAlgorithmSelection is the signatureAttributes entry Core sends to select algorithm.
func SignatureAlgorithmSelection(algorithm SignatureAlgorithm) mdl.RequestAttribute {
	selection := mdl.NewRequestAttributeV3(SignatureAlgorithmAttributeUUID, SignatureAlgorithmAttributeName,
		mdl.ATTRIBUTECONTENTTYPE_STRING, mdl.ATTRIBUTEVERSION_V3)
	selection.Content = []mdl.BaseAttributeContentDtoV3{algorithm.content()}
	return mdl.RequestAttributeV3AsRequestAttribute(selection)
}

// SelectedSignatureAlgorithm returns the canonical code a single v3
// signatureAlgorithm attribute selects, matched ignoring case.
func SelectedSignatureAlgorithm(signatureAttributes []mdl.RequestAttribute) (SignatureAlgorithm, error) {
	selection, err := signatureAlgorithmAttribute(signatureAttributes)
	if err != nil {
		return "", err
	}
	if len(selection.Content) != 1 {
		return "", errSignatureAlgorithmNotSelected
	}
	value := selection.Content[0].StringAttributeContentV3
	if value == nil {
		return "", errSignatureAlgorithmNotString
	}
	if value.Data == "" {
		return "", errSignatureAlgorithmNotSelected
	}
	algorithm, ok := canonicalSignatureAlgorithm(value.Data)
	if !ok {
		return "", ErrSignatureAlgorithmUnsupported
	}
	return algorithm, nil
}

// signatureAlgorithmAttribute finds v3 attribute named signatureAlgorithm.
func signatureAlgorithmAttribute(attrs []mdl.RequestAttribute) (*mdl.RequestAttributeV3, error) {
	var found *mdl.RequestAttribute
	for i := range attrs {
		if requestAttributeName(attrs[i]) != SignatureAlgorithmAttributeName {
			continue
		}
		if found != nil {
			return nil, errSignatureAlgorithmRepeated
		}
		found = &attrs[i]
	}
	if found == nil {
		return nil, errSignatureAlgorithmNotSelected
	}
	if found.RequestAttributeV3 == nil {
		return nil, errSignatureAlgorithmNotV3
	}
	return found.RequestAttributeV3, nil
}

func requestAttributeName(a mdl.RequestAttribute) string {
	switch {
	case a.RequestAttributeV3 != nil:
		return a.RequestAttributeV3.Name
	case a.RequestAttributeV2 != nil:
		return a.RequestAttributeV2.Name
	default:
		return ""
	}
}

// canonicalSignatureAlgorithm matches code ignoring case.
func canonicalSignatureAlgorithm(code string) (SignatureAlgorithm, bool) {
	for _, entry := range signatureAlgorithmLabels {
		if strings.EqualFold(string(entry.algorithm), code) {
			return entry.algorithm, true
		}
	}
	return "", false
}

func (a SignatureAlgorithm) content() mdl.BaseAttributeContentDtoV3 {
	code := a
	if canonical, ok := canonicalSignatureAlgorithm(string(a)); ok {
		code = canonical
	}
	value := mdl.NewStringAttributeContentV3(string(code), mdl.ATTRIBUTECONTENTTYPE_STRING)
	label := code.Label()
	value.Reference = &label
	return mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(value)
}
