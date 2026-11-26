package cms

import (
	"crypto"
	"encoding/asn1"
)

// Content types (RFC 5652 section 4 and 5.1).
var (
	oidSignedData = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 2}
	oidData       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 7, 1}
)

// Attribute types (RFC 5652 section 11, RFC 6211 section 2).
var (
	oidAttrContentType         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 3}
	oidAttrMessageDigest       = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 4}
	oidAttrSigningTime         = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 5}
	oidAttrAlgorithmProtection = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 9, 52}
)

// RSASSA-PSS and MGF1 (RFC 4055 section 3).
var (
	oidRSAPSS = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 10}
	oidMGF1   = asn1.ObjectIdentifier{1, 2, 840, 113549, 1, 1, 8}
)

// oidEd25519 is id-Ed25519 (RFC 8410 section 3).
var oidEd25519 = asn1.ObjectIdentifier{1, 3, 101, 112}

// digestOIDs holds the SHA-2 identifiers of RFC 5754 section 2.
var digestOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA224: {2, 16, 840, 1, 101, 3, 4, 2, 4},
	crypto.SHA256: {2, 16, 840, 1, 101, 3, 4, 2, 1},
	crypto.SHA384: {2, 16, 840, 1, 101, 3, 4, 2, 2},
	crypto.SHA512: {2, 16, 840, 1, 101, 3, 4, 2, 3},
}

// rsaOIDs holds sha*WithRSAEncryption (RFC 4055 section 5).
var rsaOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256: {1, 2, 840, 113549, 1, 1, 11},
	crypto.SHA384: {1, 2, 840, 113549, 1, 1, 12},
	crypto.SHA512: {1, 2, 840, 113549, 1, 1, 13},
}

// ecdsaOIDs holds ecdsa-with-SHA* (RFC 5758 section 3.2).
var ecdsaOIDs = map[crypto.Hash]asn1.ObjectIdentifier{
	crypto.SHA256: {1, 2, 840, 10045, 4, 3, 2},
	crypto.SHA384: {1, 2, 840, 10045, 4, 3, 3},
	crypto.SHA512: {1, 2, 840, 10045, 4, 3, 4},
}

// nistSignatureOID returns the NIST sigAlgs arc 2.16.840.1.101.3.4.3 with the given last
// component: 17 to 19 for ML-DSA (RFC 9881), 20 to 25 for SLH-DSA-SHA2 (RFC 9909).
func nistSignatureOID(last int) asn1.ObjectIdentifier {
	return asn1.ObjectIdentifier{2, 16, 840, 1, 101, 3, 4, 3, last}
}
