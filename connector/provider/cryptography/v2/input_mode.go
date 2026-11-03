package cryptography

import mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"

// InputMode returns how req's items are to be signed; the contract treats an
// absent field as data.
func InputMode(req *mdl.SignDataRequestV2Dto) mdl.SignatureInputMode {
	if mode := req.GetSignatureInputMode(); mode != "" {
		return mode
	}
	return mdl.SIGNATUREINPUTMODE_DATA
}
