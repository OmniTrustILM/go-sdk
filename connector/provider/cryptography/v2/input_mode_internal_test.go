package cryptography

import (
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/cryptography/v2"
)

// The generated enum refuses an unknown mode while decoding, so only a mode
// added by a later regeneration reaches signerFor's default branch.
func TestSignerForRefusesAModeItDoesNotRoute(t *testing.T) {
	h := &Handler{}

	sign, err := h.signerFor(mdl.SignatureInputMode("externalMu"))

	if err != errInputModeNotSupported {
		t.Fatalf("signerFor error = %v, want errInputModeNotSupported", err)
	}
	if sign != nil {
		t.Fatal("signerFor returned a signer for a mode it does not route")
	}
}
