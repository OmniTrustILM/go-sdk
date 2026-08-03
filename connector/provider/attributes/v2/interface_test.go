package attributes_test

import (
	"slices"
	"testing"

	attributes "github.com/OmniTrustILM/go-sdk/connector/provider/attributes/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// TestInterfaceOptsOutEvenWithFeaturesConfigured pins the deliberate drop
// documented on attributes.Base: handlerbase.WithFeatures is accepted (Base is
// a transparent passthrough for every handlerbase option) and lands in
// Config.Features, but Attributes v2 reports a zero InterfaceInfo so /v2/info
// leaves it out of the interfaces list entirely — there is no "attributes"
// ConnectorInterface code to advertise flags against. A refactor that wires
// this handler through Config.InterfaceInfo() would start leaking both a
// bogus code and the flags; this test fails first.
func TestInterfaceOptsOutEvenWithFeaturesConfigured(t *testing.T) {
	h, err := attributes.NewHandler("1.2.3", standardDefs(),
		attributes.Base(handlerbase.WithFeatures("stateless")))
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	// The option applied — the flag really is configured, so the drop below
	// is Interface()'s doing and not a silently rejected option.
	if want := []string{"stateless"}; !slices.Equal(h.Config.Features, want) {
		t.Fatalf("Config.Features = %v, want %v", h.Config.Features, want)
	}

	got := h.Interface()

	if got.Code != "" {
		t.Errorf("Code = %q, want %q (opts out of the /v2/info interfaces list)", got.Code, "")
	}
	if got.Version != "" {
		t.Errorf("Version = %q, want %q", got.Version, "")
	}
	if got.Features != nil {
		t.Errorf("Features = %v, want nil (flags are a field on an omitted list entry)", got.Features)
	}
}
