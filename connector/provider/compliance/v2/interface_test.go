package compliance_test

import (
	"slices"
	"testing"

	compliance "github.com/OmniTrustILM/go-sdk/connector/provider/compliance/v2"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

func TestInterfaceAdvertisesConfiguredFeatures(t *testing.T) {
	want := []string{"stateless"}
	h := &compliance.Handler{Config: handlerbase.Config{Features: want}}

	got := h.Interface()

	if got.Code != shared.InterfaceCodeCompliance {
		t.Errorf("Code = %q, want %q", got.Code, shared.InterfaceCodeCompliance)
	}
	if got.Version != shared.VersionV2 {
		t.Errorf("Version = %q, want %q", got.Version, shared.VersionV2)
	}
	if !slices.Equal(got.Features, want) {
		t.Errorf("Features = %v, want %v", got.Features, want)
	}
}

func TestInterfaceWithoutFeaturesAdvertisesNone(t *testing.T) {
	h := &compliance.Handler{}

	if got := h.Interface().Features; got != nil {
		t.Errorf("Features = %v, want nil", got)
	}
}
