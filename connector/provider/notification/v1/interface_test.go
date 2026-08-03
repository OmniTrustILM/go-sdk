package notification_test

import (
	"slices"
	"testing"

	notification "github.com/OmniTrustILM/go-sdk/connector/provider/notification/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

func TestInterfaceAdvertisesConfiguredFeatures(t *testing.T) {
	want := []string{"stateless"}
	h := &notification.Handler{Config: handlerbase.Config{Features: want}}

	got := h.Interface()

	if got.Code != shared.InterfaceCodeNotification {
		t.Errorf("Code = %q, want %q", got.Code, shared.InterfaceCodeNotification)
	}
	if got.Version != shared.VersionV1 {
		t.Errorf("Version = %q, want %q", got.Version, shared.VersionV1)
	}
	if !slices.Equal(got.Features, want) {
		t.Errorf("Features = %v, want %v", got.Features, want)
	}
}

func TestInterfaceWithoutFeaturesAdvertisesNone(t *testing.T) {
	h := &notification.Handler{}

	if got := h.Interface().Features; got != nil {
		t.Errorf("Features = %v, want nil", got)
	}
}
