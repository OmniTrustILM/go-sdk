package handlerbase_test

import (
	"slices"
	"testing"

	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// applyFeatures runs WithFeatures against a default Config and returns the
// resulting Features together with any option error.
func applyFeatures(t *testing.T, features ...string) ([]string, error) {
	t.Helper()
	cfg := handlerbase.NewConfig("/v3/authorityProvider")
	err := handlerbase.WithFeatures(features...)(&cfg)
	return cfg.Features, err
}

func TestNewConfigAdvertisesNoFeatures(t *testing.T) {
	cfg := handlerbase.NewConfig("/v3/authorityProvider")

	if cfg.Features != nil {
		t.Errorf("NewConfig().Features = %v, want nil", cfg.Features)
	}
}

func TestWithFeaturesStoresSuppliedFlags(t *testing.T) {
	got, err := applyFeatures(t, "stateless", "certificateRegistration")
	if err != nil {
		t.Fatalf("WithFeatures: %v", err)
	}

	want := []string{"stateless", "certificateRegistration"}
	if !slices.Equal(got, want) {
		t.Errorf("Features = %v, want %v", got, want)
	}
}

// TestWithFeaturesAppendsAcrossCalls pins the same accumulate-not-replace
// semantics WithKinds has, so a caller can build the set up in stages.
func TestWithFeaturesAppendsAcrossCalls(t *testing.T) {
	cfg := handlerbase.NewConfig("/v3/authorityProvider")

	for _, f := range []string{"stateless", "certificateRegistration"} {
		if err := handlerbase.WithFeatures(f)(&cfg); err != nil {
			t.Fatalf("WithFeatures(%q): %v", f, err)
		}
	}

	want := []string{"stateless", "certificateRegistration"}
	if !slices.Equal(cfg.Features, want) {
		t.Errorf("Features = %v, want %v", cfg.Features, want)
	}
}

func TestWithFeaturesRejectsEmptyFlag(t *testing.T) {
	got, err := applyFeatures(t, "stateless", "")
	if err == nil {
		t.Fatalf("WithFeatures(\"stateless\", \"\") = nil error, want rejection (Features %v)", got)
	}
}

func TestWithFeaturesRejectsEmptyFlagWithoutPartialWrite(t *testing.T) {
	got, err := applyFeatures(t, "stateless", "")
	if err == nil {
		t.Fatalf("WithFeatures = nil error, want rejection")
	}

	if got != nil {
		t.Errorf("Features = %v after rejected option, want nil", got)
	}
}

func TestWithFeaturesNoFlagsIsNoOp(t *testing.T) {
	got, err := applyFeatures(t)
	if err != nil {
		t.Fatalf("WithFeatures(): %v", err)
	}

	if got != nil {
		t.Errorf("Features = %v, want nil", got)
	}
}

func TestWithFeaturesCopiesCallerSlice(t *testing.T) {
	caller := []string{"stateless", "certificateRegistration"}
	cfg := handlerbase.NewConfig("/v3/authorityProvider")
	if err := handlerbase.WithFeatures(caller...)(&cfg); err != nil {
		t.Fatalf("WithFeatures: %v", err)
	}

	caller[0] = "tampered"

	want := []string{"stateless", "certificateRegistration"}
	if !slices.Equal(cfg.Features, want) {
		t.Errorf("Features = %v after caller mutation, want %v", cfg.Features, want)
	}
}
