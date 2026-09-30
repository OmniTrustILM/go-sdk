package shared

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// TestProblemCodeRegistryCoversEverySpec keeps the registry in step with the
// vendored specs: every error code a connector spec publishes renders with its
// own type URI, rather than falling back to the common category.
func TestProblemCodeRegistryCoversEverySpec(t *testing.T) {
	specs, err := filepath.Glob(filepath.Join("..", "spec", "*.json"))
	if err != nil || len(specs) == 0 {
		t.Fatalf("no specs found: %v", err)
	}
	for _, spec := range specs {
		raw, err := os.ReadFile(spec)
		if err != nil {
			t.Fatal(err)
		}
		var doc struct {
			Components struct {
				Schemas struct {
					ErrorCode struct {
						Enum []string `json:"enum"`
					} `json:"ErrorCode"`
				} `json:"schemas"`
			} `json:"components"`
		}
		if err := json.Unmarshal(raw, &doc); err != nil {
			t.Fatalf("parse %s: %v", spec, err)
		}
		for _, code := range doc.Components.Schemas.ErrorCode.Enum {
			if _, ok := problemCodeRegistry[code]; !ok {
				t.Errorf("%s publishes error code %s, which the registry does not list", filepath.Base(spec), code)
			}
		}
	}
}
