package shared

import (
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"testing"
)

type stubRegistrable struct{ info InterfaceInfo }

func (s stubRegistrable) Mount(Router)             {}
func (s stubRegistrable) Interface() InterfaceInfo { return s.info }

func TestInfoListsContentSigningFormatting(t *testing.T) {
	if InterfaceCodeContentSigningFormatting != "contentSigningFormatting" {
		t.Fatalf("code = %q", InterfaceCodeContentSigningFormatting)
	}
	reg := stubRegistrable{InterfaceInfo{Code: InterfaceCodeContentSigningFormatting, Version: VersionV1}}
	c, err := New(Register(reg))
	if err != nil {
		t.Fatal(err)
	}
	w := httptest.NewRecorder()
	c.Handler().ServeHTTP(w, httptest.NewRequest(http.MethodGet, "/v2/info", nil))

	var got V2InfoResponse
	if err := json.Unmarshal(w.Body.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	for _, i := range got.Interfaces {
		if i.Code == "contentSigningFormatting" && i.Version == "v1" {
			return
		}
	}
	t.Fatalf("interface not listed: %s", w.Body)
}
