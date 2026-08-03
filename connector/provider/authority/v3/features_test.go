package authority_test

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"slices"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	mdlsec "github.com/OmniTrustILM/go-sdk/connector/model/secret/v1"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	secret "github.com/OmniTrustILM/go-sdk/connector/provider/secret/v1"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
	"github.com/OmniTrustILM/go-sdk/connector/shared/handlerbase"
)

// structuredFlags are the authority/v3 capability flags Core gates structured
// requestContent on — the first real consumer of handlerbase.WithFeatures.
var structuredFlags = []string{
	string(mdl.FEATUREFLAG_CERTIFICATE_REQUEST_STRUCTURED),
	string(mdl.FEATUREFLAG_CERTIFICATE_IDENTITY_OVERRIDE),
	string(mdl.FEATUREFLAG_CERTIFICATE_REGISTRATION),
}

// TestFeaturesAdvertisedOnAuthorityInterface proves a connector can populate
// InterfaceInfo.Features through the provider's existing Base lift.
func TestFeaturesAdvertisedOnAuthorityInterface(t *testing.T) {
	h, err := authority.NewHandler(stubProvider{},
		authority.Base(handlerbase.WithFeatures(structuredFlags...)),
	)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	if got := h.Interface().Features; !slices.Equal(got, structuredFlags) {
		t.Errorf("Interface().Features = %v, want %v", got, structuredFlags)
	}
}

func TestFeaturesAdvertisedOnSecretInterface(t *testing.T) {
	want := []string{
		string(mdlsec.FEATUREFLAG_SECRET_VERSIONING),
		string(mdlsec.FEATUREFLAG_SECRET_ROTATION),
	}

	h, err := secret.NewHandler(stubSecret{},
		secret.Base(handlerbase.WithFeatures(want...)),
	)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	if got := h.Interface().Features; !slices.Equal(got, want) {
		t.Errorf("Interface().Features = %v, want %v", got, want)
	}
}

func TestNoFeaturesByDefault(t *testing.T) {
	h, err := authority.NewHandler(stubProvider{})
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	if got := h.Interface().Features; got != nil {
		t.Errorf("Interface().Features = %v, want nil", got)
	}
}

func TestInterfaceDoesNotAliasHandlerFeatures(t *testing.T) {
	h, err := authority.NewHandler(stubProvider{},
		authority.Base(handlerbase.WithFeatures(structuredFlags...)),
	)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}

	first := h.Interface().Features
	first[0] = "tampered"

	if got := h.Interface().Features; !slices.Equal(got, structuredFlags) {
		t.Errorf("Interface().Features = %v after mutating an earlier result, want %v", got, structuredFlags)
	}
}

func TestFeaturesAppearInV2Info(t *testing.T) {
	authHandler, err := authority.NewHandler(stubProvider{},
		authority.Base(handlerbase.WithFeatures(structuredFlags...)),
	)
	if err != nil {
		t.Fatalf("authority NewHandler: %v", err)
	}
	secFlags := []string{string(mdlsec.FEATUREFLAG_SECRET_ROTATION)}
	secHandler, err := secret.NewHandler(stubSecret{},
		secret.Base(handlerbase.WithFeatures(secFlags...)),
	)
	if err != nil {
		t.Fatalf("secret NewHandler: %v", err)
	}

	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "feat", Name: "feat", Version: "0.0.1"}),
		shared.Register(authHandler),
		shared.Register(secHandler),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/v2/info")
	if err != nil {
		t.Fatalf("GET /v2/info: %v", err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("GET /v2/info = %d, want 200", resp.StatusCode)
	}
	raw, err := io.ReadAll(resp.Body)
	if err != nil {
		t.Fatalf("read body: %v", err)
	}
	var info shared.V2InfoResponse
	if err := json.Unmarshal(raw, &info); err != nil {
		t.Fatalf("decode: %v (body %s)", err, raw)
	}

	for _, want := range []struct {
		code, version string
		features      []string
	}{
		{shared.InterfaceCodeAuthority, shared.VersionV3, structuredFlags},
		{shared.InterfaceCodeSecret, shared.VersionV1, secFlags},
		// health is a built-in baseline entry nobody configured features on.
		{shared.InterfaceCodeHealth, "", nil},
	} {
		entry, ok := findInterface(info.Interfaces, want.code)
		if !ok {
			t.Errorf("/v2/info has no %q interface entry (body %s)", want.code, raw)
			continue
		}
		if want.version != "" && entry.Version != want.version {
			t.Errorf("%s interface version = %q, want %q", want.code, entry.Version, want.version)
		}
		if !slices.Equal(entry.Features, want.features) {
			t.Errorf("%s interface features = %v, want %v", want.code, entry.Features, want.features)
		}
	}

	// The pre-existing omitempty tag on InterfaceInfo.Features must keep the key off entries nobody configured,
	// so an interface that never calls the option serves the same /v2/info shape it did before.
	if n := strings.Count(string(raw), `"features"`); n != 2 {
		t.Errorf("body has %d %q keys, want 2 (authority + secret only): %s", n, "features", raw)
	}
}

func findInterface(ifaces []shared.InterfaceInfo, code string) (shared.InterfaceInfo, bool) {
	for _, i := range ifaces {
		if i.Code == code {
			return i, true
		}
	}
	return shared.InterfaceInfo{}, false
}
