package authority_test

import (
	"context"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	mdl "github.com/OmniTrustILM/go-sdk/connector/model/authority/v3"
	authority "github.com/OmniTrustILM/go-sdk/connector/provider/authority/v3"
	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

const authoritiesPath = "/v3/authorityProvider/authorities"

type authorityMetadataStub struct {
	metadata []mdl.MetadataAttribute
	err      error
	calls    int
}

func (s *authorityMetadataStub) CheckAuthorityConnectionWithMetadata(context.Context, []mdl.RequestAttribute) ([]mdl.MetadataAttribute, error) {
	s.calls++
	return s.metadata, s.err
}

// failingCheckProvider fails the Provider connection check, so a test can tell
// which of the two checks the route called.
type failingCheckProvider struct{ stubProvider }

func (failingCheckProvider) CheckAuthorityConnection(context.Context, []mdl.RequestAttribute) error {
	return authority.ErrConnectionFailed
}

func authoritiesServer(t *testing.T, p authority.Provider, opts ...authority.Option) *httptest.Server {
	t.Helper()
	h, err := authority.NewHandler(p, opts...)
	if err != nil {
		t.Fatalf("NewHandler: %v", err)
	}
	c, err := shared.New(
		shared.WithInfo(shared.Info{ID: "meta", Name: "meta", Version: "0.0.1"}),
		shared.Register(h),
	)
	if err != nil {
		t.Fatalf("shared.New: %v", err)
	}
	srv := httptest.NewServer(c.Handler())
	t.Cleanup(srv.Close)
	return srv
}

func postAuthorities(t *testing.T, srv *httptest.Server) (int, []byte) {
	t.Helper()
	resp, err := http.Post(srv.URL+authoritiesPath, "application/json", strings.NewReader(`[]`))
	if err != nil {
		t.Fatalf("POST: %v", err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(resp.Body)
	return resp.StatusCode, raw
}

func metadataAttribute(uuid, name, value string) mdl.MetadataAttribute {
	content := mdl.NewStringAttributeContentV3(value, mdl.ATTRIBUTECONTENTTYPE_STRING)
	attr := mdl.NewMetadataAttributeV3(
		uuid, name, 3,
		mdl.ATTRIBUTETYPE_META,
		mdl.ATTRIBUTECONTENTTYPE_STRING,
		*mdl.NewMetadataAttributeProperties(name, true),
		mdl.ATTRIBUTEVERSION_V3,
	)
	attr.Content = []mdl.BaseAttributeContentDtoV3{mdl.StringAttributeContentV3AsBaseAttributeContentDtoV3(content)}
	return mdl.MetadataAttributeV3AsMetadataAttribute(attr)
}

func TestCheckAuthorityConnectionWithoutMetadataProvider(t *testing.T) {
	code, body := postAuthorities(t, authoritiesServer(t, stubProvider{}))
	if code != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("got %d %q, want 204 without body", code, body)
	}
}

func TestCheckAuthorityConnectionWithoutMetadataProviderError(t *testing.T) {
	code, _ := postAuthorities(t, authoritiesServer(t, failingCheckProvider{}))
	if code < 400 {
		t.Fatalf("status = %d, want an error status", code)
	}
}

func TestCheckAuthorityConnectionReturnsMetadata(t *testing.T) {
	stub := &authorityMetadataStub{metadata: []mdl.MetadataAttribute{
		metadataAttribute("7c9e6679-7425-40de-944b-e07fc1f90ae7", "accountUrl", "https://acme.example/acct/1"),
	}}
	srv := authoritiesServer(t, failingCheckProvider{}, authority.WithAuthorityMetadata(stub))

	code, body := postAuthorities(t, srv)
	if code != http.StatusOK {
		t.Fatalf("status = %d, want 200; body %s", code, body)
	}
	var got mdl.AuthorityConnectionResponseDto
	if err := json.Unmarshal(body, &got); err != nil {
		t.Fatalf("decode %s: %v", body, err)
	}
	if len(got.Metadata) != 1 {
		t.Fatalf("metadata = %+v, want one item", got.Metadata)
	}
	attr := got.Metadata[0].MetadataAttributeV3
	if attr == nil {
		t.Fatalf("metadata item is not a v3 attribute: %+v", got.Metadata[0])
	}
	if attr.Uuid != "7c9e6679-7425-40de-944b-e07fc1f90ae7" || attr.Name != "accountUrl" {
		t.Fatalf("attribute = %+v", attr)
	}
	if len(attr.Content) != 1 || attr.Content[0].StringAttributeContentV3 == nil ||
		attr.Content[0].StringAttributeContentV3.Data != "https://acme.example/acct/1" {
		t.Fatalf("content = %+v", attr.Content)
	}
	if stub.calls != 1 {
		t.Fatalf("metadata provider calls = %d, want 1", stub.calls)
	}
}

func TestCheckAuthorityConnectionEmptyMetadata(t *testing.T) {
	stub := &authorityMetadataStub{}
	srv := authoritiesServer(t, failingCheckProvider{}, authority.WithAuthorityMetadata(stub))

	code, body := postAuthorities(t, srv)
	if code != http.StatusNoContent || len(body) != 0 {
		t.Fatalf("got %d %q, want 204 without body", code, body)
	}
	if stub.calls != 1 {
		t.Fatalf("metadata provider calls = %d, want 1", stub.calls)
	}
}

func TestCheckAuthorityConnectionMetadataError(t *testing.T) {
	stub := &authorityMetadataStub{err: authority.ErrConnectionFailed}
	srv := authoritiesServer(t, stubProvider{}, authority.WithAuthorityMetadata(stub))

	want, _ := postAuthorities(t, authoritiesServer(t, failingCheckProvider{}))
	code, _ := postAuthorities(t, srv)
	if code != want {
		t.Fatalf("status = %d, want %d as for the Provider check's error", code, want)
	}
}

func TestWithAuthorityMetadataRejectsNil(t *testing.T) {
	if _, err := authority.NewHandler(stubProvider{}, authority.WithAuthorityMetadata(nil)); err == nil {
		t.Fatal("NewHandler accepted a nil authority metadata provider")
	}
}
