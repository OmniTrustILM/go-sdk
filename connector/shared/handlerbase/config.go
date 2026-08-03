// Package handlerbase provides the shared configuration and option helpers
// every provider Handler embeds. Every provider sub-package (secret v1,
// discovery v1, authority v1/v2, ...) needs the same knobs — base path,
// request-body size limit, strict-decode flag, logger override, advertised
// feature flags — and the option boilerplate to set them. Hoisting those into
// one place keeps each provider package focused on its spec-specific surface.
//
// Provider packages embed Config in their Handler and expose a Base option
// that lifts handlerbase.Option into the provider's own Option type:
//
//	type Handler struct {
//	    handlerbase.Config
//	    provider Provider
//	    // provider-specific fields
//	}
//
//	type Option func(*Handler) error
//
//	func Base(opts ...handlerbase.Option) Option {
//	    return func(h *Handler) error {
//	        for _, o := range opts {
//	            if err := o(&h.Config); err != nil { return err }
//	        }
//	        return nil
//	    }
//	}
//
// Caller code then writes:
//
//	discovery.NewHandler(p,
//	    discovery.Base(
//	        handlerbase.WithStrictDecode(true),
//	        handlerbase.WithMaxRequestBytes(2<<20),
//	    ),
//	    discovery.WithKinds("a"),
//	)
package handlerbase

import (
	"errors"
	"fmt"
	"log/slog"
	"net/http"
	"slices"
	"strings"

	"github.com/OmniTrustILM/go-sdk/connector/shared"
)

// ApplyOptions runs the supplied options against h. Used by every provider's
// NewHandler to keep the option-apply loop in one place; providerName is
// included in any returned error so the caller does not have to wrap.
//
// The type parameter F is constrained with `~func(*H) error` so providers
// can pass their named Option type (e.g. `secret.Option`) without having
// to first convert to a `func(*H) error` literal — Go's type system would
// otherwise reject named-vs-anonymous mismatches.
func ApplyOptions[H any, F ~func(*H) error](h *H, opts []F, providerName string) error {
	for _, opt := range opts {
		if err := opt(h); err != nil {
			return fmt.Errorf("%s: apply option: %w", providerName, err)
		}
	}
	return nil
}

// MountPerKindAttributes registers GET <base>/<kind>/attributes and
// POST <base>/<kind>/attributes/validate routes for every declared kind,
// with the kind name captured as a literal path segment. Required when the
// 4-segment GET conflicts with a sibling /authorities/{uuid} or similar
// wildcard route — see authority/v2 Mount doc for the conflict reason.
//
// Pass nil for either handler to skip that side (e.g. notification mounts
// only the list per-kind; validate stays wildcard because it is 5 segments
// and does not collide).
func MountPerKindAttributes(
	r shared.Router,
	basePath string,
	kinds []string,
	listFn, validateFn func(w http.ResponseWriter, r *http.Request, kind string),
) {
	for _, k := range kinds {
		kind := k
		listPath := basePath + "/" + kind + "/attributes"
		validatePath := listPath + "/validate"
		if listFn != nil {
			r.Handle(http.MethodGet, listPath, func(w http.ResponseWriter, r *http.Request) {
				listFn(w, r, kind)
			})
		}
		if validateFn != nil {
			r.Handle(http.MethodPost, validatePath, func(w http.ResponseWriter, r *http.Request) {
				validateFn(w, r, kind)
			})
		}
	}
}

// DefaultMaxRequestBytes caps decoded request bodies. Picked to match the
// shared.Connector default; provider Handlers inherit it via NewConfig.
const DefaultMaxRequestBytes int64 = 1 << 20 // 1 MiB

// Config carries the cross-provider configuration that every provider
// Handler embeds. Fields are exported so the embedding struct sees them via
// promotion (h.BasePath, h.MaxBytes, etc.) without forwarding accessors.
//
// LoggerFor is exposed as a method so route handlers do not have to
// duplicate the "override-or-context" lookup.
type Config struct {
	// BasePath is the route prefix the provider mounts its endpoints under.
	BasePath string

	// MaxBytes caps body size for endpoints that decode JSON.
	MaxBytes int64

	// Strict toggles json.Decoder.DisallowUnknownFields.
	Strict bool

	// Logger overrides the per-request slog.Logger when non-nil. Most
	// handlers prefer LoggerFor(r) which falls back to the context logger.
	Logger *slog.Logger

	// Kinds declares the connector kinds this provider supports. Surfaced in
	// /v1 listSupportedFunctions and used by Mount to register
	// per-literal-kind attribute routes (see MountPerKindAttributes).
	// Values are validated by WithKinds before being stored.
	Kinds []string

	// Features declares the capability flags the interface advertises in
	// shared.InterfaceInfo.Features on /v2/info. WithFeatures rejects an
	// empty flag but does not check values against the FeatureFlag
	// vocabulary; nil means advertise nothing.
	Features []string
}

// InterfaceInfo builds the /v2/info entry for a provider interface: the code
// and version the provider reports, plus the configured capability flags.
func (c *Config) InterfaceInfo(code, version string) shared.InterfaceInfo {
	return shared.InterfaceInfo{
		Code:     code,
		Version:  version,
		Features: slices.Clone(c.Features),
	}
}

// ValidateKind returns nil when k is acceptable as a literal URL segment.
// Empty strings and values containing path separators or pattern
// metacharacters are rejected so they cannot register malformed routes
// or shadow other handlers.
func ValidateKind(k string) error {
	if k == "" {
		return errors.New("kind must not be empty")
	}
	if strings.ContainsAny(k, "/{}") {
		return fmt.Errorf("kind %q contains forbidden characters (/, {, })", k)
	}
	return nil
}

// WithKinds appends the supplied kinds to Config.Kinds after validation.
// Provider packages wrap this in their own WithKinds option so callers see
// it in their provider's namespace; the validation lives here so every
// provider rejects bad input identically.
func WithKinds(kinds ...string) Option {
	return func(c *Config) error {
		for _, k := range kinds {
			if err := ValidateKind(k); err != nil {
				return err
			}
		}
		c.Kinds = append(c.Kinds, kinds...)
		return nil
	}
}

// NewConfig returns a Config populated with the SDK defaults. defaultBasePath
// is the provider-specific route prefix (e.g. "/v1/discoveryProvider").
func NewConfig(defaultBasePath string) Config {
	return Config{
		BasePath: defaultBasePath,
		MaxBytes: DefaultMaxRequestBytes,
	}
}

// LoggerFor returns the most specific logger available: an explicit override
// (WithLogger) when set, otherwise the request-scoped logger from the shared
// middleware chain.
func (c *Config) LoggerFor(r *http.Request) *slog.Logger {
	if c.Logger != nil {
		return c.Logger
	}
	return shared.LoggerFromContext(r.Context())
}

// Option configures a Config. Provider packages lift these into their own
// Option type via a thin Base(...) wrapper.
type Option func(*Config) error

// WithBasePath overrides the route prefix the provider mounts under. Useful
// when fronting the connector with a prefix-stripping proxy.
func WithBasePath(p string) Option {
	return func(c *Config) error {
		if p == "" {
			return errors.New("base path must not be empty")
		}
		c.BasePath = p
		return nil
	}
}

// WithMaxRequestBytes caps decoded request body size. Default 1 MiB.
func WithMaxRequestBytes(n int64) Option {
	return func(c *Config) error {
		if n <= 0 {
			return errors.New("maxRequestBytes must be > 0")
		}
		c.MaxBytes = n
		return nil
	}
}

// WithStrictDecode rejects request bodies containing unknown JSON fields.
// Default false.
func WithStrictDecode(b bool) Option {
	return func(c *Config) error { c.Strict = b; return nil }
}

// WithFeatures appends capability flags to Config.Features, which every
// provider Handler.Interface() reports as shared.InterfaceInfo.Features on
// "/v2/info".
//
// The intended values are the FeatureFlag wire values from the generated
// model packages. The vocabulary is shared across interfaces rather than
// per-interface — so pass whichever package's constants you have imported,
// converted to string:
//
//	authority.NewHandler(p,
//	    authority.Base(handlerbase.WithFeatures(
//	        string(mdl.FEATUREFLAG_CERTIFICATE_REQUEST_STRUCTURED),
//	        string(mdl.FEATUREFLAG_CERTIFICATE_REGISTRATION),
//	    )),
//	)
//
// Values are not checked against that vocabulary — only an empty flag is
// rejected. That is deliberate: it lets a connector advertise a flag the
// platform already knows but this SDK's generated model does not yet carry.
// Prefer the generated constants over string literals.
func WithFeatures(features ...string) Option {
	return func(c *Config) error {
		if slices.Contains(features, "") {
			return errors.New("feature flag must not be empty")
		}
		c.Features = append(c.Features, features...)
		return nil
	}
}

// WithLogger overrides the per-handler base logger. When unset, handlers use
// the request-scoped logger from shared.LoggerFromContext.
func WithLogger(l *slog.Logger) Option {
	return func(c *Config) error {
		if l == nil {
			return errors.New("logger must not be nil")
		}
		c.Logger = l
		return nil
	}
}
